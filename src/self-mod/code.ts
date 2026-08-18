/**
 * Self-Modification Engine
 *
 * Allows the automaton to edit its own code and configuration.
 * All changes are audited, rate-limited, and some paths are protected.
 *
 * Safety model inspired by nanoclaw's trust boundary architecture:
 * - Hard-coded invariants that can NEVER be modified by the agent
 * - The safety enforcement code is immutable from the agent's perspective
 * - Pre-modification snapshots via git
 * - Rate limiting on modification frequency
 * - Symlink resolution before path validation
 * - Maximum diff size enforcement
 */

import fs from "fs";
import path from "path";
import { createPatch } from "diff";
import type {
  ConwayClient,
  AutomatonDatabase,
} from "../types.js";
import { logModification } from "./audit-log.js";
import { createLogger } from "../observability/logger.js";

const logger = createLogger("self-mod");

// ─── IMMUTABLE SAFETY INVARIANTS ─────────────────────────────
// These are hard-coded and CANNOT be changed by the agent.
// The agent cannot modify this file (it's in PROTECTED_FILES).
// Even if it modifies a copy, the runtime loads from the original.

/**
 * Files that the automaton cannot modify under any circumstances.
 * This list protects:
 * - Identity (wallet, config)
 * - Defense systems (injection defense, this file)
 * - State database
 * - The audit log itself
 */
const PROTECTED_FILES: readonly string[] = Object.freeze([
  // Identity
  "wallet.json",
  "config.json",
  // Database
  "state.db",
  "state.db-wal",
  "state.db-shm",
  // Constitution (immutable, propagated to children)
  "constitution.md",
  // Defense infrastructure (the agent must not modify its own guardrails)
  "injection-defense.ts",
  "injection-defense.js",
  "injection-defense.d.ts",
  // Self-modification safety (this file and its compiled output)
  "self-mod/code.ts",
  "self-mod/code.js",
  "self-mod/code.d.ts",
  "self-mod/audit-log.ts",
  "self-mod/audit-log.js",
  // Tool guard definitions
  "agent/tools.ts",
  "agent/tools.js",
  // Upstream and tools-manager infrastructure
  "self-mod/upstream.ts",
  "self-mod/upstream.js",
  "self-mod/tools-manager.ts",
  "self-mod/tools-manager.js",
  // Skills infrastructure
  "skills/loader.ts",
  "skills/loader.js",
  "skills/registry.ts",
  "skills/registry.js",
  // Configuration and identity
  "automaton.json",
  "package.json",
  "SOUL.md",
  // Policy engine (protect from self-modification)
  "agent/policy-engine.ts",
  "agent/policy-engine.js",
  "agent/policy-rules/index.ts",
  "agent/policy-rules/index.js",
]);

/**
 * Directory patterns that are completely off-limits.
 * The agent cannot write to these locations.
 */
const BLOCKED_DIRECTORY_PATTERNS: readonly string[] = Object.freeze([
  ".ssh",
  ".gnupg",
  ".gpg",
  ".aws",
  ".azure",
  ".gcloud",
  ".kube",
  ".docker",
  "/etc/systemd",
  "/etc/passwd",
  "/etc/shadow",
  "/proc",
  "/sys",
]);

/**
 * Maximum number of self-modifications per hour.
 * Prevents runaway modification loops.
 */
const MAX_MODIFICATIONS_PER_HOUR = 20;

/**
 * Maximum size of a single file modification (bytes).
 */
const MAX_MODIFICATION_SIZE = 100_000; // 100KB

/**
 * Maximum diff size stored in the audit log (characters).
 */
const MAX_DIFF_SIZE = 10_000;

// ─── Path Validation ─────────────────────────────────────────

/**
 * Resolve a file path, following symlinks, to prevent traversal attacks.
 * Returns null if the path cannot be resolved or is suspicious.
 */
function resolveAndValidatePath(filePath: string): string | null {
  try {
    // Step 1: Resolve ~ to home
    let resolved = filePath;
    if (resolved.startsWith("~")) {
      resolved = path.join(process.env.HOME || "/root", resolved.slice(1));
    }

    // Step 2: Resolve to absolute path (handles .. and relative paths)
    resolved = path.resolve(resolved);

    // Step 3: Check resolved path is within the base directory (cwd)
    const baseDir = path.resolve(process.cwd());
    if (!resolved.startsWith(baseDir + path.sep) && resolved !== baseDir) {
      return null;
    }

    // Step 4: If the path exists, resolve symlinks and re-check
    if (fs.existsSync(resolved)) {
      const realPath = fs.realpathSync(resolved);
      if (!realPath.startsWith(baseDir + path.sep) && realPath !== baseDir) {
        return null;
      }
      resolved = realPath;
    }

    return resolved;
  } catch {
    return null;
  }
}

/**
 * Check if a file path is protected from modification.
 */
export function isProtectedFile(filePath: string): boolean {
  const resolved = path.resolve(filePath);

  // Check against protected file patterns using path-segment matching
  for (const pattern of PROTECTED_FILES) {
    const patternResolved = path.resolve(pattern);
    // Exact match on resolved paths
    if (resolved === patternResolved) return true;
    // Match by path suffix: the resolved path ends with /pattern
    if (resolved.endsWith(path.sep + pattern)) return true;
    // Also check multi-segment patterns (e.g., "self-mod/code.ts")
    if (pattern.includes("/") && resolved.endsWith(path.sep + pattern.replace(/\//g, path.sep))) return true;
  }

  // Check against blocked directory patterns using path-segment matching
  for (const pattern of BLOCKED_DIRECTORY_PATTERNS) {
    // Check if any path segment matches the blocked directory
    if (resolved.includes(path.sep + pattern + path.sep) ||
        resolved.endsWith(path.sep + pattern) ||
        resolved === pattern) {
      return true;
    }
    // Handle absolute patterns like /etc/systemd
    if (pattern.startsWith("/") && resolved.startsWith(pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if the modification rate limit has been exceeded.
 */
function isRateLimited(db: AutomatonDatabase): boolean {
  const recentMods = db.getRecentModifications(MAX_MODIFICATIONS_PER_HOUR);
  if (recentMods.length < MAX_MODIFICATIONS_PER_HOUR) return false;

  // Check if the oldest is within the last hour
  const oldest = recentMods[0];
  if (!oldest) return false;

  const hourAgo = Date.now() - 60 * 60 * 1000;
  return new Date(oldest.timestamp).getTime() > hourAgo;
}

// ─── Self-Modification API ───────────────────────────────────

/**
 * Edit a file in the automaton's environment.
 * Records the change in the audit log.
 * Commits a git snapshot before modification.
 *
 * Safety checks:
 * 1. Path traversal check (symlink resolution)
 * 2. Protected file check (hard-coded invariant) -- evaluated against
 *    BOTH the literal path and the symlink-resolved real path, so a
 *    symlink whose target resolves to a protected file is also blocked
 * 3. Blocked directory check
 * 4. Rate limiting
 * 5. File size limit
 * 6. Pre-modification git snapshot
 * 7. Audit log entry
 *
 * All file I/O below is performed against the symlink-resolved real
 * path (not the literal, possibly-symlinked path the caller supplied),
 * so validation and execution always agree on which file is touched.
 */
export async function editFile(
  conway: ConwayClient,
  db: AutomatonDatabase,
  filePath: string,
  newContent: string,
  reason: string,
): Promise<{ success: boolean; error?: string }> {
  // 1. Path validation (symlink resolution + traversal check). This must
  // run BEFORE the protected-file check: it resolves symlinks to their
  // real target so that check can see through them.
  const resolvedPath = resolveAndValidatePath(filePath);
  if (!resolvedPath) {
    return {
      success: false,
      error: `BLOCKED: Invalid or suspicious file path: ${filePath}`,
    };
  }

  // 2. Protected file check -- checked against both the literal path and
  // the resolved real path. Checking only the literal path would let an
  // agent create a symlink (e.g. via `exec`) at an unprotected path that
  // points at a protected file, then "edit" the symlink to bypass this
  // guard entirely.
  if (isProtectedFile(filePath) || isProtectedFile(resolvedPath)) {
    return {
      success: false,
      error: `BLOCKED: Cannot modify protected file: ${filePath}. This is a hard-coded safety invariant.`,
    };
  }

  // 3. Rate limiting
  if (isRateLimited(db)) {
    return {
      success: false,
      error: `RATE LIMITED: Too many modifications in the past hour (max ${MAX_MODIFICATIONS_PER_HOUR}). Wait before making more changes.`,
    };
  }

  // 4. File size limit
  if (newContent.length > MAX_MODIFICATION_SIZE) {
    return {
      success: false,
      error: `BLOCKED: File content too large (${newContent.length} bytes, max ${MAX_MODIFICATION_SIZE}). Break into smaller changes.`,
    };
  }

  // 5. Read current content for diff. Uses the resolved real path so the
  // diff reflects what will actually be overwritten.
  let oldContent: string;
  try {
    oldContent = await conway.readFile(resolvedPath);
  } catch {
    oldContent = "(new file)";
  }

  // 6. Pre-modification git snapshot (in repo root, not ~/.automaton/)
  try {
    const { gitCommit } = await import("../git/tools.js");
    await gitCommit(conway, process.cwd(), `pre-modify: ${reason}`);
  } catch (err: unknown) {
    // Git not available or the commit failed -- proceed without a
    // snapshot, but log it. Silently swallowing this would leave no
    // trace that the pre-modification safety snapshot was skipped.
    const message = err instanceof Error ? err.message : String(err);
    logger.warn("Pre-modification git snapshot failed; proceeding without it", {
      filePath: resolvedPath,
      error: message,
    });
  }

  // 7. Write new content. Uses the resolved real path -- never the raw,
  // possibly-symlinked path -- so a symlink cannot redirect the write
  // after validation has already run.
  try {
    await conway.writeFile(resolvedPath, newContent);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      success: false,
      error: `Failed to write file: ${message}`,
    };
  }

  // 8. Generate diff and log
  const diff = generateDiff(resolvedPath, oldContent, newContent);

  logModification(db, "code_edit", reason, {
    filePath: resolvedPath,
    diff: diff.slice(0, MAX_DIFF_SIZE),
    reversible: true,
  });

  // 9. Post-modification git commit (in repo root)
  try {
    const { gitCommit } = await import("../git/tools.js");
    await gitCommit(conway, process.cwd(), `self-mod: ${reason}`);
  } catch (err: unknown) {
    // Git not available or the commit failed -- proceed without it,
    // but log it. This is the git-versioning half of the audit trail
    // for self-modifications, so a silent failure here is a debugging
    // and forensics gap.
    const message = err instanceof Error ? err.message : String(err);
    logger.warn("Post-modification git commit failed", {
      filePath: resolvedPath,
      error: message,
    });
  }

  // 10. Rebuild if source file was edited
  if (/\.(ts|js|tsx|jsx)$/.test(resolvedPath)) {
    try {
      await conway.exec("npm run build", 60_000);
    } catch {
      return { success: true, error: "File edited but rebuild failed. Run 'npm run build' manually." };
    }
  }

  return { success: true };
}

/**
 * Validate a proposed modification without executing it.
 * Returns safety analysis results.
 */
export function validateModification(
  db: AutomatonDatabase,
  filePath: string,
  contentSize: number,
): {
  allowed: boolean;
  reason: string;
  checks: { name: string; passed: boolean; detail: string }[];
} {
  const checks: { name: string; passed: boolean; detail: string }[] = [];

  // Path validation (symlink resolution + traversal check) -- run first
  // so the protected-file check below can also evaluate the real,
  // symlink-resolved target, not just the literal path.
  const resolved = resolveAndValidatePath(filePath);
  checks.push({
    name: "path_valid",
    passed: !!resolved,
    detail: resolved
      ? `Resolved to: ${resolved}`
      : "Path is invalid or suspicious",
  });

  // Protected file check -- checked against both the literal path and
  // the symlink-resolved real path, so a symlink whose target resolves
  // to a protected file is also caught.
  const isProtected =
    isProtectedFile(filePath) || (!!resolved && isProtectedFile(resolved));
  checks.push({
    name: "protected_file",
    passed: !isProtected,
    detail: isProtected
      ? `File matches protected pattern`
      : "File is not protected",
  });

  // Rate limit
  const rateLimited = isRateLimited(db);
  checks.push({
    name: "rate_limit",
    passed: !rateLimited,
    detail: rateLimited
      ? `Exceeded ${MAX_MODIFICATIONS_PER_HOUR}/hour limit`
      : "Within rate limit",
  });

  // Size limit
  const sizeOk = contentSize <= MAX_MODIFICATION_SIZE;
  checks.push({
    name: "size_limit",
    passed: sizeOk,
    detail: sizeOk
      ? `${contentSize} bytes (max ${MAX_MODIFICATION_SIZE})`
      : `${contentSize} bytes exceeds ${MAX_MODIFICATION_SIZE} limit`,
  });

  const allPassed = checks.every((c) => c.passed);
  const failedChecks = checks.filter((c) => !c.passed);

  return {
    allowed: allPassed,
    reason: allPassed
      ? "All safety checks passed"
      : `Blocked: ${failedChecks.map((c) => c.detail).join("; ")}`,
    checks,
  };
}

// ─── Diff Generation ─────────────────────────────────────────

/**
 * Generate a unified diff between the old and new file content for the
 * audit log.
 *
 * This uses the `diff` library's LCS-based line alignment rather than
 * comparing lines by index. Index-based comparison misaligns every line
 * after a single insertion or deletion -- a single inserted line would
 * make every subsequent line look changed, turning the stored audit diff
 * for any non-pure-replace edit into a wall of spurious changes. LCS
 * alignment keeps the diff limited to the lines that actually changed.
 */
function generateDiff(
  filePath: string,
  oldContent: string,
  newContent: string,
): string {
  if (oldContent === newContent) return "(no content change)";

  return createPatch(filePath, oldContent, newContent, undefined, undefined, {
    context: 3,
  });
}
