/**
 * Self-Modification Audit Diff Tests
 *
 * editFile() records a diff of every self-modification to the audit log
 * (the `modifications` table). The diff must be generated via real line
 * alignment (LCS), not by comparing old/new lines at the same index --
 * index-based comparison misaligns every line after a single insertion
 * or deletion, turning the stored audit diff for any non-pure-replace
 * edit into a wall of spurious changes that's useless for a creator
 * reviewing what an automaton actually changed.
 */

import { describe, it, expect, afterEach } from "vitest";
import path from "path";
import fs from "fs";
import os from "os";
import { editFile } from "../self-mod/code.js";
import { MockConwayClient, createTestDb } from "./mocks.js";

describe("self-modification audit diff generation", () => {
  const originalCwd = process.cwd();
  let tmpDir: string;

  afterEach(() => {
    process.chdir(originalCwd);
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function setUpTmpCwd(): void {
    tmpDir = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "automaton-diff-test-")),
    );
    process.chdir(tmpDir);
  }

  it("does not misalign unrelated lines after a single inserted line", async () => {
    setUpTmpCwd();

    const conway = new MockConwayClient();
    const db = createTestDb();

    const filePath = "notes.txt";
    const resolvedPath = path.resolve(filePath);
    const oldContent = "line1\nline2\nline3\nline4\nline5";
    const newContent = "line1\nline2\nINSERTED\nline3\nline4\nline5";
    conway.files[resolvedPath] = oldContent;

    const result = await editFile(conway, db, filePath, newContent, "insert a line");
    expect(result.success).toBe(true);

    const [modification] = db.getRecentModifications(1);
    expect(modification).toBeDefined();
    const diff = modification!.diff ?? "";

    // Only the genuinely new line should be marked as added...
    expect(diff).toContain("+INSERTED");
    // ...and none of the unrelated, unchanged lines should be marked as
    // removed just because they shifted down by one position. A naive
    // index-based diff would spuriously report line3/line4/line5 as
    // both removed and re-added.
    expect(diff).not.toContain("-line3");
    expect(diff).not.toContain("-line4");
    expect(diff).not.toContain("-line5");
  });

  it("does not misalign unrelated lines after a single deleted line", async () => {
    setUpTmpCwd();

    const conway = new MockConwayClient();
    const db = createTestDb();

    const filePath = "notes.txt";
    const resolvedPath = path.resolve(filePath);
    const oldContent = "line1\nline2\nREMOVE_ME\nline3\nline4\nline5";
    const newContent = "line1\nline2\nline3\nline4\nline5";
    conway.files[resolvedPath] = oldContent;

    const result = await editFile(conway, db, filePath, newContent, "delete a line");
    expect(result.success).toBe(true);

    const [modification] = db.getRecentModifications(1);
    const diff = modification!.diff ?? "";

    expect(diff).toContain("-REMOVE_ME");
    expect(diff).not.toContain("-line3");
    expect(diff).not.toContain("-line4");
    expect(diff).not.toContain("-line5");
  });

  it("records a no-op marker when content is unchanged", async () => {
    setUpTmpCwd();

    const conway = new MockConwayClient();
    const db = createTestDb();

    const filePath = "notes.txt";
    const resolvedPath = path.resolve(filePath);
    const content = "unchanged content\n";
    conway.files[resolvedPath] = content;

    const result = await editFile(conway, db, filePath, content, "no-op edit");
    expect(result.success).toBe(true);

    const [modification] = db.getRecentModifications(1);
    expect(modification!.diff).toBe("(no content change)");
  });
});
