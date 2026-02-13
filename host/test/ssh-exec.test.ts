import assert from "node:assert/strict";
import test from "node:test";

import { getInfoFromSshExecRequest } from "../src/ssh-exec";

test("getInfoFromSshExecRequest parses git-upload-pack", () => {
  const info = getInfoFromSshExecRequest({
    hostname: "github.com",
    port: 22,
    guestUsername: "git",
    command: "git-upload-pack 'my-org/my-repo.git'",
    src: { ip: "192.168.127.3", port: 50000 },
  });

  assert.deepEqual(info, { service: "git-upload-pack", repo: "my-org/my-repo.git" });
});

test("getInfoFromSshExecRequest normalizes repo paths", () => {
  const info = getInfoFromSshExecRequest({
    hostname: "github.com",
    port: 22,
    guestUsername: "git",
    command: "git-receive-pack '/my-org/my-repo.git/'",
    src: { ip: "192.168.127.3", port: 50000 },
  });

  assert.deepEqual(info, { service: "git-receive-pack", repo: "my-org/my-repo.git" });
});

test("getInfoFromSshExecRequest returns null for non-git commands", () => {
  const info = getInfoFromSshExecRequest({
    hostname: "example.com",
    port: 22,
    guestUsername: "root",
    command: "echo hello",
    src: { ip: "192.168.127.3", port: 50000 },
  });

  assert.equal(info, null);
});
