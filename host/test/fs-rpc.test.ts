import assert from "node:assert/strict";
import os from "node:os";
import test from "node:test";

import { FsRpcService, MemoryProvider, MAX_RPC_DATA } from "../src/vfs";

const { errno: ERRNO } = os.constants;

function createService() {
  return new FsRpcService(new MemoryProvider());
}

async function send(service: FsRpcService, op: string, req: Record<string, unknown>, id = 1) {
  return service.handleRequest({
    v: 1,
    t: "fs_request",
    id,
    p: { op, req },
  });
}

test("fs rpc create/write/read", async () => {
  const service = createService();

  const create = await send(service, "create", {
    parent_ino: 1,
    name: "hello.txt",
    mode: 0o644,
    flags: 0,
  });
  assert.equal(create.p.err, 0);
  const fh = create.p.res?.fh as number;

  const write = await send(service, "write", {
    fh,
    offset: 0,
    data: Buffer.from("hello"),
  });
  assert.equal(write.p.err, 0);
  assert.equal(write.p.res?.size, 5);

  const read = await send(service, "read", {
    fh,
    offset: 0,
    size: 5,
  });
  assert.equal(read.p.err, 0);
  const data = Buffer.from(read.p.res?.data as Buffer);
  assert.equal(data.toString(), "hello");

  const lookup = await send(service, "lookup", {
    parent_ino: 1,
    name: "hello.txt",
  });
  assert.equal(lookup.p.err, 0);
  const ino = (lookup.p.res?.entry as { ino: number }).ino;

  const getattr = await send(service, "getattr", { ino });
  assert.equal(getattr.p.err, 0);

  await send(service, "release", { fh });
  await service.close();
});

test("fs rpc readdir offsets", async () => {
  const service = createService();

  await send(service, "create", {
    parent_ino: 1,
    name: "a.txt",
    mode: 0o644,
    flags: 0,
  });
  await send(service, "create", {
    parent_ino: 1,
    name: "b.txt",
    mode: 0o644,
    flags: 0,
  });

  const first = await send(service, "readdir", {
    ino: 1,
    offset: 0,
    max_entries: 1,
  });
  assert.equal(first.p.err, 0);
  const firstEntries = (first.p.res?.entries as Array<{ name: string; offset: number }>) ?? [];
  assert.equal(firstEntries.length, 1);
  const nextOffset = firstEntries[0].offset;

  const second = await send(service, "readdir", {
    ino: 1,
    offset: nextOffset,
    max_entries: 1,
  });
  assert.equal(second.p.err, 0);
  const secondEntries = (second.p.res?.entries as Array<{ name: string }>) ?? [];
  assert.equal(secondEntries.length, 1);
  assert.notEqual(secondEntries[0].name, firstEntries[0].name);

  await service.close();
});

test("fs rpc validates names and payload size", async () => {
  const service = createService();

  const invalidName = await send(service, "mkdir", {
    parent_ino: 1,
    name: "bad/name",
    mode: 0o755,
  });
  assert.equal(invalidName.p.err, ERRNO.EINVAL);

  const create = await send(service, "create", {
    parent_ino: 1,
    name: "big.txt",
    mode: 0o644,
    flags: 0,
  });
  const fh = create.p.res?.fh as number;

  const oversized = await send(service, "write", {
    fh,
    offset: 0,
    data: Buffer.alloc(MAX_RPC_DATA + 1),
  });
  assert.equal(oversized.p.err, ERRNO.EINVAL);

  await send(service, "release", { fh });
  await service.close();
});
