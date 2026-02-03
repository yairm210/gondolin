import assert from "node:assert/strict";
import test from "node:test";

import { VM } from "../src/vm";

const url = process.env.WS_URL;
const timeoutMs = Number(process.env.WS_TIMEOUT ?? 15000);
const httpUrl = process.env.WS_HTTP_URL ?? "http://icanhazip.com";
const httpsUrl = process.env.WS_HTTPS_URL ?? "https://icanhazip.com";
const token = process.env.ELWING_TOKEN ?? process.env.SANDBOX_WS_TOKEN;

async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error("timeout waiting for response"));
    }, ms);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function assertFetchOutput(output: string, stderr: string) {
  const lines = output.trim().split("\n");
  const httpIndex = lines.findIndex((line) => line.trim() === "HTTP");
  const httpsIndex = lines.findIndex((line) => line.trim() === "HTTPS");
  if (httpIndex === -1 || httpsIndex === -1) {
    const detail = stderr.trim() ? `\n${stderr.trim()}` : "";
    assert.fail(`missing http/https output: ${output.trim()}${detail}`);
  }
  const httpValue = lines[httpIndex + 1]?.trim();
  const httpsValue = lines[httpsIndex + 1]?.trim();
  if (!httpValue || !httpsValue) {
    const detail = stderr.trim() ? `\n${stderr.trim()}` : "";
    assert.fail(`empty http/https response: ${output.trim()}${detail}`);
  }
}

test("ws http/https fetch", { timeout: timeoutMs }, async () => {
  const vm = new VM({ url: url ?? undefined, token: token ?? undefined });

  try {
    const result = await withTimeout(
      vm.exec([
        "python3",
        "-c",
        `import sys,urllib.request;\n` +
          `print('HTTP');\n` +
          `print(urllib.request.urlopen('${httpUrl}', timeout=10).read().decode().strip());\n` +
          `print('HTTPS');\n` +
          `print(urllib.request.urlopen('${httpsUrl}', timeout=10).read().decode().strip());\n`,
      ]),
      timeoutMs
    );

    const output = result.stdout.toString();
    const stderr = result.stderr.toString();

    assert.equal(
      result.exitCode,
      0,
      stderr.trim() ? `unexpected exit code: ${result.exitCode}\n${stderr.trim()}` : undefined
    );

    assertFetchOutput(output, stderr);
  } finally {
    await vm.stop();
  }
});
