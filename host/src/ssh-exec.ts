import type { SshExecRequest } from "./qemu-net";

export type GitSshExecInfo = {
  /** git service name (for example "git-upload-pack") */
  service: string;
  /** git repo path (for example "org/name.git") */
  repo: string;
};

function splitSshExecCommand(command: string): string[] {
  const out: string[] = [];
  let i = 0;

  while (i < command.length) {
    // skip whitespace
    while (i < command.length && /\s/.test(command[i]!)) i += 1;
    if (i >= command.length) break;

    let cur = "";
    let mode: "none" | "single" | "double" = "none";

    while (i < command.length) {
      const ch = command[i]!;

      if (mode === "none") {
        if (/\s/.test(ch)) break;
        if (ch === "'") {
          mode = "single";
          i += 1;
          continue;
        }
        if (ch === '"') {
          mode = "double";
          i += 1;
          continue;
        }
        if (ch === "\\") {
          i += 1;
          if (i < command.length) {
            cur += command[i]!;
            i += 1;
          }
          continue;
        }
        cur += ch;
        i += 1;
        continue;
      }

      if (mode === "single") {
        if (ch === "'") {
          mode = "none";
          i += 1;
          continue;
        }
        cur += ch;
        i += 1;
        continue;
      }

      // mode === "double"
      if (ch === '"') {
        mode = "none";
        i += 1;
        continue;
      }
      if (ch === "\\") {
        i += 1;
        if (i < command.length) {
          cur += command[i]!;
          i += 1;
        }
        continue;
      }
      cur += ch;
      i += 1;
    }

    out.push(cur);

    // consume trailing whitespace for this arg
    while (i < command.length && /\s/.test(command[i]!)) i += 1;
  }

  return out;
}

function basenamePosix(value: string): string {
  const idx = value.lastIndexOf("/");
  return idx === -1 ? value : value.slice(idx + 1);
}

/**
 * Best-effort parser for git-over-SSH exec commands.
 *
 * This intentionally only understands common git smart-protocol invocations such as:
 * - git-upload-pack 'org/repo.git'
 * - git-receive-pack 'org/repo.git'
 */
export function getInfoFromSshExecRequest(req: SshExecRequest): GitSshExecInfo | null {
  const argv = splitSshExecCommand(req.command);
  if (argv.length < 2) return null;

  const service = basenamePosix(argv[0]!.trim());
  if (!/^git-[a-z0-9][a-z0-9-]*$/i.test(service)) return null;

  let repo = (argv[1] ?? "").trim();
  if (!repo) return null;

  // Common normalizations for server-side git paths
  if (repo.startsWith("~/")) repo = repo.slice(2);
  repo = repo.replace(/^\/+/, "");
  repo = repo.replace(/\/+$/, "");

  // Conservative sanity checks
  if (!repo.includes("/")) return null;
  if (repo.includes("..")) return null;
  if (repo.startsWith("-")) return null;

  return { service, repo };
}
