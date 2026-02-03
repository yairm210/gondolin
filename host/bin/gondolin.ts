import { runBash } from "./bash";
import { runExec } from "./exec";
import { runWsServer } from "./ws-server";

function usage() {
  console.log("Usage: gondolin <command> [options]");
  console.log("Commands:");
  console.log("  exec         Run a command via the virtio socket");
  console.log("  ws-server    Start the WebSocket bridge server");
  console.log("  bash         Start an interactive bash session over WS");
  console.log("  help         Show this help");
  console.log("\nRun gondolin <command> --help for command-specific flags.");
}

async function main() {
  const [command, ...args] = process.argv.slice(2);

  if (!command || command === "help" || command === "--help" || command === "-h") {
    usage();
    process.exit(command ? 0 : 1);
  }

  switch (command) {
    case "exec":
      runExec(args);
      return;
    case "ws-server":
    case "server":
      await runWsServer(args);
      return;
    case "bash":
      await runBash();
      return;
    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
