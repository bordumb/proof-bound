import fs from "node:fs";
import net from "node:net";
import { spawnSync } from "node:child_process";

const [mode, inputPath, outputPath, attackPath, portText] = process.argv.slice(2);
if (!mode || !inputPath || !outputPath || !attackPath || !portText) {
  throw new Error("expected mode, input, output, attack path, and port");
}

function connect(host, port) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection({ host, port });
    client.setTimeout(2000);
    client.once("connect", () => {
      client.end();
      resolve();
    });
    client.once("error", reject);
    client.once("timeout", () => reject(new Error("network timeout")));
  });
}

switch (mode) {
  case "positive": {
    const value = fs.readFileSync(inputPath, "utf8").trim();
    const environment = process.env.PB_REGISTERED_VALUE;
    if (environment === undefined) throw new Error("missing registered environment");
    fs.writeFileSync(outputPath, `${value}|${environment}\n`, "utf8");
    break;
  }
  case "read-undeclared":
    fs.writeFileSync(outputPath, fs.readFileSync(attackPath, "utf8"), "utf8");
    break;
  case "env-undeclared": {
    const value = process.env.PB_UNDECLARED_VALUE;
    if (value === undefined) throw new Error("undeclared environment denied");
    fs.writeFileSync(outputPath, value, "utf8");
    break;
  }
  case "exec-unregistered": {
    const child = spawnSync("/usr/bin/true", [], { stdio: "ignore" });
    if (child.error) throw child.error;
    if (child.status !== 0) throw new Error(`child exited ${child.status}`);
    fs.writeFileSync(outputPath, "child-executed\n", "utf8");
    break;
  }
  case "network":
    await connect("127.0.0.1", Number(portText));
    fs.writeFileSync(outputPath, "network-observed\n", "utf8");
    break;
  case "write-reviewed":
  case "write-escape":
    fs.writeFileSync(attackPath, "unauthorized-write\n", "utf8");
    break;
  default:
    throw new Error(`unknown mode: ${mode}`);
}
