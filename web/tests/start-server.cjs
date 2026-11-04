// A disposable, independently authenticated console for browser regression tests.
const fs = require("node:fs");
const path = require("node:path");
const cp = require("node:child_process");
const root = path.resolve(__dirname, "../..");
const directory = fs.mkdtempSync(path.join(root, ".local/browser-tests-"));
fs.chmodSync(directory, 0o700);
const env = {
  ...process.env,
  MCR_DATA_DIR: directory,
  MCR_LISTEN: "127.0.0.1:3100",
  MCR_WEB_DIR: path.join(root, "web/dist"),
};
const build = cp.spawnSync(
  "cargo",
  ["build", "--locked", "--offline", "-p", "meshcentral-server"],
  { cwd: root, env, stdio: "inherit" },
);
if (build.status !== 0) process.exit(1);
const binary = path.join(root, "target/debug/meshcentral-server");
const init = cp.spawnSync(binary, ["init-user", "test-admin"], {
  cwd: root,
  env,
  input: "browser-test-password-123",
  encoding: "utf8",
});
if (init.status !== 0) {
  console.error(init.stderr);
  process.exit(1);
}
const server = cp.spawn(binary, [], { cwd: root, env, stdio: "inherit" });
for (const signal of ["SIGTERM", "SIGINT"])
  process.on(signal, () => server.kill(signal));
server.on("exit", (code) => {
  fs.rmSync(directory, { recursive: true, force: true });
  process.exit(code ?? 0);
});
