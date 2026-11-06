// Package the retained upstream core exactly as MeshCentral does: a four-byte
// reserved prefix, addModule declarations, JSON globals, then meshcore.js.
// The native executable is never changed.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = path.join(__dirname, "..");
const directory = path.join(root, ".local/cores");
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
let core = fs.readFileSync(path.join(root, "agents/meshcore.js"), "utf8");
function adaptCore(before, after) {
  if (core.split(before).length !== 2)
    throw new Error(
      "Could not locate a unique forwarding handler in the agent core.",
    );
  core = core.replace(before, after);
}
// Preserve the TCP data handler instead of replacing it with the normal
// console handler. Loopback UDP forwards also use a loopback receive socket.
adaptCore(
  "    if (this.udpport != null) {\n        // This is a UDP relay connection",
  "    else if (this.udpport != null) {\n        // This is a UDP relay connection",
);
adaptCore(
  "s.udprelay.bind({ port: 0, address: '0.0.0.0' });",
  "s.udprelay.bind({ port: 0, address: this.udpaddr === '127.0.0.1' ? '127.0.0.1' : '0.0.0.0' });",
);
adaptCore(
  "s.tcprelay.peerindex = this.index;",
  "s.tcprelay.peerindex = this.index;\n        s.tcprelay.on('error', function () { s.end(); });",
);
adaptCore(
  "function onUdpRelayTargetTunnelConnect(data) {\n    var peerTunnel = tunnels[this.peerindex];\n    peerTunnel.s.write(data);",
  "function onUdpRelayTargetTunnelConnect(data, peer) {\n    var peerTunnel = tunnels[this.peerindex];\n    var address = this.udpaddr || '127.0.0.1';\n    if (peerTunnel && peer && (peer.address === address || peer.address === '::ffff:' + address) && peer.port === parseInt(this.udpport) && data.length > 0 && data.length < 4096) { peerTunnel.s.write(data); }",
);
for (const platform of ["macos", "linux", "windows"]) {
  const pieces = ["var addedModules = [];\r\n"];
  for (const file of fs
    .readdirSync(path.join(root, "agents/modules_meshcore"))
    .sort()) {
    const name = file.replace(/\.(js|json)$/, "");
    if (name.startsWith("amt-") || name === "smbios") continue;
    if (name.startsWith("win-") && platform !== "windows") continue;
    if (name.startsWith("linux-") && platform !== "linux") continue;
    if (name.startsWith("mac-") && platform !== "macos") continue;
    const text = fs.readFileSync(
      path.join(root, "agents/modules_meshcore", file),
      "utf8",
    );
    if (file.endsWith(".js"))
      pieces.push(
        "try { addModule(" +
          JSON.stringify(name) +
          ", " +
          JSON.stringify(text) +
          "); addedModules.push(" +
          JSON.stringify(name) +
          "); } catch (ex) {}\r\n",
      );
    if (file.endsWith(".json")) {
      if (!/^[a-zA-Z_$][\w$]*$/.test(name))
        throw new Error("Invalid JSON global");
      pieces.push(
        "var " + name + " = " + JSON.stringify(JSON.parse(text)) + ";\r\n",
      );
    }
  }
  pieces.push(core);
  const bytes = Buffer.concat([
    Buffer.alloc(4),
    Buffer.from(
      pieces
        .join("")
        .replace(/\u2028/g, "\\u2028")
        .replace(/\u2029/g, "\\u2029"),
    ),
  ]);
  fs.writeFileSync(path.join(directory, platform + ".bin"), bytes, {
    mode: 0o600,
  });
  console.log(
    platform +
      ": " +
      bytes.length +
      " bytes, SHA384 " +
      crypto.createHash("sha384").update(bytes).digest("hex"),
  );
}
