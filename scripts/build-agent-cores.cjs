// Package the retained upstream core exactly as MeshCentral does: a four-byte
// reserved prefix, addModule declarations, JSON globals, then meshcore.js.
// The native executable is never changed.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = path.join(__dirname, "..");
const directory = path.join(root, ".local/cores");
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
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
  pieces.push(fs.readFileSync(path.join(root, "agents/meshcore.js"), "utf8"));
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
