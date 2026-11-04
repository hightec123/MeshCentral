const fs = require("node:fs");
const path = require("node:path");
const root = path.join(__dirname, "..");
const directory = path.join(root, "web/public/vendor");
fs.mkdirSync(directory, { recursive: true });
fs.copyFileSync(
  path.join(root, "public/scripts/agent-desktop-0.0.2.js"),
  path.join(directory, "agent-desktop.js"),
);
