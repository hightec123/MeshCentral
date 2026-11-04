const fs = require("node:fs");
const path = require("node:path");
const root = path.join(__dirname, "..");
const directory = path.join(root, "web/public/vendor");
fs.mkdirSync(directory, { recursive: true });
// Upstream's page supplies ShortToStr globally. Keep the small wire helper local
// to this adapter, preserving the retained renderer without adding page globals.
const source = fs.readFileSync(
  path.join(root, "public/scripts/agent-desktop-0.0.2.js"),
  "utf8",
);
fs.writeFileSync(
  path.join(directory, "agent-desktop.js"),
  "(function () {\nfunction ShortToStr(value) { return String.fromCharCode((value >>> 8) & 255, value & 255); }\n" +
    source +
    "\nwindow.CreateAgentRemoteDesktop = CreateAgentRemoteDesktop;\n})();\n",
);
