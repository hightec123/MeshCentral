// Tests the Rust CLI with native loopback sockets and the stock agent's real relay.
const { spawn } = require("node:child_process");
const { randomBytes } = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs");
const net = require("node:net");
const dgram = require("node:dgram");
const path = require("node:path");
const { chromium } = require("../web/node_modules/playwright");
const { expect } = require("../web/node_modules/@playwright/test");

const root = path.resolve(__dirname, "..");
const port = Number(process.argv[2]);
const linux = process.argv.includes("--linux");
const routed = process.argv.includes("--route");
const prefix = (linux ? "linux-" : "") + (routed ? "routed-" : "");
const openChildren = new Set();

async function within(work, label) {
  let timer;
  try {
    return await Promise.race([
      work,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(label + " timed out")),
          12000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function bridge(kind, origin, session, token) {
  const url = new URL(session.socket_path, origin);
  url.protocol = "ws:";
  const child = spawn(path.join(root, "target/debug/meshcentral-server"), [
    "forward",
    kind,
    url.href,
  ]);
  openChildren.add(child);
  let stdout = "";
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (data) => {
    stderr += data;
  });
  child.stdin.on("error", () => {});
  child.stdin.end(token + "\n");
  const exited = once(child, "exit").then(([code]) => {
    openChildren.delete(child);
    return code;
  });
  const ready = new Promise((resolve, reject) => {
    child.stdout.setEncoding("utf8").on("data", (data) => {
      stdout += data;
      const match = stdout.match(/listening on 127\.0\.0\.1:(\d+)/);
      if (match) resolve(Number(match[1]));
    });
    exited.then(
      () =>
        reject(
          new Error(
            "Forward client exited before bind. " +
              (stderr.includes("403") ? "The bridge token was denied." : ""),
          ),
        ),
      reject,
    );
  });
  ready.catch(() => {});
  return { ready, exited };
}

async function tcpRoundTrip(socket) {
  const payload = randomBytes(80000);
  const data = [];
  let size = 0;
  const echoed = new Promise((resolve, reject) => {
    socket.on("error", reject);
    socket.on("close", () => reject(new Error("TCP socket closed early.")));
    socket.on("data", (chunk) => {
      data.push(chunk);
      size += chunk.length;
      if (size >= payload.length) resolve(Buffer.concat(data));
    });
  });
  socket.write(payload);
  expect(await within(echoed, "TCP echo")).toEqual(payload);
}

async function udpRoundTrip(socket, localPort) {
  const payloads = [randomBytes(17), randomBytes(4095), randomBytes(303)];
  const packets = [];
  const echoed = new Promise((resolve, reject) => {
    socket.on("error", reject);
    socket.on("message", (packet) => {
      packets.push(packet);
      if (packets.length === payloads.length) resolve(packets);
    });
  });
  socket.send(randomBytes(5000), localPort, "127.0.0.1");
  for (const payload of payloads) socket.send(payload, localPort, "127.0.0.1");
  expect(await within(echoed, "UDP echo")).toEqual(payloads);
}

async function main() {
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error(
      "Pass the port printed by the disposable loopback fixture.",
    );
  const credentials = JSON.parse(
    fs.readFileSync(
      path.join(
        root,
        ".local",
        (linux ? "linux-" : "") + "operator-login.json",
      ),
    ),
  );
  if (routed && !linux)
    throw new Error("The private route fixture only runs in the Linux lab.");
  const address = routed ? "10.207.241.2" : "127.0.0.1";
  const origin = linux ? "http://127.0.0.1:3001" : "http://127.0.0.1:3000";
  if (credentials.url !== origin) throw new Error("Unexpected console URL.");
  const id = linux
    ? JSON.parse(
        fs.readFileSync(path.join(root, ".local/linux-agent/identity.json")),
      ).node_id
    : JSON.parse(
        fs.readFileSync(
          path.join(root, ".local/evidence/online-before-restart.json"),
        ),
      ).device.id;

  const browser = await chromium.launch();
  let tcp, udp;
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(origin);
    await page
      .getByLabel("Username", { exact: true })
      .fill(credentials.username);
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByRole("heading", { name: "Devices", exact: true }).waitFor();
    const auth = await (
      await page.request.get(origin + "/api/v1/auth/session")
    ).json();
    const headers = { Origin: origin, "X-CSRF-Token": auth.csrf };
    const inventory = await (
      await page.request.get(origin + "/api/v1/devices")
    ).json();
    const device = inventory.devices.find((entry) => entry.id === id);
    if (
      !device ||
      device.group !== "Rust lab" ||
      device.status !== "online" ||
      !device.core_ready
    )
      throw new Error("Recorded lab device is unavailable.");
    await page
      .getByRole("row")
      .filter({ has: page.getByRole("cell", { name: "Online", exact: true }) })
      .getByRole("button", { name: device.name, exact: true })
      .click();
    const panel = page.getByRole("dialog", { name: device.name });
    await panel.getByRole("tab", { name: "Forwarding" }).click();
    const start =
      origin + "/api/v1/devices/" + encodeURIComponent(id) + "/sessions";
    if (routed) {
      const listed = await page.request.get(
        origin +
          "/api/v1/devices/" +
          encodeURIComponent(id) +
          "/forward-routes",
      );
      expect(await listed.json()).toContainEqual({
        name: "lab-echo-tcp",
        address,
        port,
        kind: "tcp",
      });
      for (const body of [
        { kind: "tcp", route: "unapproved" },
        { kind: "udp", route: "lab-echo-tcp" },
      ])
        expect(
          (await page.request.post(start, { headers, data: body })).status(),
        ).toBe(403);
      expect(
        (
          await page.request.post(start, {
            headers,
            data: { kind: "tcp", port, address },
          })
        ).status(),
      ).toBe(422);
      await panel.getByLabel("Destination").selectOption("lab-echo-tcp");
    } else {
      await panel.getByLabel("Device port").fill(String(port));
    }
    const prepared = page.waitForResponse(
      (response) =>
        response.url() === start && response.request().method() === "POST",
    );
    await panel.getByRole("button", { name: "Prepare forward" }).click();
    const tcpResponse = await prepared;
    expect(tcpResponse.status()).toBe(200);
    const tcpSession = await tcpResponse.json();
    expect(tcpSession.session.target_address).toBe(address);
    await expect(panel.getByLabel("Forwarding command")).toContainText(
      "forward tcp",
    );
    await expect(panel.getByLabel("Bridge token")).toBeVisible();

    const bad = bridge(
      "tcp",
      origin,
      tcpSession,
      randomBytes(32).toString("base64url"),
    );
    expect(await within(bad.exited, "Forged credential denial")).toBe(1);
    const tcpBridge = bridge(
      "tcp",
      origin,
      tcpSession,
      tcpSession.bridge_token,
    );
    const tcpPort = await within(tcpBridge.ready, "TCP attach");
    tcp = net.createConnection(tcpPort, "127.0.0.1");
    await within(once(tcp, "connect"), "TCP local connect");
    await tcpRoundTrip(tcp);
    const replay = bridge("tcp", origin, tcpSession, tcpSession.bridge_token);
    expect(await within(replay.exited, "Credential replay denial")).toBe(1);

    const udpResponse = await page.request.post(start, {
      headers,
      data: routed
        ? { kind: "udp", route: "lab-echo-udp" }
        : { kind: "udp", port },
    });
    expect(udpResponse.status()).toBe(200);
    const udpSession = await udpResponse.json();
    const udpBridge = bridge(
      "udp",
      origin,
      udpSession,
      udpSession.bridge_token,
    );
    const udpPort = await within(udpBridge.ready, "UDP attach");
    udp = dgram.createSocket("udp4");
    await udpRoundTrip(udp, udpPort);

    const audit = await (
      await page.request.get(origin + "/api/v1/audit")
    ).json();
    for (const kind of ["tcp", "udp"])
      expect(
        audit.events.some(
          (event) =>
            event.action === "forward.start" &&
            event.target === id + "/" + kind + "/" + address + ":" + port,
        ),
      ).toBe(true);

    const tcpClosed = once(tcp, "close");
    const other = await context.newPage();
    await other.goto(origin);
    await other.getByRole("button", { name: "Sign out", exact: true }).click();
    expect(await within(tcpBridge.exited, "TCP logout")).toBe(0);
    expect(await within(udpBridge.exited, "UDP logout")).toBe(0);
    await within(tcpClosed, "Local TCP close");

    const evidence = {
      recorded_at: new Date().toISOString(),
      tcp_bytes_echoed: 80000,
      udp_datagram_lengths: [17, 4095, 303],
      oversized_and_unexpected_source_datagrams_dropped: true,
      forged_and_replayed_tokens_denied: true,
      forward_start_audited: true,
      logout_closed_both_forwarding_clients: true,
      ...(routed && {
        named_private_route: true,
        unknown_route_and_address_override_denied: true,
      }),
    };
    fs.writeFileSync(
      path.join(root, ".local/evidence", prefix + "forwarding-acceptance.json"),
      JSON.stringify(evidence, null, 2),
      { mode: 0o600 },
    );
    console.log(JSON.stringify(evidence));
  } finally {
    tcp?.destroy();
    udp?.close();
    for (const child of openChildren) child.kill();
    await browser.close();
  }
}

main().catch((error) => {
  const location =
    error.stack?.match(/verify-forward-lab\.cjs:\d+:\d+/)?.[0] ?? "";
  console.error(error.message.split("\n")[0], location);
  process.exitCode = 1;
});
