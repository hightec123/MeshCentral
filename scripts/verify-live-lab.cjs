// Explicit local acceptance against the configured disposable lab agent only.
// Credentials and artifacts stay under ignored .local/. Never target production.
const fs = require("node:fs");
const path = require("node:path");
const { randomBytes, randomUUID } = require("node:crypto");
const { createRequire } = require("node:module");
const { chromium, devices } = require("../web/node_modules/playwright");
const { expect } = require("../web/node_modules/@playwright/test");
const webRequire = createRequire(require.resolve("../web/package.json"));
async function main() {
  const root = path.join(__dirname, "..");
  const flags = process.argv.slice(2);
  const linux = flags.includes("--linux");
  const mfa = flags.includes("--mfa");
  if (flags.some((flag) => !["--linux", "--mfa"].includes(flag)))
    throw new Error("Supported flags: --linux and --mfa.");
  const linuxIdentity = linux
    ? JSON.parse(
        fs.readFileSync(path.join(root, ".local/linux-agent/identity.json")),
      )
    : null;
  const prefix = linux ? "linux-" : "";
  const evidencePrefix = prefix + (mfa ? "mfa-" : "");
  const credentials = JSON.parse(
    fs.readFileSync(
      path.join(root, ".local/" + prefix + "operator-login.json"),
    ),
  );
  const expected =
    linuxIdentity?.node_id ??
    JSON.parse(
      fs.readFileSync(
        path.join(root, ".local/evidence/online-before-restart.json"),
      ),
    ).device.id;
  if (
    credentials.url !==
    (linux ? "http://127.0.0.1:3001" : "http://127.0.0.1:3000")
  )
    throw new Error("This acceptance script only targets the local lab URL.");
  const scratch = linux
    ? linuxIdentity.remote_scratch
    : path.join(root, ".local/lab-agent/acceptance");
  if (
    linux &&
    !/^\/home\/[a-zA-Z0-9._-]+\/meshcentral-lab\/acceptance$/.test(scratch)
  )
    throw new Error("Invalid Linux lab scratch directory.");
  if (!linux) fs.mkdirSync(scratch, { recursive: true, mode: 0o700 });
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  let original, csrf;
  let admin, adminCsrf, operator, totp, recoveryCode;
  const result = {};
  const dashboard = page.getByRole("heading", { name: "Devices", exact: true });
  async function signIn(account, factor) {
    await page.getByLabel("Username", { exact: true }).fill(account.username);
    await page.getByLabel("Password", { exact: true }).fill(account.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    if (factor) {
      await expect(
        page.getByRole("heading", { name: "Verify your sign-in" }),
      ).toBeVisible();
      expect(
        (
          await context.request.get(credentials.url + "/api/v1/devices")
        ).status(),
      ).toBe(401);
      if (factor === "recovery") {
        await page.getByRole("button", { name: "Use a recovery code" }).click();
        await page
          .getByLabel("Recovery code", { exact: true })
          .fill(recoveryCode);
      } else {
        await page
          .getByLabel("Authenticator code", { exact: true })
          .fill(await totp.totp());
      }
      await page.getByRole("button", { name: "Verify", exact: true }).click();
    }
    await expect(dashboard).toBeVisible();
  }
  try {
    if (mfa) {
      admin = await browser.newContext({ baseURL: credentials.url });
      const headers = { Origin: credentials.url };
      const login = await admin.request.post("/api/v1/auth/login", {
        headers,
        data: {
          username: credentials.username,
          password: credentials.password,
        },
      });
      expect(login.status()).toBe(200);
      adminCsrf = (await login.json()).csrf;
      const account = {
        username: "mfa-lab-" + randomUUID().slice(0, 8),
        password: randomBytes(24).toString("base64url"),
      };
      const create = await admin.request.post("/api/v1/users", {
        headers: { ...headers, "X-CSRF-Token": adminCsrf },
        data: {
          user: {
            username: account.username,
            role: "administrator",
            groups: [],
          },
          password: account.password,
        },
      });
      expect(create.ok()).toBe(true);
      operator = account;
    }
    await page.goto(credentials.url);
    await signIn(operator ?? credentials);
    if (mfa) {
      const { base32 } = await import(
        webRequire.resolve("@better-auth/utils/base32")
      );
      const { createOTP } = await import(
        webRequire.resolve("@better-auth/utils/otp")
      );
      await page.getByRole("button", { name: "Account", exact: true }).click();
      await page
        .getByLabel("Password for two-factor settings")
        .fill(operator.password);
      await page.getByRole("button", { name: "Set up authenticator" }).click();
      await expect(
        page.getByRole("img", { name: "Authenticator setup QR code" }),
      ).toBeVisible();
      await page.getByText("Enter a setup key manually").click();
      totp = createOTP(
        base32.decode(await page.locator(".mfa-key").innerText()),
      );
      await page
        .getByLabel("Authenticator code", { exact: true })
        .fill(await totp.totp());
      await page
        .getByRole("button", { name: "Enable two-factor authentication" })
        .click();
      recoveryCode = await page
        .getByRole("list", { name: "Recovery codes" })
        .getByRole("listitem")
        .first()
        .innerText();
      await page.getByRole("button", { name: "Done", exact: true }).click();
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
      await signIn(operator, "totp");
      result.authenticator_sign_in = true;
      result.password_only_inventory_denied = true;
    }
    const auth = await (
      await context.request.get(credentials.url + "/api/v1/auth/session")
    ).json();
    csrf = auth.csrf;
    await expect
      .poll(
        async () => {
          const data = await (
            await context.request.get(credentials.url + "/api/v1/devices")
          ).json();
          return data.devices.find((d) => d.id === expected)?.core_ready;
        },
        { timeout: 30000 },
      )
      .toBe(true);
    const inventory = await (
      await context.request.get(credentials.url + "/api/v1/devices")
    ).json();
    original = inventory.devices.find((d) => d.id === expected);
    if (original.group !== "Rust lab")
      throw new Error("Configured agent is not in the disposable lab group.");
    const deviceButton = page
      .getByRole("row")
      .filter({ has: page.getByRole("cell", { name: "Online", exact: true }) })
      .getByRole("button", { name: original.name, exact: true });
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await deviceButton.click();
    const workspace = page.getByRole("dialog", { name: original.name });
    await workspace
      .getByLabel("Notes", { exact: true })
      .fill("MCR UI acceptance fixture");
    await workspace
      .getByRole("button", { name: "Save details", exact: true })
      .click();
    await expect(
      workspace.getByText("Changes saved", { exact: true }),
    ).toBeVisible();
    const edited = await (
      await context.request.get(
        credentials.url + "/api/v1/devices/" + encodeURIComponent(expected),
      )
    ).json();
    expect(edited.notes).toBe("MCR UI acceptance fixture");
    result.metadata_edit = true;
    await workspace.getByRole("tab", { name: "Terminal", exact: true }).click();
    await workspace
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(
      workspace.getByText("Connected", { exact: true }),
    ).toBeVisible();
    await workspace.locator(".xterm-helper-textarea").focus();
    await page.keyboard.type(
      "printf '%s%s\\n' 'MCR_UI_TERMINAL_' 'VERIFIED_8b32'",
    );
    await page.keyboard.press("Enter");
    await expect(workspace.locator(".xterm-accessibility-tree")).toContainText(
      "MCR_UI_TERMINAL_VERIFIED_8b32",
      { timeout: 15000 },
    );
    result.terminal_ui = true;
    await workspace
      .getByRole("button", { name: "Disconnect", exact: true })
      .click();
    await workspace.getByRole("tab", { name: "Files", exact: true }).click();
    await workspace
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(
      workspace.getByText("Connected", { exact: true }),
    ).toBeVisible();
    await workspace.getByLabel("Remote path", { exact: true }).fill(scratch);
    await workspace.getByRole("button", { name: "Open", exact: true }).click();
    await expect(
      workspace.getByText("0 entries", { exact: true }),
    ).toBeVisible();
    const filename = "ui-roundtrip-" + Date.now() + ".bin";
    const payload = Buffer.from(
      Array.from({ length: 40000 }, (_, i) => (i * 29 + 123) & 255),
    );
    await workspace.locator("input[type=file]").setInputFiles({
      name: filename,
      mimeType: "application/octet-stream",
      buffer: payload,
    });
    const row = workspace
      .getByRole("row")
      .filter({ has: page.getByRole("cell", { name: filename, exact: true }) });
    await expect(row).toBeVisible({ timeout: 15000 });
    const downloaded = page.waitForEvent("download");
    await row.getByRole("button", { name: "Download", exact: true }).click();
    const artifact = await downloaded;
    expect(fs.readFileSync(await artifact.path()).equals(payload)).toBe(true);
    result.file_upload_download_byte_exact = true;
    page.once("dialog", (dialog) => dialog.accept());
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(row).not.toBeVisible();
    result.file_fixture_deleted = true;
    await workspace
      .getByRole("button", { name: "Disconnect", exact: true })
      .click();
    await workspace.getByRole("tab", { name: "Desktop", exact: true }).click();
    await workspace
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(
      workspace.getByText("Connected", { exact: true }),
    ).toBeVisible();
    await expect
      .poll(
        async () =>
          parseInt(await workspace.getByText(/frames drawn$/).innerText(), 10),
        { timeout: 15000 },
      )
      .toBeGreaterThan(0);
    result.desktop_images_drawn = true;
    // Input is permitted only on the disposable Linux VM's virtual desktop.
    // The host's real macOS desktop is always viewed without input.
    const inputName = "desktop-input-" + Date.now() + ".txt";
    if (linux) {
      const launch = require("node:child_process").spawnSync(
        "limactl",
        [
          "shell",
          "mcr-linux",
          "--",
          "sh",
          "-c",
          'cd "$HOME/meshcentral-lab" && DISPLAY=:99 XAUTHORITY="$PWD/empty.xauth" nohup xterm -title MCR-Input-Receiver -geometry 100x30+0+0 -e python3 ./desktop-input-receiver.py "$1" >input-receiver.log 2>&1 </dev/null &',
          "receiver",
          inputName,
        ],
        {
          env: { ...process.env, LIMA_HOME: "/private/tmp/mcr-lima" },
          encoding: "utf8",
        },
      );
      if (launch.status !== 0)
        throw new Error("Could not launch the isolated input receiver.");
      await expect
        .poll(
          () =>
            require("node:child_process").spawnSync(
              "limactl",
              [
                "shell",
                "mcr-linux",
                "--",
                "sh",
                "-c",
                "DISPLAY=:99 xwininfo -root -tree | grep MCR-Input-Receiver",
              ],
              {
                env: { ...process.env, LIMA_HOME: "/private/tmp/mcr-lima" },
                stdio: "ignore",
              },
            ).status,
        )
        .toBe(0);
      await workspace
        .getByRole("checkbox", { name: "Allow mouse and keyboard control" })
        .check();
      await workspace
        .getByLabel("Remote desktop", { exact: true })
        .click({ position: { x: 100, y: 100 } });
      await page.keyboard.type("MCR_DESKTOP_INPUT_VERIFIED", { delay: 100 });
      await page.keyboard.press("Enter");
      // Keep the desktop relay open until the guest has handled the last input
      // packet. Closing it immediately can cancel buffered keystrokes.
      await expect
        .poll(
          () =>
            require("node:child_process").spawnSync(
              "limactl",
              [
                "shell",
                "mcr-linux",
                "--",
                "test",
                "-f",
                scratch + "/" + inputName,
              ],
              {
                env: { ...process.env, LIMA_HOME: "/private/tmp/mcr-lima" },
                stdio: "ignore",
              },
            ).status,
          { timeout: 15000 },
        )
        .toBe(0);
    }
    await workspace
      .getByRole("button", { name: "Disconnect", exact: true })
      .click();
    if (linux) {
      await workspace.getByRole("tab", { name: "Files", exact: true }).click();
      await workspace
        .getByRole("button", { name: "Connect", exact: true })
        .click();
      await expect(
        workspace.getByText("Connected", { exact: true }),
      ).toBeVisible();
      await workspace.getByLabel("Remote path", { exact: true }).fill(scratch);
      await workspace
        .getByRole("button", { name: "Open", exact: true })
        .click();
      const proof = workspace.getByRole("row").filter({
        has: page.getByRole("cell", { name: inputName, exact: true }),
      });
      await expect(proof).toBeVisible({ timeout: 15000 });
      const pending = page.waitForEvent("download");
      await proof
        .getByRole("button", { name: "Download", exact: true })
        .click();
      const download = await pending;
      expect(fs.readFileSync(await download.path(), "utf8")).toBe(
        "MCR_DESKTOP_INPUT_VERIFIED\n",
      );
      page.once("dialog", (dialog) => dialog.accept());
      await proof.getByRole("button", { name: "Delete", exact: true }).click();
      await expect(proof).not.toBeVisible();
      await workspace
        .getByRole("button", { name: "Disconnect", exact: true })
        .click();
      result.desktop_mouse_keyboard_input = true;
    }
    await workspace
      .getByRole("button", { name: "Close device", exact: true })
      .click();
    await page.getByRole("button", { name: "Sessions", exact: true }).click();
    await expect(
      page.getByText("No active remote sessions.", { exact: true }),
    ).toBeVisible();
    result.session_cleanup = true;
    await page.getByRole("button", { name: "Activity", exact: true }).click();
    await expect(
      page.getByRole("cell", { name: "remote.start", exact: true }).first(),
    ).toBeVisible();
    result.audit_ui = true;
    await page.getByRole("button", { name: "Devices", exact: true }).click();
    await page.screenshot({
      path: path.join(
        root,
        ".local/evidence/" + evidencePrefix + "management-console-desktop.png",
      ),
      fullPage: true,
    });
    const mobileContext = await browser.newContext({
      ...devices["Pixel 7"],
      storageState: await context.storageState(),
    });
    const mobile = await mobileContext.newPage();
    await mobile.goto(credentials.url);
    await expect(
      mobile.getByRole("heading", { name: "Devices", exact: true }),
    ).toBeVisible();
    expect(
      await mobile.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await mobile.screenshot({
      path: path.join(
        root,
        ".local/evidence/" + evidencePrefix + "management-console-mobile.png",
      ),
      fullPage: true,
    });
    await mobileContext.close();
    result.mobile_layout = true;
    // Keep raw file/desktop sockets outside React's lifecycle so cross-tab UI
    // cleanup cannot make a missing server-side logout revocation look correct.
    const proofSockets = [];
    for (const kind of ["files", "desktop"]) {
      const response = await context.request.post(
        credentials.url +
          "/api/v1/devices/" +
          encodeURIComponent(expected) +
          "/sessions",
        { headers: { "X-CSRF-Token": csrf }, data: { kind } },
      );
      expect(response.ok()).toBe(true);
      proofSockets.push((await response.json()).socket_path);
    }
    await page.evaluate(async (paths) => {
      window.mcrLogoutProof = { closed: 0, sockets: [] };
      await Promise.all(
        paths.map(
          (path) =>
            new Promise((resolve, reject) => {
              const ws = new WebSocket(
                (location.protocol === "https:" ? "wss://" : "ws://") +
                  location.host +
                  path,
              );
              window.mcrLogoutProof.sockets.push(ws);
              ws.onclose = () => {
                window.mcrLogoutProof.closed++;
              };
              ws.onerror = () =>
                reject(new Error("Logout proof connection failed"));
              ws.onmessage = (event) => {
                if (typeof event.data === "string") {
                  try {
                    if (JSON.parse(event.data).event === "connected") resolve();
                  } catch {}
                }
              };
            }),
        ),
      );
    }, proofSockets);
    await deviceButton.click();
    const terminalWorkspace = page.getByRole("dialog", { name: original.name });
    await terminalWorkspace
      .getByRole("tab", { name: "Terminal", exact: true })
      .click();
    await terminalWorkspace
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(
      terminalWorkspace.getByText("Connected", { exact: true }),
    ).toBeVisible();
    const secondTab = await context.newPage();
    await secondTab.goto(credentials.url);
    await expect(
      secondTab.getByRole("heading", { name: "Devices", exact: true }),
    ).toBeVisible();
    await secondTab
      .getByRole("button", { name: "Sign out", exact: true })
      .click();
    await expect(
      secondTab.getByRole("heading", { name: "Sign in to your workspace" }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Sign in to your workspace" }),
    ).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => window.mcrLogoutProof.closed), {
        timeout: 5000,
      })
      .toBe(2);
    expect(
      (await context.request.get(credentials.url + "/api/v1/devices")).status(),
    ).toBe(401);
    await secondTab.close();
    result.logout_closes_native_remote_sessions = true;
    await signIn(operator ?? credentials, mfa ? "recovery" : undefined);
    if (mfa) result.recovery_code_sign_in = true;
    csrf = (
      await (
        await context.request.get(credentials.url + "/api/v1/auth/session")
      ).json()
    ).csrf;
    const remaining = await (
      await context.request.get(credentials.url + "/api/v1/sessions")
    ).json();
    expect(remaining.sessions).toEqual([]);
    const connected = await (
      await context.request.get(credentials.url + "/api/v1/devices")
    ).json();
    expect(
      connected.devices.find((device) => device.id === expected)?.status,
    ).toBe("online");
    result.agent_stays_online_after_logout = true;
    expect(errors).toEqual([]);
    fs.writeFileSync(
      path.join(
        root,
        ".local/evidence/" + evidencePrefix + "management-ui-acceptance.json",
      ),
      JSON.stringify(
        { recorded_at: new Date().toISOString(), ...result },
        null,
        2,
      ),
      { mode: 0o600 },
    );
    console.log(JSON.stringify(result));
  } finally {
    if (original && csrf)
      await context.request
        .patch(
          credentials.url + "/api/v1/devices/" + encodeURIComponent(expected),
          {
            headers: { "X-CSRF-Token": csrf },
            data: {
              alias: original.alias,
              notes: original.notes,
              tags: original.tags,
            },
          },
        )
        .catch(() => {});
    try {
      if (operator && adminCsrf) {
        const headers = { Origin: credentials.url, "X-CSRF-Token": adminCsrf };
        const removed = await admin.request.delete(
          "/api/v1/users/" + operator.username,
          { headers },
        );
        expect(removed.ok()).toBe(true);
        await admin.request.post("/api/auth/sign-out", { headers, data: {} });
      }
    } finally {
      await browser.close();
    }
  }
}
main().catch((error) => {
  // Playwright request diagnostics can include authenticated request headers.
  console.error(String(error.message ?? error).split("\n")[0]);
  process.exitCode = 1;
});
