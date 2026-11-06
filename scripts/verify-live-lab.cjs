// Explicit local acceptance against the configured disposable lab agent only.
// Credentials and artifacts stay under ignored .local/. Never target production.
const fs = require("node:fs");
const path = require("node:path");
const { randomBytes, randomUUID } = require("node:crypto");
const { createRequire } = require("node:module");
const { chromium, devices } = require("../web/node_modules/playwright");
const { expect } = require("../web/node_modules/@playwright/test");
const webRequire = createRequire(require.resolve("../web/package.json"));
const mailpit = "http://127.0.0.1:18025/api/v1";
async function recoveryMessages(email) {
  const response = await fetch(mailpit + "/messages");
  if (!response.ok) throw new Error("Could not read the disposable lab inbox.");
  const { messages } = await response.json();
  return messages.filter((message) =>
    message.To?.some((to) => to.Address === email),
  );
}
async function recoveryMailLink(email, kind, origin) {
  const subject =
    kind === "verify-recovery"
      ? "Confirm your recovery email"
      : "Reset your password";
  let message;
  await expect
    .poll(
      async () => {
        message = (await recoveryMessages(email)).find((entry) =>
          entry.Subject.endsWith(subject),
        );
        return Boolean(message);
      },
      { timeout: 15000 },
    )
    .toBe(true);
  const response = await fetch(
    mailpit + "/message/" + encodeURIComponent(message.ID),
  );
  if (!response.ok) throw new Error("Could not read the recovery email.");
  const { Text } = await response.json();
  const href = Text.split(/\r?\n/).find((line) =>
    line.startsWith(origin + "/#" + kind + "="),
  );
  if (!href)
    throw new Error("Recovery email did not point to the expected lab.");
  return new URL(href);
}
async function main() {
  const root = path.join(__dirname, "..");
  const flags = process.argv.slice(2);
  const linux = flags.includes("--linux");
  const mfa = flags.includes("--mfa");
  const passkey = flags.includes("--passkey");
  const emailRecovery = flags.includes("--recovery");
  const scriptRun = flags.includes("--scripts");
  const fleet = flags.includes("--fleet");
  const schedules = fleet || flags.includes("--schedules");
  if (
    flags.some(
      (flag) =>
        ![
          "--linux",
          "--mfa",
          "--passkey",
          "--recovery",
          "--scripts",
          "--schedules",
          "--fleet",
        ].includes(flag),
    ) ||
    (passkey && emailRecovery)
  )
    throw new Error(
      "Use --linux, --mfa, --scripts, or --schedules with either --passkey or --recovery.",
    );
  const linuxIdentity = linux
    ? JSON.parse(
        fs.readFileSync(path.join(root, ".local/linux-agent/identity.json")),
      )
    : null;
  const prefix = linux ? "linux-" : "";
  const evidencePrefix =
    prefix +
    (fleet
      ? "fleet-"
      : schedules
        ? "schedules-"
        : scriptRun
          ? "scripts-"
          : emailRecovery
            ? "recovery-"
            : passkey
              ? "passkey-"
              : mfa
                ? "mfa-"
                : "");
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
  if (passkey)
    credentials.url = credentials.url.replace("127.0.0.1", "localhost");
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
  const failedPaths = [];
  page.on("response", (response) => {
    if (response.status() >= 400)
      failedPaths.push(
        `${response.status()} ${new URL(response.url()).pathname}`,
      );
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  let original, csrf;
  let admin, adminCsrf, operator, totp, recoveryCode;
  let recoveryContext, mailbox;
  let schedulePath;
  const scheduleIds = new Map();
  const scheduleName = "Lab acceptance " + randomUUID().slice(0, 8);
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
  async function signInWithPasskey() {
    expect(
      (await context.request.get(credentials.url + "/api/v1/devices")).status(),
    ).toBe(401);
    await page
      .getByRole("button", { name: "Sign in with a passkey", exact: true })
      .click();
    await expect(dashboard).toBeVisible();
    const session = await (
      await context.request.get(credentials.url + "/api/v1/auth/session")
    ).json();
    expect(session.user.username).toBe(operator.username);
  }
  try {
    if (mfa || passkey || emailRecovery) {
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
        username:
          (emailRecovery
            ? "recovery-lab-"
            : passkey
              ? "passkey-lab-"
              : "mfa-lab-") + randomUUID().slice(0, 8),
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
    if (passkey) {
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable");
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
        },
      });
      await page.getByRole("button", { name: "Account", exact: true }).click();
      await page
        .getByLabel("Passkey name")
        .fill("Disposable lab authenticator");
      await page
        .getByLabel("Password for passkey setup")
        .fill(operator.password);
      await page
        .getByRole("button", { name: "Add passkey", exact: true })
        .click();
      await expect(
        page.getByRole("list", { name: "Registered passkeys" }),
      ).toContainText("Disposable lab authenticator");
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
      await signInWithPasskey();
      result.passkey_sign_in = true;
    }
    if (emailRecovery) {
      mailbox = operator.username + "@recovery.test";
      recoveryContext = await browser.newContext({ baseURL: credentials.url });
      await page.getByRole("button", { name: "Account", exact: true }).click();
      await page.getByLabel("New recovery email").fill(mailbox);
      await page
        .getByLabel("Password for recovery email")
        .fill(operator.password);
      await page
        .getByRole("button", { name: "Send confirmation", exact: true })
        .click();
      await expect(
        page.getByText("Check your inbox to confirm the recovery address."),
      ).toBeVisible();
      const before = await context.request.get(
        credentials.url + "/api/auth/recovery-email",
      );
      expect((await before.json()).email).toBeNull();
      const unverified = await recoveryContext.request.post(
        "/api/auth/request-password-reset",
        {
          headers: { Origin: credentials.url },
          data: { email: mailbox },
        },
      );
      expect(unverified.ok()).toBe(true);
      expect(
        (await recoveryMessages(mailbox)).every(
          (message) => !message.Subject.endsWith("Reset your password"),
        ),
      ).toBe(true);
      const confirm = await recoveryMailLink(
        mailbox,
        "verify-recovery",
        credentials.url,
      );
      const emailPage = await recoveryContext.newPage();
      await emailPage.goto(confirm.href);
      await emailPage
        .getByRole("button", { name: "Confirm email", exact: true })
        .click();
      await expect(
        emailPage.getByText("Your recovery email is confirmed."),
      ).toBeVisible();
      const confirmed = await context.request.get(
        credentials.url + "/api/auth/recovery-email",
      );
      expect((await confirmed.json()).email).toBe(mailbox);
      expect(
        (await recoveryContext.request.get("/api/v1/devices")).status(),
      ).toBe(401);
      await emailPage.close();
      result.recovery_email_confirmed = true;
      result.unverified_address_ineligible = true;
      await page.getByRole("button", { name: "Devices", exact: true }).click();
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
    if (schedules) {
      schedulePath =
        credentials.url +
        "/api/v1/devices/" +
        encodeURIComponent(expected) +
        "/schedules";
      const headers = { Origin: credentials.url, "X-CSRF-Token": csrf };
      if (fleet) {
        const fleetPath = credentials.url + "/api/v1/schedules";
        await workspace.getByRole("button", { name: "Close device" }).click();
        await page
          .getByRole("navigation", { name: "Main navigation" })
          .getByRole("button", { name: "Tasks", exact: true })
          .click();
        const tasksPage = page.getByRole("main");
        await tasksPage
          .getByRole("checkbox", {
            name: [
              original.name,
              original.group,
              "online",
              expected.slice(-8),
            ].join(" · "),
            exact: true,
          })
          .check();
        await tasksPage.getByLabel("Task name").fill(scheduleName);
        const next = new Date(Date.now() + 60 * 60 * 1000);
        next.setMinutes(next.getMinutes() - next.getTimezoneOffset());
        await tasksPage
          .getByLabel("First run (local time)")
          .fill(next.toISOString().slice(0, 16));
        await tasksPage.getByLabel("Scheduled shell script").fill("exit 8");
        const response = page.waitForResponse(
          (entry) =>
            entry.url() === fleetPath && entry.request().method() === "POST",
        );
        await tasksPage
          .getByRole("button", { name: "Schedule script" })
          .click();
        const created = await response;
        expect(created.status()).toBe(201);
        const [task] = await created.json();
        scheduleIds.set(task.id, expected);
        expect(task.device_id).toBe(expected);
        const scheduled = tasksPage
          .getByRole("article")
          .filter({ hasText: scheduleName });
        await expect(scheduled).toContainText(original.name);
        await scheduled.getByRole("button", { name: "Cancel task" }).click();
        await expect(scheduled).toHaveCount(0);
        await page
          .getByRole("navigation", { name: "Main navigation" })
          .getByRole("button", { name: "Devices", exact: true })
          .click();
        await deviceButton.click();
        result.fleet_picker_and_cancel = true;
      }
      await workspace.getByRole("tab", { name: "Tasks", exact: true }).click();
      await workspace.getByLabel("Task name").fill(scheduleName);
      const future = new Date(Date.now() + 60 * 60 * 1000);
      future.setMinutes(future.getMinutes() - future.getTimezoneOffset());
      await workspace
        .getByLabel("First run (local time)")
        .fill(future.toISOString().slice(0, 16));
      await workspace.getByLabel("Scheduled shell script").fill("exit 8");
      const created = page.waitForResponse(
        (response) =>
          response.url() === schedulePath &&
          response.request().method() === "POST",
      );
      await workspace.getByRole("button", { name: "Schedule script" }).click();
      const createdResponse = await created;
      expect(createdResponse.status()).toBe(201);
      const uiTask = await createdResponse.json();
      scheduleIds.set(uiTask.id, expected);
      const article = workspace
        .getByRole("article")
        .filter({ hasText: scheduleName });
      await expect(article).toBeVisible();
      await article.getByRole("button", { name: "Cancel task" }).click();
      await expect(article).toHaveCount(0);
      const firstRun = new Date(Date.now() + 8000);
      const body = {
        name: scheduleName,
        script: "exit 7",
        run_at: firstRun.toISOString(),
        repeat: "daily",
      };
      const offline =
        fleet && linux
          ? inventory.devices.find(
              (device) =>
                device.id !== expected &&
                device.group === "Rust lab" &&
                device.platform === "Linux" &&
                device.status === "offline",
            )
          : null;
      if (fleet && linux) expect(offline).toBeTruthy();
      const targets = offline ? [expected, offline.id] : [expected];
      const response = await context.request.post(
        fleet ? credentials.url + "/api/v1/schedules" : schedulePath,
        { headers, data: fleet ? { devices: targets, task: body } : body },
      );
      expect(response.status()).toBe(201);
      const data = await response.json();
      const task = fleet ? data[0] : data;
      scheduleIds.set(task.id, expected);
      if (offline) {
        const other = data.find((entry) => entry.device_id === offline.id);
        expect(other).toBeTruthy();
        scheduleIds.set(other.id, offline.id);
        const fleetPath = credentials.url + "/api/v1/schedules";
        await expect
          .poll(
            async () => {
              const all = await (await context.request.get(fleetPath)).json();
              return all.find((entry) => entry.id === other.id)?.last_run
                ?.status;
            },
            { timeout: 20000 },
          )
          .toBe("device_unavailable");
        const offlinePath =
          credentials.url +
          "/api/v1/devices/" +
          encodeURIComponent(offline.id) +
          "/schedules/" +
          other.id;
        expect(
          (await context.request.delete(offlinePath, { headers })).status(),
        ).toBe(204);
        result.fleet_independent_offline_outcome = true;
      }
      await expect(
        article.getByText("Failed · exit 7", { exact: false }),
      ).toBeVisible({ timeout: 25000 });
      const records = await (await context.request.get(schedulePath)).json();
      const done = records.find((record) => record.id === task.id);
      expect(done.last_run).toMatchObject({ status: "failed", exit_code: 7 });
      expect(Date.parse(done.next_run)).toBe(firstRun.getTime() + 86400000);
      expect(done).not.toHaveProperty("script");
      const { events } = await (
        await context.request.get(credentials.url + "/api/v1/audit")
      ).json();
      expect(
        events.some(
          (event) =>
            event.action === "schedule.run" &&
            event.target === task.id &&
            event.outcome === "failed",
        ),
      ).toBe(true);
      await article.getByRole("button", { name: "Cancel task" }).click();
      await expect(article).toHaveCount(0);
      expect(
        (await (await context.request.get(schedulePath)).json()).some(
          (record) => scheduleIds.has(record.id),
        ),
      ).toBe(false);
      result.schedule_create_cancel = true;
      result.schedule_agent_exit_and_audit = true;
      result.schedule_daily_advances = true;
    }
    if (scriptRun) {
      await workspace
        .getByRole("tab", { name: "Scripts", exact: true })
        .click();
      await workspace
        .getByLabel("Shell script")
        .fill(
          "printf '%s\\n' 'MCR_SCRIPT_STDOUT'\nprintf '%s\\n' 'MCR_SCRIPT_STDERR' >&2\nexit 7",
        );
      await workspace
        .getByRole("button", { name: "Run script", exact: true })
        .click();
      await expect(
        workspace.getByText("Script finished with exit code 7.", {
          exact: true,
        }),
      ).toBeVisible({ timeout: 30000 });
      await expect(workspace.getByLabel("Script output")).toContainText(
        "MCR_SCRIPT_STDOUT",
      );
      await expect(workspace.getByLabel("Script output")).toContainText(
        "MCR_SCRIPT_STDERR",
      );
      const run = await context.request.post(
        credentials.url +
          "/api/v1/devices/" +
          encodeURIComponent(expected) +
          "/scripts/run",
        {
          headers: { "X-CSRF-Token": csrf, Origin: credentials.url },
          data: { script: "printf '%09000d' 1\nexit 0" },
        },
      );
      expect(run.ok()).toBe(true);
      const output = await run.json();
      expect(output).toMatchObject({
        status: "completed",
        exit_code: 0,
        truncated: true,
      });
      expect(Buffer.byteLength(output.output)).toBe(8192);
      const { events } = await (
        await context.request.get(credentials.url + "/api/v1/audit")
      ).json();
      expect(
        events.some(
          (event) =>
            event.action === "script.run" &&
            event.target === expected + "/" + output.id &&
            event.outcome === "success",
        ),
      ).toBe(true);
      result.script_output_and_exit_code = true;
      result.script_output_cap_and_audit = true;
    }
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
    // Keep raw relay sockets outside React's lifecycle so cross-tab UI
    // cleanup cannot make a missing server-side logout revocation look correct.
    const proofSockets = [];
    for (const kind of ["terminal", "files", "desktop"]) {
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
              const timeout = setTimeout(
                () =>
                  reject(new Error("Timed out opening a logout proof relay")),
                15000,
              );
              ws.onclose = () => {
                window.mcrLogoutProof.closed++;
              };
              ws.onerror = () => {
                clearTimeout(timeout);
                reject(new Error("Logout proof connection failed"));
              };
              ws.onmessage = (event) => {
                if (typeof event.data === "string") {
                  try {
                    if (JSON.parse(event.data).event === "connected") {
                      clearTimeout(timeout);
                      resolve();
                    }
                  } catch {}
                }
              };
            }),
        ),
      );
    }, proofSockets);
    let replacementPassword;
    if (emailRecovery) {
      const headers = { Origin: credentials.url };
      const unknown = await recoveryContext.request.post(
        "/api/auth/request-password-reset",
        {
          headers,
          data: { email: "unknown-" + mailbox },
        },
      );
      const forgot = await recoveryContext.newPage();
      await forgot.goto(credentials.url);
      await forgot
        .getByRole("button", { name: "Forgot password?", exact: true })
        .click();
      await forgot.getByLabel("Recovery email", { exact: true }).fill(mailbox);
      const requested = forgot.waitForResponse(
        (response) =>
          new URL(response.url()).pathname ===
          "/api/auth/request-password-reset",
      );
      await forgot
        .getByRole("button", { name: "Send reset link", exact: true })
        .click();
      await expect(
        forgot.getByText(
          "If this address is registered for recovery, you’ll receive a reset link.",
        ),
      ).toBeVisible();
      expect(await (await requested).json()).toEqual(await unknown.json());
      const reset = await recoveryMailLink(
        mailbox,
        "reset-password",
        credentials.url,
      );
      const resetPage = await recoveryContext.newPage();
      await resetPage.goto(reset.href);
      replacementPassword = randomBytes(24).toString("base64url");
      await resetPage
        .getByLabel("New password", { exact: true })
        .fill(replacementPassword);
      await resetPage
        .getByLabel("Confirm new password", { exact: true })
        .fill(replacementPassword);
      await resetPage
        .getByRole("button", { name: "Reset password", exact: true })
        .click();
      await expect(
        resetPage.getByText(
          "Your password was reset. Sign in with your new password.",
        ),
      ).toBeVisible();
      const token = new URLSearchParams(reset.hash.slice(1)).get(
        "reset-password",
      );
      const replay = await recoveryContext.request.post(
        "/api/auth/reset-password",
        {
          headers,
          data: { token, newPassword: replacementPassword },
        },
      );
      expect(replay.ok()).toBe(false);
      expect(
        (await recoveryContext.request.get("/api/v1/devices")).status(),
      ).toBe(401);
      expect(
        (
          await recoveryContext.request.post("/api/v1/auth/login", {
            headers,
            data: operator,
          })
        ).status(),
      ).toBe(401);
      const audit = await admin.request.get("/api/v1/audit");
      expect(audit.ok()).toBe(true);
      const { events } = await audit.json();
      expect(
        events.some(
          (entry) =>
            entry.actor === operator.username &&
            entry.action === "account.recovery.reset",
        ),
      ).toBe(true);
      result.email_password_reset = true;
      result.reset_token_single_use = true;
      result.old_password_denied = true;
      result.unknown_address_response_matches = true;
    } else {
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
      await secondTab.close();
    }
    await expect
      .poll(() => page.evaluate(() => window.mcrLogoutProof.closed), {
        timeout: 5000,
      })
      .toBe(proofSockets.length);
    expect(
      (await context.request.get(credentials.url + "/api/v1/devices")).status(),
    ).toBe(401);
    if (emailRecovery) {
      result.reset_closes_native_remote_sessions = true;
      await page.reload();
      await signIn(
        { username: operator.username, password: replacementPassword },
        mfa ? "totp" : undefined,
      );
      result.new_password_sign_in = true;
      if (mfa) result.reset_preserves_mfa = true;
    } else if (passkey) {
      result.logout_closes_native_remote_sessions = true;
      await signInWithPasskey();
      result.passkey_sign_in_after_logout = true;
    } else {
      result.logout_closes_native_remote_sessions = true;
      await signIn(operator ?? credentials, mfa ? "recovery" : undefined);
      if (mfa) result.recovery_code_sign_in = true;
    }
    csrf = (
      await (
        await context.request.get(credentials.url + "/api/v1/auth/session")
      ).json()
    ).csrf;
    const remaining = await (
      await context.request.get(credentials.url + "/api/v1/sessions")
    ).json();
    if (!Array.isArray(remaining.sessions) || remaining.sessions.length)
      throw new Error("Remote sessions remained after logout.");
    const connected = await (
      await context.request.get(credentials.url + "/api/v1/devices")
    ).json();
    expect(
      connected.devices.find((device) => device.id === expected)?.status,
    ).toBe("online");
    result[
      emailRecovery
        ? "agent_stays_online_after_reset"
        : "agent_stays_online_after_logout"
    ] = true;
    if (errors.length)
      throw new Error(
        `Browser reported ${errors.length} errors. Failed requests: ${failedPaths.join(", ")}`,
      );
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
    if (schedulePath && csrf) {
      for (const [id, device] of scheduleIds)
        await context.request
          .delete(
            credentials.url +
              "/api/v1/devices/" +
              encodeURIComponent(device) +
              "/schedules/" +
              encodeURIComponent(id),
            {
              headers: { Origin: credentials.url, "X-CSRF-Token": csrf },
            },
          )
          .catch(() => {});
    }
    if (original && csrf)
      await (admin?.request ?? context.request)
        .patch(
          credentials.url + "/api/v1/devices/" + encodeURIComponent(expected),
          {
            headers: { "X-CSRF-Token": adminCsrf ?? csrf },
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
      if (mailbox) {
        const ids = (await recoveryMessages(mailbox)).map(
          (message) => message.ID,
        );
        if (ids.length) {
          const removed = await fetch(mailpit + "/messages", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ IDs: ids }),
          });
          if (!removed.ok)
            throw new Error(
              "Could not clean up the disposable recovery messages.",
            );
        }
      }
    } finally {
      await browser.close();
    }
  }
}
main().catch((error) => {
  // Playwright request diagnostics can include authenticated request headers.
  const location = String(error.stack).match(
    /verify-live-lab\.cjs:\d+:\d+/,
  )?.[0];
  console.error(
    String(error.message ?? error)
      .split("\n")[0]
      .replace(
        /(verify-recovery|reset-password)=[A-Za-z0-9_-]+/g,
        "$1=[redacted]",
      ),
    location ?? "",
  );
  process.exitCode = 1;
});
