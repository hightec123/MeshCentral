// Explicit local acceptance against the configured disposable lab agent only.
// Credentials and artifacts stay under ignored .local/. Never target production.
const fs = require("node:fs");
const path = require("node:path");
const { chromium, devices } = require("../web/node_modules/playwright");
const { expect } = require("../web/node_modules/@playwright/test");
async function main() {
  const root = path.join(__dirname, "..");
  const credentials = JSON.parse(
    fs.readFileSync(path.join(root, ".local/operator-login.json")),
  );
  const expected = JSON.parse(
    fs.readFileSync(
      path.join(root, ".local/evidence/online-before-restart.json"),
    ),
  ).device.id;
  if (credentials.url !== "http://127.0.0.1:3000")
    throw new Error("This acceptance script only targets the local lab URL.");
  const scratch = path.join(root, ".local/lab-agent/acceptance");
  fs.mkdirSync(scratch, { recursive: true, mode: 0o700 });
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
  const result = {};
  try {
    await page.goto(credentials.url);
    await page
      .getByLabel("Username", { exact: true })
      .fill(credentials.username);
    await page
      .getByLabel("Password", { exact: true })
      .fill(credentials.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Devices", exact: true }),
    ).toBeVisible();
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
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await page
      .getByRole("button", { name: original.name, exact: true })
      .click();
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
    await workspace
      .locator("input[type=file]")
      .setInputFiles({
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
    // No keyboard/mouse events are sent to the real desktop during acceptance.
    await workspace
      .getByRole("button", { name: "Disconnect", exact: true })
      .click();
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
      path: path.join(root, ".local/evidence/management-console-desktop.png"),
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
      path: path.join(root, ".local/evidence/management-console-mobile.png"),
      fullPage: true,
    });
    await mobileContext.close();
    result.mobile_layout = true;
    expect(errors).toEqual([]);
    fs.writeFileSync(
      path.join(root, ".local/evidence/management-ui-acceptance.json"),
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
    await browser.close();
  }
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
