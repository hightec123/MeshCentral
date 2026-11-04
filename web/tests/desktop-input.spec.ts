import { expect, test } from "@playwright/test";

test("desktop input requires explicit control and stays scoped to its canvas", async ({
  page,
  context,
}) => {
  await context.request.post("/api/v1/auth/login", {
    headers: { Origin: "http://127.0.0.1:3100" },
    data: { username: "test-admin", password: "browser-test-password-123" },
  });
  const device = {
    id: "desktop-fixture",
    name: "Desktop fixture",
    hostname: "desktop-fixture",
    platform: "Linux",
    group: "Lab",
    group_id: "A1".repeat(48),
    node_id_hex: "B2".repeat(48),
    status: "online",
    last_seen: null,
    core_ready: true,
  };
  await page.route("**/api/v1/devices", (route) =>
    route.fulfill({ json: { devices: [device] } }),
  );
  await page.route("**/api/v1/devices/desktop-fixture", (route) =>
    route.fulfill({ json: device }),
  );
  await page.route("**/api/v1/devices/desktop-fixture/sessions", (route) =>
    route.fulfill({
      json: {
        session: { id: "test-desktop" },
        socket_path: "/api/v1/sessions/test-desktop/socket",
      },
    }),
  );
  await page.route("**/api/v1/sessions/test-desktop", (route) =>
    route.fulfill({ status: 204 }),
  );
  const inputs: number[] = [];
  await page.routeWebSocket("**/api/v1/sessions/test-desktop/socket", (ws) => {
    ws.onMessage((message) => {
      if (Buffer.isBuffer(message) && message.length >= 4) {
        const command = message.readUInt16BE(0);
        if ([1, 2, 85].includes(command)) inputs.push(command);
      }
    });
    ws.send(JSON.stringify({ event: "connected", kind: "desktop" }));
  });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByRole("button", { name: device.name, exact: true }).click();
  const dialog = page.getByRole("dialog", { name: device.name });
  await dialog.getByRole("tab", { name: "Desktop", exact: true }).click();
  await dialog.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(dialog.getByText("Connected", { exact: true })).toBeVisible();
  const canvas = dialog.getByLabel("Remote desktop", { exact: true });
  await canvas.click({ position: { x: 50, y: 50 } });
  await page.keyboard.type("blocked");
  await page.keyboard.press("Enter");
  expect(inputs).toEqual([]);
  await dialog
    .getByRole("checkbox", { name: "Allow mouse and keyboard control" })
    .check();
  await canvas.click({ position: { x: 60, y: 60 } });
  await page.keyboard.type("allowed");
  await page.keyboard.press("Enter");
  await expect
    .poll(() => inputs.filter((command) => command === 2).length)
    .toBeGreaterThan(0);
  await expect
    .poll(() => inputs.filter((command) => command === 85).length)
    .toBeGreaterThan(0);
  await expect
    .poll(() => inputs.filter((command) => command === 1).length)
    .toBeGreaterThan(0);
  await dialog
    .getByRole("checkbox", { name: "Allow mouse and keyboard control" })
    .uncheck();
  const count = inputs.length;
  await canvas.click({ position: { x: 70, y: 70 } });
  await page.keyboard.type("blocked-again");
  await page.keyboard.press("Enter");
  expect(inputs.length).toBe(count);
  expect(errors).toEqual([]);
});
