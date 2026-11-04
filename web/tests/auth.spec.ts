import { expect, test } from "@playwright/test";

test("sign-out updates another dashboard tab sharing the same Better Auth session", async ({
  page,
  context,
}) => {
  const login = await context.request.post("/api/v1/auth/login", {
    headers: { Origin: "http://127.0.0.1:3100" },
    data: { username: "test-admin", password: "browser-test-password-123" },
  });
  expect(login.ok()).toBe(true);
  await page.goto("/");
  const other = await context.newPage();
  await other.goto("/");
  await expect(
    page.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  await expect(
    other.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  await expect(
    other.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  expect((await context.request.get("/api/v1/devices")).status()).toBe(401);
  await other.close();
});

test("sign-in form validates credentials and sign-out protects the inventory", async ({
  page,
  context,
}) => {
  const request = context.request;
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  await page.getByLabel("Username", { exact: true }).fill("test-admin");
  await page.getByLabel("Password", { exact: true }).fill("incorrect-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Sign-in failed");
  await page
    .getByLabel("Password", { exact: true })
    .fill("browser-test-password-123");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  expect((await request.get("/api/v1/devices")).status()).toBe(401);
});

test("administrator can create a viewer without granting account-management rights", async ({
  page,
  context,
}, info) => {
  const request = context.request;
  expect(
    (
      await request.post("/api/v1/auth/login", {
        headers: { Origin: "http://127.0.0.1:3100" },
        data: { username: "test-admin", password: "browser-test-password-123" },
      })
    ).ok(),
  ).toBe(true);
  await page.goto("/");
  await page.getByRole("button", { name: "People", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Create or update an operator" }),
  ).toBeVisible();
  const username = "viewer-" + info.project.name;
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page
    .getByLabel("Password", { exact: true })
    .fill("viewer-password-123");
  await page
    .getByRole("button", { name: "Save operator", exact: true })
    .click();
  await expect(
    page.getByRole("cell", { name: username, exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page
    .getByLabel("Password", { exact: true })
    .fill("viewer-password-123");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "People", exact: true }),
  ).not.toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sessions", exact: true }),
  ).not.toBeVisible();
  expect((await request.get("/api/v1/users")).status()).toBe(403);
  expect((await request.get("/api/v1/audit")).status()).toBe(403);
  const session = await (await request.get("/api/v1/auth/session")).json();
  expect(
    (
      await request.post("/api/v1/users", {
        headers: { "X-CSRF-Token": session.csrf },
        data: { user: { username, role: "administrator", groups: [] } },
      })
    ).status(),
  ).toBe(403);
});

test("account password change revokes its session and requires the new password", async ({
  page,
  context,
}, info) => {
  const request = context.request;
  const admin = await request.post("/api/v1/auth/login", {
    headers: { Origin: "http://127.0.0.1:3100" },
    data: { username: "test-admin", password: "browser-test-password-123" },
  });
  const auth = await admin.json();
  const username = "password-" + info.project.name;
  expect(
    (
      await request.post("/api/v1/users", {
        headers: { "X-CSRF-Token": auth.csrf },
        data: {
          user: { username, role: "viewer", groups: [] },
          password: "original-password-123",
        },
      })
    ).ok(),
  ).toBe(true);
  expect(
    (
      await request.post("/api/v1/auth/login", {
        headers: { Origin: "http://127.0.0.1:3100" },
        data: { username, password: "original-password-123" },
      })
    ).ok(),
  ).toBe(true);
  await page.goto("/");
  await page.getByRole("button", { name: "Account", exact: true }).click();
  await page
    .getByLabel("Current password", { exact: true })
    .fill("original-password-123");
  await page
    .getByLabel("New password", { exact: true })
    .fill("replacement-password-123");
  await page
    .getByRole("button", { name: "Change password", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Sign in to your workspace" }),
  ).toBeVisible();
  expect((await request.get("/api/v1/devices")).status()).toBe(401);
  expect(
    (
      await request.post("/api/v1/auth/login", {
        headers: { Origin: "http://127.0.0.1:3100" },
        data: { username, password: "original-password-123" },
      })
    ).status(),
  ).toBe(401);
  expect(
    (
      await request.post("/api/v1/auth/login", {
        headers: { Origin: "http://127.0.0.1:3100" },
        data: { username, password: "replacement-password-123" },
      })
    ).ok(),
  ).toBe(true);
});
