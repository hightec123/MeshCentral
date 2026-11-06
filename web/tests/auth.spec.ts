import { expect, test } from "@playwright/test";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";

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

test("dashboard enrolls an authenticator and a password alone cannot access devices", async ({
  page,
  context,
  playwright,
}, info) => {
  const origin = "http://127.0.0.1:3100";
  const headers = { Origin: origin };
  const username = "mfa-" + info.project.name;
  const password = "browser-mfa-password-123";
  const credentials = { username, password };
  const request = context.request;
  const admin = await request.post("/api/v1/auth/login", {
    headers,
    data: { username: "test-admin", password: "browser-test-password-123" },
  });
  const { csrf } = await admin.json();
  expect(
    (
      await request.post("/api/v1/users", {
        headers: { ...headers, "X-CSRF-Token": csrf },
        data: { user: { username, role: "viewer", groups: [] }, password },
      })
    ).ok(),
  ).toBe(true);
  expect(
    (
      await request.post("/api/v1/auth/login", { headers, data: credentials })
    ).status(),
  ).toBe(200);

  const old = await playwright.request.newContext({ baseURL: origin });
  try {
    expect(
      (
        await old.post("/api/v1/auth/login", { headers, data: credentials })
      ).status(),
    ).toBe(200);
    await page.goto("/");
    await page.getByRole("button", { name: "Account", exact: true }).click();
    await page.getByLabel("Password for two-factor settings").fill(password);
    await page.getByRole("button", { name: "Set up authenticator" }).click();
    await expect(
      page.getByRole("img", { name: "Authenticator setup QR code" }),
    ).toBeVisible();
    await page.getByText("Enter a setup key manually").click();
    const secret = await page.locator(".mfa-key").innerText();
    await page
      .getByLabel("Authenticator code", { exact: true })
      .fill(await createOTP(base32.decode(secret)).totp());
    await page
      .getByRole("button", { name: "Enable two-factor authentication" })
      .click();
    const code = await page
      .getByRole("list", { name: "Recovery codes" })
      .getByRole("listitem")
      .first()
      .innerText();
    expect((await old.get("/api/v1/devices")).status()).toBe(401);

    const challenge = await old.post("/api/v1/auth/login", {
      headers,
      data: credentials,
    });
    expect(challenge.status()).toBe(202);
    expect(await challenge.json()).toMatchObject({ twoFactorRedirect: true });
    expect((await old.get("/api/v1/devices")).status()).toBe(401);
    expect(
      (
        await old.post("/api/auth/two-factor/disable", {
          headers,
          data: { password },
        })
      ).status(),
    ).toBe(401);

    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByLabel("Username", { exact: true }).fill(username);
    await page.getByLabel("Password", { exact: true }).fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Verify your sign-in" }),
    ).toBeVisible();
    expect((await request.get("/api/v1/devices")).status()).toBe(401);
    await page.getByRole("button", { name: "Use a recovery code" }).click();
    await page.getByLabel("Recovery code", { exact: true }).fill(code);
    await page.getByRole("button", { name: "Verify", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Devices", exact: true }),
    ).toBeVisible();
    expect((await request.get("/api/v1/devices")).status()).toBe(200);
  } finally {
    await old.dispose();
  }
});
