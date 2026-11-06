import { expect, test } from "@playwright/test";

test("passkey enrollment requires the current password and removal revokes sessions", async ({
  page,
  context,
  playwright,
}, info) => {
  const origin = "http://localhost:3100";
  const headers = { Origin: origin };
  const username = "passkey-" + info.project.name;
  const password = "browser-passkey-password-123";
  const credentials = { username, password };
  const request = context.request;
  expect(
    (
      await request.get(origin + "/api/auth/passkey/generate-register-options")
    ).status(),
  ).toBe(401);
  expect(
    (
      await request.get("/api/auth/passkey/generate-authenticate-options")
    ).status(),
  ).toBe(403);
  const options = await request.get(
    origin + "/api/auth/passkey/generate-authenticate-options",
  );
  expect((await options.json()).userVerification).toBe("required");

  const admin = await request.post(origin + "/api/v1/auth/login", {
    headers,
    data: { username: "test-admin", password: "browser-test-password-123" },
  });
  const { csrf } = await admin.json();
  expect(
    (
      await request.post(origin + "/api/v1/users", {
        headers: { ...headers, "X-CSRF-Token": csrf },
        data: { user: { username, role: "viewer", groups: [] }, password },
      })
    ).ok(),
  ).toBe(true);
  expect(
    (
      await request.post(origin + "/api/v1/auth/login", {
        headers,
        data: credentials,
      })
    ).ok(),
  ).toBe(true);

  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    },
  );
  await page.goto(origin);
  await page.getByRole("button", { name: "Account", exact: true }).click();
  await page.getByLabel("Passkey name").fill("Browser test key");
  await page
    .getByLabel("Password for passkey setup")
    .fill("wrong-password-123");
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(page.getByRole("alert")).toContainText(
    "Current password is incorrect",
  );
  await expect(
    page.getByRole("list", { name: "Registered passkeys" }),
  ).toHaveCount(0);
  await cdp.send("WebAuthn.clearCredentials", { authenticatorId });
  await page.getByLabel("Password for passkey setup").fill(password);
  await page.getByRole("button", { name: "Add passkey" }).click();
  await expect(
    page.getByRole("list", { name: "Registered passkeys" }),
  ).toContainText("Browser test key");

  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  expect((await request.get(origin + "/api/v1/devices")).status()).toBe(401);
  const verified = page.waitForResponse((response) =>
    response.url().endsWith("/passkey/verify-authentication"),
  );
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  const verification = await verified;
  expect(await verification.json()).toEqual({ ok: true });
  await expect(
    page.getByRole("heading", { name: "Devices", exact: true }),
  ).toBeVisible();
  expect((await request.get(origin + "/api/v1/devices")).status()).toBe(200);

  const other = await playwright.request.newContext({ baseURL: origin });
  try {
    const assertion = verification.request();
    const replay = await other.post("/api/auth/passkey/verify-authentication", {
      headers: { ...headers, Cookie: (await assertion.allHeaders()).cookie },
      data: assertion.postDataJSON(),
    });
    expect(replay.ok()).toBe(false);
    expect((await other.get("/api/v1/devices")).status()).toBe(401);
    expect(
      (
        await other.post("/api/v1/auth/login", { headers, data: credentials })
      ).ok(),
    ).toBe(true);
    await page.getByRole("button", { name: "Account", exact: true }).click();
    await page
      .getByRole("list", { name: "Registered passkeys" })
      .getByRole("button", { name: "Remove" })
      .click();
    await expect(
      page.getByRole("heading", { name: "Sign in to your workspace" }),
    ).toBeVisible();
    expect((await request.get(origin + "/api/v1/devices")).status()).toBe(401);
    expect((await other.get("/api/v1/devices")).status()).toBe(401);
    await page.getByRole("button", { name: "Sign in with a passkey" }).click();
    await expect(page.getByRole("alert")).toContainText(
      "Passkey sign-in failed",
    );
    expect((await request.get(origin + "/api/v1/devices")).status()).toBe(401);
  } finally {
    await other.dispose();
  }
});
