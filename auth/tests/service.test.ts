import { afterAll, beforeAll, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
const directory = mkdtempSync(join(tmpdir(), "mcr-auth-test-"));
chmodSync(directory, 0o700);
const secret = crypto.randomUUID() + crypto.randomUUID();
writeFileSync(
  join(directory, "dashboard-auth.json"),
  JSON.stringify({
    schema_version: 1,
    secret,
    internal_secret: secret,
    cookie_prefix: "auth-test",
  }),
  { mode: 0o600 },
);
let child: Bun.Subprocess<"ignore", "pipe", "inherit">;
let url: string;
const origin = "http://127.0.0.1:3300";
async function internal(path: string, body: unknown) {
  return fetch(url + "/internal/" + path, {
    method: "POST",
    headers: { "x-mcr-internal": secret, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}
async function request(path: string, body?: unknown, cookie?: string) {
  return fetch(url + "/api/auth/" + path, {
    method: body ? "POST" : "GET",
    headers: {
      "x-mcr-internal": secret,
      "Content-Type": "application/json",
      Origin: origin,
      ...(cookie ? { Cookie: cookie } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}
function cookies(reply: Response) {
  return reply.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
}
beforeAll(async () => {
  child = Bun.spawn(["bun", join(import.meta.dir, "../src/service.ts")], {
    env: {
      ...process.env,
      MCR_AUTH_DATA_DIR: directory,
      MCR_AUTH_ORIGIN: origin,
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "inherit",
  });
  const reader = child.stdout.getReader();
  let text = "";
  while (!text.includes("MCR_AUTH_READY=")) {
    const chunk = await reader.read();
    if (chunk.done) throw new Error("Auth service failed to start");
    text += new TextDecoder().decode(chunk.value);
  }
  url = "http://127.0.0.1:" + text.match(/MCR_AUTH_READY=(\d+)/)![1];
}, 20000);
afterAll(async () => {
  if (url) await internal("shutdown", {});
  if (child) await child.exited;
  rmSync(directory, { recursive: true, force: true });
});
test("private service and signup cannot bypass Rust account provisioning", async () => {
  expect(
    (await fetch(url + "/internal/session", { method: "POST", body: "{}" }))
      .status,
  ).toBe(403);
  expect(
    (
      await request("sign-up/email", {
        email: "intruder@example.invalid",
        password: "forged-password-123",
        name: "intruder",
      })
    ).status,
  ).toBe(404);
  expect(
    (
      await internal("identity", {
        username: "invalid/name",
        password: "test-password-123",
      })
    ).status,
  ).toBe(400);
});
test("Better Auth signs in an imported Argon2 identity and revokes its cookie", async () => {
  const hash = await Bun.password.hash("imported-password-123", {
    algorithm: "argon2id",
    memoryCost: 19456,
    timeCost: 2,
  });
  const created = await internal("identity", {
    username: "imported",
    password_hash: hash,
  });
  expect(created.ok).toBe(true);
  const id = (await created.json()).user_id;
  expect(
    (
      await internal("identity", {
        username: "imported",
        expected_id: "wrong-id",
      })
    ).status,
  ).toBe(409);
  const login = await request("sign-in/username", {
    username: "imported",
    password: "imported-password-123",
  });
  expect(login.status).toBe(200);
  const cookie = login.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  const current = await (await internal("session", { cookie })).json();
  expect(current.user_id).toBe(id);
  expect(current.username).toBe("imported");
  expect((await request("sign-out", {}, cookie)).status).toBe(200);
  expect(await (await internal("session", { cookie })).json()).toBeNull();
});
test("password reset revokes every session of the provisioned identity", async () => {
  const created = await internal("identity", {
    username: "reset-user",
    password: "original-password-123",
  });
  expect(created.ok).toBe(true);
  const id = (await created.json()).user_id;
  const login = await request("sign-in/username", {
    username: "reset-user",
    password: "original-password-123",
  });
  expect(login.ok).toBe(true);
  const cookie = login.headers
    .getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");
  expect(
    (
      await internal("identity", {
        username: "reset-user",
        expected_id: id,
        password: "replacement-password-123",
      })
    ).ok,
  ).toBe(true);
  expect(await (await internal("session", { cookie })).json()).toBeNull();
  expect(
    (
      await request("sign-in/username", {
        username: "reset-user",
        password: "original-password-123",
      })
    ).status,
  ).toBe(401);
  expect(
    (
      await request("sign-in/username", {
        username: "reset-user",
        password: "replacement-password-123",
      })
    ).ok,
  ).toBe(true);
});

test("MFA enrollment rotates sessions, gates password login, and consumes recovery codes", async () => {
  const username = "mfa-operator";
  const password = "mfa-password-123";
  const credentials = { username, password };
  const { user_id } = await (await internal("identity", credentials)).json();
  const signIn = () => request("sign-in/username", credentials);
  const readSession = async (cookie: string) =>
    (await internal("session", { cookie })).json();
  const enrolling = cookies(await signIn());
  const old = cookies(await signIn());
  expect((await readSession(old)).user_id).toBe(user_id);
  const setup = await request("two-factor/enable", { password }, enrolling);
  expect(setup.status).toBe(200);
  expect(setup.headers.get("cache-control")).toBe("no-store");
  const { totpURI, backupCodes } = await setup.json();
  const key = new URL(totpURI).searchParams.get("secret")!;
  const totp = createOTP(base32.decode(key));
  const enrollmentCode = await totp.totp();
  const [concurrentLogin, confirm] = await Promise.all([
    signIn(),
    request("two-factor/verify-totp", { code: enrollmentCode }, enrolling),
  ]);
  expect(concurrentLogin.status).toBe(200);
  expect(confirm.status).toBe(200);
  const confirmed = cookies(confirm);
  expect((await readSession(confirmed)).user_id).toBe(user_id);
  expect(await readSession(enrolling)).toBeNull();
  expect(await readSession(old)).toBeNull();
  expect(await readSession(cookies(concurrentLogin))).toBeNull();

  const challenge = await signIn();
  expect(await challenge.json()).toMatchObject({ twoFactorRedirect: true });
  const pending = cookies(challenge);
  expect(await readSession(pending)).toBeNull();
  expect((await request("two-factor/disable", { password }, pending)).ok).toBe(
    false,
  );
  const verified = await request(
    "two-factor/verify-totp",
    { code: await totp.totp(), trustDevice: true },
    pending,
  );
  expect(verified.status).toBe(200);
  expect(cookies(verified)).not.toContain("trust_device");
  expect((await readSession(cookies(verified))).user_id).toBe(user_id);

  const cancelled = cookies(await signIn());
  expect((await request("sign-out", {}, cancelled)).ok).toBe(true);
  const recovery = { code: backupCodes[0] };
  expect(
    (await request("two-factor/verify-backup-code", recovery, cancelled)).ok,
  ).toBe(false);
  const recovered = await request(
    "two-factor/verify-backup-code",
    recovery,
    cookies(await signIn()),
  );
  expect(recovered.status).toBe(200);
  expect((await readSession(cookies(recovered))).user_id).toBe(user_id);
  expect(
    (
      await request(
        "two-factor/verify-backup-code",
        recovery,
        cookies(await signIn()),
      )
    ).ok,
  ).toBe(false);

  const disable = await request("two-factor/disable", { password }, confirmed);
  expect(disable.status).toBe(200);
  expect(await readSession(cookies(recovered))).toBeNull();
  expect((await readSession(cookies(await signIn()))).user_id).toBe(user_id);
});
