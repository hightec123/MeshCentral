import { afterAll, beforeAll, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
