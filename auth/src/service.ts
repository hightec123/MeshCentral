// Private, Rust-supervised Better Auth service. The public proxy exposes only
// dashboard authentication endpoints; device permissions remain in Rust.
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { username } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";
import { chmodSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { timingSafeEqual } from "node:crypto";

process.umask(0o077);
const directory = process.env.MCR_AUTH_DATA_DIR;
const origin = process.env.MCR_AUTH_ORIGIN;
if (!directory || !origin)
  throw new Error("Rust must configure the private auth service.");
const secrets = JSON.parse(
  readFileSync(join(directory, "dashboard-auth.json"), "utf8"),
);
if (statSync(directory).mode & 0o077)
  throw new Error("Auth state directory must be private.");
const database = new Database(join(directory, "dashboard-auth.sqlite"), {
  create: true,
  strict: true,
});
database.exec(
  "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000;",
);
chmodSync(join(directory, "dashboard-auth.sqlite"), 0o600);
const base = new URL(origin);
if (
  !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname) ||
  base.protocol !== "http:"
)
  throw new Error("Only the loopback preview is supported.");
const options = {
  appName: "MeshCentral Rust",
  baseURL: origin,
  basePath: "/api/auth",
  secret: secrets.secret,
  database,
  trustedOrigins: [
    origin,
    `http://localhost:${base.port}`,
    `http://127.0.0.1:${base.port}`,
    `http://[::1]:${base.port}`,
    "http://127.0.0.1:5173",
  ],
  emailAndPassword: {
    enabled: true,
    disableSignUp: true,
    minPasswordLength: 12,
    maxPasswordLength: 128,
    password: {
      hash: async (password) =>
        Bun.password.hash(password, {
          algorithm: "argon2id",
          memoryCost: 19456,
          timeCost: 2,
        }),
      verify: async ({ hash, password }) => Bun.password.verify(password, hash),
    },
  },
  plugins: [
    username({
      minUsernameLength: 3,
      maxUsernameLength: 64,
      immutableUsername: true,
      usernameValidator: (value) => /^[a-zA-Z0-9._-]{3,64}$/.test(value),
    }),
  ],
  session: {
    expiresIn: 8 * 3600,
    disableSessionRefresh: true,
    cookieCache: { enabled: false },
  },
  rateLimit: {
    enabled: true,
    window: 60,
    max: 100,
    customRules: { "/sign-in/username": { window: 60, max: 60 } },
  },
  advanced: {
    cookiePrefix: secrets.cookie_prefix,
    useSecureCookies: false,
    defaultCookieAttributes: { httpOnly: true, sameSite: "strict", path: "/" },
  },
  logger: { level: "error" },
} satisfies BetterAuthOptions;
const migrations = await getMigrations(options);
await migrations.runMigrations();
export const auth = betterAuth(options);
const context = await auth.$context;
// Preserve the preview's restart-revokes-all-sessions behavior, including after
// restoring an archive. Auth service exit also stops its Rust supervisor.
database.exec('DELETE FROM "session"');
const internal = context.internalAdapter;
const validName = (value: unknown): value is string =>
  typeof value === "string" && /^[a-z0-9._-]{3,64}$/.test(value);
const publicPaths = new Set([
  "sign-in/username",
  "sign-out",
  "get-session",
  "change-password",
  "list-sessions",
  "revoke-session",
  "revoke-sessions",
  "revoke-other-sessions",
]);
let pendingHashes = 0;
const response = (value: unknown, status = 200) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });
function privateCaller(request: Request) {
  const input = Buffer.from(request.headers.get("x-mcr-internal") ?? "");
  const expected = Buffer.from(secrets.internal_secret);
  return input.length === expected.length && timingSafeEqual(input, expected);
}
async function session(cookie: string) {
  const value = await auth.api.getSession({
    headers: new Headers({ cookie }),
    query: { disableCookieCache: true },
  });
  return value
    ? {
        user_id: value.user.id,
        username: value.user.username,
        session_id: value.session.id,
        expires_at: Math.floor(
          new Date(value.session.expiresAt).getTime() / 1000,
        ),
      }
    : null;
}
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  maxRequestBodySize: 64 * 1024,
  async fetch(request) {
    if (!privateCaller(request))
      return response({ error: "Private auth service" }, 403);
    const url = new URL(request.url);
    try {
      if (url.pathname === "/internal/session" && request.method === "POST") {
        const body = await request.json();
        return response(
          await session(typeof body.cookie === "string" ? body.cookie : ""),
        );
      }
      if (url.pathname === "/internal/identity" && request.method === "POST") {
        if (pendingHashes >= 2) return response({ error: "Busy" }, 503);
        pendingHashes++;
        try {
          const body = await request.json();
          if (!validName(body.username))
            return response({ error: "Invalid username" }, 400);
          if (
            body.password != null &&
            (typeof body.password !== "string" ||
              Buffer.byteLength(body.password) < 12 ||
              Buffer.byteLength(body.password) > 128)
          )
            return response({ error: "Invalid password length" }, 400);
          const email = body.username + "@dashboard.invalid";
          let existing = await internal.findUserByEmail(email, {
            includeAccounts: true,
          });
          if (body.expected_id && existing?.user.id !== body.expected_id)
            return response({ error: "Identity mismatch" }, 409);
          if (!existing) {
            if (!body.password && !body.password_hash)
              return response({ error: "Password required" }, 400);
            const hash = body.password
              ? await context.password.hash(body.password)
              : body.password_hash;
            if (typeof hash !== "string" || !hash.startsWith("$argon2id$"))
              return response({ error: "Unsupported password hash" }, 400);
            const user = await internal.createUser(
              {
                email,
                name: body.username,
                username: body.username,
                emailVerified: false,
              },
              { method: "email-password" },
            );
            try {
              await internal.createAccount({
                userId: user.id,
                accountId: user.id,
                providerId: "credential",
                password: hash,
              });
            } catch (error) {
              await internal.deleteUser(user.id);
              throw error;
            }
            existing = await internal.findUserByEmail(email, {
              includeAccounts: true,
            });
          } else if (body.password) {
            await internal.updatePassword(
              existing.user.id,
              await context.password.hash(body.password),
            );
            await internal.deleteUserSessions(existing.user.id);
          }
          if (!existing)
            return response({ error: "Identity creation failed" }, 500);
          if (
            !existing.accounts.some(
              (account) =>
                account.providerId === "credential" && account.password,
            )
          )
            return response({ error: "Credential account is missing" }, 409);
          return response({ user_id: existing.user.id });
        } finally {
          pendingHashes--;
        }
      }
      if (
        url.pathname === "/internal/revoke-user" &&
        request.method === "POST"
      ) {
        const body = await request.json();
        if (typeof body.user_id !== "string") return response({}, 400);
        await internal.deleteUserSessions(body.user_id);
        return response({ success: true });
      }
      if (
        url.pathname === "/internal/delete-user" &&
        request.method === "POST"
      ) {
        const body = await request.json();
        if (typeof body.user_id !== "string") return response({}, 400);
        await internal.deleteUserSessions(body.user_id);
        await internal.deleteUser(body.user_id);
        return response({ success: true });
      }
      if (url.pathname === "/internal/shutdown" && request.method === "POST") {
        setTimeout(() => {
          server.stop(true);
          database.close();
          process.exit(0);
        }, 25);
        return response({ success: true });
      }
      const path = url.pathname.replace(/^\/api\/auth\//, "");
      if (!url.pathname.startsWith("/api/auth/") || !publicPaths.has(path))
        return response({}, 404);
      return await auth.handler(request);
    } catch {
      return response({ error: "Authentication operation failed" }, 400);
    }
  },
});
console.log("MCR_AUTH_READY=" + server.port);
process.on("SIGTERM", () => {
  server.stop(true);
  database.close();
  process.exit(0);
});
