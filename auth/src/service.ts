// Private, Rust-supervised Better Auth service. The public proxy exposes only
// dashboard authentication endpoints; device permissions remain in Rust.
import { Database } from "bun:sqlite";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { twoFactor, username } from "better-auth/plugins";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { getMigrations } from "better-auth/db/migration";
import { passkey } from "@better-auth/passkey";
import { chmodSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";

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
const secureConsole = base.protocol === "https:";
if (
  !secureConsole &&
  (base.protocol !== "http:" ||
    !["127.0.0.1", "localhost", "[::1]"].includes(base.hostname))
)
  throw new Error("An HTTP console must use loopback.");
const passkeyOrigin = secureConsole
  ? isIP(base.hostname.replace(/^\[|\]$/g, ""))
    ? null
    : origin
  : `http://localhost${base.port ? ":" + base.port : ""}`;
const passkeyCookie = "webauthn_challenge";
const registrationPasswordHeader = "x-mcr-passkey-password";
const options = {
  appName: "MeshCentral Rust",
  baseURL: origin,
  basePath: "/api/auth",
  secret: secrets.secret,
  database,
  trustedOrigins: secureConsole
    ? [origin]
    : [
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
    twoFactor({ twoFactorCookieMaxAge: 300 }),
    passkey({
      rpID: passkeyOrigin ? new URL(passkeyOrigin).hostname : "localhost",
      origin: passkeyOrigin,
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      advanced: { webAuthnChallengeCookie: passkeyCookie },
      registration: {
        requireSession: true,
        async afterVerification({ ctx, user }) {
          const encoded = ctx.headers?.get(registrationPasswordHeader);
          const credential =
            await ctx.context.internalAdapter.findCredentialAccount(user.id);
          if (
            !encoded ||
            !credential?.password ||
            !(await ctx.context.password.verify({
              hash: credential.password,
              password: Buffer.from(encoded, "base64").toString("utf8"),
            }))
          )
            throw new APIError("UNAUTHORIZED", {
              message: "Current password is incorrect.",
            });
        },
      },
    }),
  ],
  hooks: {
    before: createAuthMiddleware(async (ctx) => {
      if (
        ctx.path === "/two-factor/verify-totp" ||
        ctx.path === "/two-factor/verify-backup-code"
      ) {
        // Require a factor at every sign-in, including for direct API callers.
        return { context: { body: { ...ctx.body, trustDevice: false } } };
      }
      if (ctx.path === "/sign-out") {
        const cookie = ctx.context.createAuthCookie(passkeyCookie);
        const challenge = await ctx.getSignedCookie(
          cookie.name,
          ctx.context.secret,
        );
        if (challenge) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            challenge,
          );
          ctx.setCookie(cookie.name, "", { ...cookie.attributes, maxAge: 0 });
        }
      }
      if (
        ctx.path === "/sign-out" ||
        ctx.path === "/sign-in/username" ||
        ctx.path === "/passkey/verify-authentication"
      ) {
        const cookie = ctx.context.createAuthCookie("two_factor");
        const challenge = await ctx.getSignedCookie(
          cookie.name,
          ctx.context.secret,
        );
        if (challenge) {
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            challenge,
          );
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(
            `2fa-attempts-${challenge}`,
          );
          ctx.setCookie(cookie.name, "", { ...cookie.attributes, maxAge: 0 });
        }
      }
    }),
  },
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
    useSecureCookies: secureConsole,
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
const deleteChallenges = `DELETE FROM "verification"
  WHERE "identifier" GLOB '2fa-*' AND "value" = ?`;
// Better Auth sets the flag after verifying the enrollment code. Commit it
// together with the factor and revocations so a crash cannot strand enrollment.
database.exec(`
  DELETE FROM "session";
  DELETE FROM "verification" WHERE "identifier" GLOB '2fa-*';
  DELETE FROM "verification"
    WHERE CASE WHEN json_valid("value")
      THEN json_extract("value", '$.type') IN ('registration', 'authentication')
      ELSE 0 END;
  CREATE UNIQUE INDEX IF NOT EXISTS "mcr_passkey_credential" ON "passkey" ("credentialID");
  CREATE TRIGGER IF NOT EXISTS "mcr_revoke_on_passkey_removal"
  AFTER DELETE ON "passkey"
  BEGIN
    DELETE FROM "session" WHERE "userId" = OLD."userId";
  END;
  CREATE TRIGGER IF NOT EXISTS "mcr_revoke_on_mfa_change"
  AFTER UPDATE OF "twoFactorEnabled" ON "user"
  WHEN coalesce(OLD."twoFactorEnabled", 0) <> coalesce(NEW."twoFactorEnabled", 0)
  BEGIN
    UPDATE "twoFactor" SET "verified" = 1
      WHERE "userId" = NEW."id" AND NEW."twoFactorEnabled" = 1;
    DELETE FROM "twoFactor"
      WHERE "userId" = NEW."id" AND NEW."twoFactorEnabled" = 0;
    DELETE FROM "session" WHERE "userId" = NEW."id";
    ${deleteChallenges.replace("?", 'NEW."id"')};
  END;
  CREATE TRIGGER IF NOT EXISTS "mcr_clear_mfa_on_password_change"
  AFTER UPDATE OF "password" ON "account"
  WHEN OLD."password" IS NOT NEW."password"
  BEGIN
    ${deleteChallenges.replace("?", 'NEW."userId"')};
  END;
`);
const clearChallenges = database.query(deleteChallenges);
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
  "two-factor/enable",
  "two-factor/disable",
  "two-factor/verify-totp",
  "two-factor/verify-backup-code",
  "two-factor/generate-backup-codes",
  "passkey/generate-register-options",
  "passkey/verify-registration",
  "passkey/generate-authenticate-options",
  "passkey/verify-authentication",
  "passkey/list-user-passkeys",
  "passkey/delete-passkey",
]);
let authWrites = Promise.resolve();
let pendingWrites = 0;
async function authWrite(work: () => Promise<Response>) {
  // Username sign-in reads the user before verifying the password. Serialize
  // writes so it cannot issue a session using a superseded MFA or password state.
  if (pendingWrites >= 16) return response({ error: "Busy" }, 503);
  pendingWrites++;
  const result = authWrites.then(work);
  authWrites = result.then(
    () => {},
    () => {},
  );
  try {
    return await result;
  } finally {
    pendingWrites--;
  }
}
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
        return await authWrite(async () => {
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
        });
      }
      if (
        url.pathname === "/internal/revoke-user" &&
        request.method === "POST"
      ) {
        const body = await request.json();
        if (typeof body.user_id !== "string") return response({}, 400);
        return await authWrite(async () => {
          clearChallenges.run(body.user_id);
          await internal.deleteUserSessions(body.user_id);
          return response({ success: true });
        });
      }
      if (
        url.pathname === "/internal/delete-user" &&
        request.method === "POST"
      ) {
        const body = await request.json();
        if (typeof body.user_id !== "string") return response({}, 400);
        return await authWrite(async () => {
          clearChallenges.run(body.user_id);
          await internal.deleteUserSessions(body.user_id);
          await internal.deleteUser(body.user_id);
          return response({ success: true });
        });
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
      if (path.startsWith("passkey/")) {
        if (
          !passkeyOrigin ||
          request.headers.get("host") !== new URL(passkeyOrigin).host
        )
          return response(
            { error: "Passkeys require the configured console hostname." },
            403,
          );
        const suppliedOrigin = request.headers.get("origin");
        if (
          (request.method === "POST" || suppliedOrigin) &&
          suppliedOrigin !== passkeyOrigin
        )
          return response({ error: "Incorrect passkey origin." }, 403);
      }
      const handle = async () => {
        let input = request;
        if (
          path === "passkey/verify-registration" &&
          request.method === "POST"
        ) {
          const {
            password,
            name,
            response: attestation,
          } = await request.json();
          if (
            typeof password !== "string" ||
            password.length > 128 ||
            !password
          )
            return response({ error: "Current password is required." }, 400);
          if (typeof name !== "string" || !name.trim() || name.length > 64)
            return response(
              { error: "Enter a name of up to 64 characters." },
              400,
            );
          // Keep the password in the incoming JSON and only attach it to the
          // private in-process request for the verified registration hook.
          const headers = new Headers(request.headers);
          headers.delete("content-length");
          headers.set(
            registrationPasswordHeader,
            Buffer.from(password).toString("base64"),
          );
          input = new Request(request.url, {
            method: "POST",
            headers,
            body: JSON.stringify({ name: name.trim(), response: attestation }),
          });
        }
        const result = await auth.handler(input);
        result.headers.set("Cache-Control", "no-store");
        return result;
      };
      return await (request.method === "POST" ||
      path.startsWith("passkey/generate-")
        ? authWrite(handle)
        : handle());
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
