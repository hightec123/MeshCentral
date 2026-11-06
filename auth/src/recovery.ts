import type { Database } from "bun:sqlite";
import { createHash, randomBytes } from "node:crypto";
import { isIP } from "node:net";
import nodemailer from "nodemailer";

export function recoveryAddress(value: unknown) {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return email.length <= 254 &&
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(
      email,
    ) &&
    !email.endsWith("@dashboard.invalid")
    ? email
    : null;
}

function transport() {
  const raw = process.env.MCR_SMTP_URL;
  const from = process.env.MCR_SMTP_FROM;
  if (!raw && !from) return null;
  try {
    const url = new URL(raw ?? "");
    const senderAddress = recoveryAddress(from);
    if (
      !senderAddress ||
      !["smtp:", "smtps:"].includes(url.protocol) ||
      !url.hostname ||
      url.search ||
      url.hash ||
      !["", "/"].includes(url.pathname) ||
      (url.password && !url.username) ||
      (url.port &&
        (!/^\d+$/.test(url.port) ||
          Number(url.port) < 1 ||
          Number(url.port) > 65535))
    )
      throw new Error();
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const loopback = ["127.0.0.1", "::1", "localhost"].includes(host);
    const secure = url.protocol === "smtps:";
    const sender = nodemailer.createTransport(
      {
        host,
        port: url.port ? Number(url.port) : secure ? 465 : 587,
        secure,
        requireTLS: !secure && (!loopback || Boolean(url.username)),
        ...(isIP(host) ? { tls: { servername: host } } : {}),
        ...(url.username
          ? {
              auth: {
                user: decodeURIComponent(url.username),
                pass: decodeURIComponent(url.password),
              },
            }
          : {}),
        connectionTimeout: 5000,
        greetingTimeout: 5000,
        socketTimeout: 10000,
        disableFileAccess: true,
        disableUrlAccess: true,
      },
      { from: senderAddress },
    );
    return sender;
  } catch {
    throw new Error(
      "Configure MCR_SMTP_URL and MCR_SMTP_FROM with a valid SMTP connection and sender address.",
    );
  }
}

const digest = (token: string) =>
  createHash("sha256").update(token).digest("hex");
const seconds = () => Math.floor(Date.now() / 1000);
const invalidateResets = `DELETE FROM "verification"
  WHERE "identifier" GLOB 'reset-password:*' AND "value" = ?`;

export function emailRecovery(database: Database, origin: string) {
  const smtp = transport();
  let sending = 0;
  function send(
    email: string,
    kind: "verify-recovery" | "reset-password",
    token: string,
  ) {
    if (!smtp || sending >= 8) return;
    const link = new URL("/", origin);
    link.hash = new URLSearchParams({ [kind]: token }).toString();
    const subject =
      kind === "verify-recovery"
        ? "Confirm your recovery email"
        : "Reset your password";
    sending++;
    void smtp
      .sendMail({
        to: email,
        subject: "MeshCentral · " + subject,
        text: `${subject} for your MeshCentral account.\n\n${link.href}\n\nIf you did not request this, you can ignore this message.\n`,
      })
      .catch(() => {
        console.error("MeshCentral recovery email delivery failed.");
      })
      .finally(() => {
        sending--;
      });
  }

  database.exec(`
    CREATE TABLE IF NOT EXISTS "mcr_recovery_email" (
      "user_id" TEXT PRIMARY KEY REFERENCES "user"("id") ON DELETE CASCADE,
      "email" TEXT NOT NULL UNIQUE,
      "last_reset" INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS "mcr_recovery_pending" (
      "user_id" TEXT PRIMARY KEY REFERENCES "user"("id") ON DELETE CASCADE,
      "email" TEXT NOT NULL,
      "token_hash" TEXT NOT NULL UNIQUE,
      "expires" INTEGER NOT NULL
    );
    DELETE FROM "mcr_recovery_pending";
    DELETE FROM "verification" WHERE "identifier" GLOB 'reset-password:*';
    CREATE TRIGGER IF NOT EXISTS "mcr_clear_email_tokens_on_password_change"
    AFTER UPDATE OF "password" ON "account"
    WHEN OLD."password" IS NOT NEW."password"
    BEGIN
      DELETE FROM "mcr_recovery_pending" WHERE "user_id" = NEW."userId";
      ${invalidateResets.replace("?", 'NEW."userId"')};
    END;
  `);
  const clearResets = database.query(invalidateResets);
  const clearPending = database.query(
    'DELETE FROM "mcr_recovery_pending" WHERE "user_id" = ?',
  );
  const addresses = database.query<{ email: string }, [string]>(
    'SELECT "email" FROM "mcr_recovery_email" WHERE "user_id" = ?',
  );
  const resetIdentity = database.query<{ username: string }, [string]>(`
    SELECT u."username" FROM "verification" v JOIN "user" u ON v."value" = u."id"
    WHERE v."identifier" = ?
  `);
  return {
    enabled: Boolean(smtp),
    address: (userId: string) => addresses.get(userId)?.email ?? null,
    usernameForReset: (token: string) =>
      resetIdentity.get("reset-password:" + token)?.username,
    resetUser(email: string) {
      return database
        .query<{ user_id: string }, [string, number]>(
          `
        SELECT "user_id" FROM "mcr_recovery_email" WHERE "email" = ? AND "last_reset" <= ?
      `,
        )
        .get(email, seconds() - 60)?.user_id;
    },
    sendReset(userId: string, token: string) {
      const recipient = addresses.get(userId)?.email;
      if (!recipient) return;
      database
        .query(
          'UPDATE "mcr_recovery_email" SET "last_reset" = ? WHERE "user_id" = ?',
        )
        .run(seconds(), userId);
      send(recipient, "reset-password", token);
    },
    requestConfirmation(userId: string, email: string) {
      const token = randomBytes(32).toString("base64url");
      database
        .query(
          `
        INSERT INTO "mcr_recovery_pending" ("user_id", "email", "token_hash", "expires")
        VALUES (?, ?, ?, ?) ON CONFLICT ("user_id") DO UPDATE SET
          "email" = excluded."email", "token_hash" = excluded."token_hash", "expires" = excluded."expires"
      `,
        )
        .run(userId, email, digest(token), seconds() + 1800);
      send(email, "verify-recovery", token);
    },
    confirm: database.transaction((token: string) => {
      const pending = database
        .query<{ user_id: string; email: string }, [string, number]>(
          `
        SELECT "user_id", "email" FROM "mcr_recovery_pending" WHERE "token_hash" = ? AND "expires" > ?
      `,
        )
        .get(digest(token), seconds());
      if (!pending) return false;
      const { user_id, email } = pending;
      const updated = database
        .query(
          `
        INSERT INTO "mcr_recovery_email" ("user_id", "email")
        SELECT ?, ? WHERE NOT EXISTS (
          SELECT 1 FROM "mcr_recovery_email" WHERE "email" = ? AND "user_id" <> ?
        )
        ON CONFLICT ("user_id") DO UPDATE SET "email" = excluded."email", "last_reset" = 0
      `,
        )
        .run(user_id, email, email, user_id);
      clearPending.run(user_id);
      if (!updated.changes) return false;
      clearResets.run(user_id);
      return true;
    }),
    remove: database.transaction((userId: string) => {
      database
        .query('DELETE FROM "mcr_recovery_email" WHERE "user_id" = ?')
        .run(userId);
      clearPending.run(userId);
      clearResets.run(userId);
    }),
  };
}
