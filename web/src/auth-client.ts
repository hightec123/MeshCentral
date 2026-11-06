import { createAuthClient } from "better-auth/react";
import { twoFactorClient, usernameClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";

export const authClient = createAuthClient({
  plugins: [usernameClient(), twoFactorClient(), passkeyClient()],
});

export function passkeysAvailable() {
  const { hostname, protocol } = window.location;
  return (
    window.isSecureContext &&
    "PublicKeyCredential" in window &&
    (hostname === "localhost" ||
      (protocol === "https:" &&
        !hostname.includes(":") &&
        /[a-z]/i.test(hostname)))
  );
}

export function localhostPasskeyUrl() {
  const url = new URL(window.location.origin);
  if (
    url.protocol !== "http:" ||
    !["127.0.0.1", "[::1]"].includes(url.hostname)
  )
    return null;
  url.hostname = "localhost";
  return url.href;
}
