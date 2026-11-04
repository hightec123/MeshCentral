import { z } from "zod";

export const serverSchema = z.object({
  name: z.string(),
  version: z.string(),
  api_version: z.literal(1),
  uptime_seconds: z.number().nonnegative(),
  capabilities: z.object({
    agent_enrollment: z.boolean(),
    remote_desktop: z.boolean(),
    terminal: z.boolean(),
    file_transfer: z.boolean(),
  }),
});

const deviceSchema = z.object({
  id: z.string(),
  name: z.string(),
  group: z.string(),
  platform: z.string(),
  status: z.enum(["online", "offline"]),
  last_seen: z.iso.datetime().nullable(),
  group_id: z.string().default(""),
  node_id_hex: z.string().default(""),
  hostname: z.string().default(""),
  alias: z.string().nullable().default(null),
  notes: z.string().default(""),
  tags: z.array(z.string()).default([]),
  core_ready: z.boolean().default(false),
  details: z.record(z.string(), z.unknown()).nullable().default({}),
});

const inventorySchema = z.object({ devices: z.array(deviceSchema) });
export type ServerInfo = z.infer<typeof serverSchema>;
export type Device = z.infer<typeof deviceSchema>;

export type Snapshot = {
  server: ServerInfo;
  devices: Device[];
  fetchedAt: Date;
};

export class ConsoleApiError extends Error {}

async function readJson(path: string, signal: AbortSignal): Promise<unknown> {
  const response = await fetch(path, {
    signal,
    credentials: "same-origin",
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (response.status === 401) window.dispatchEvent(new Event("mcr-signout"));
  if (!response.ok)
    throw new ConsoleApiError(
      `The server returned ${response.status}. Retry the connection.`,
    );
  try {
    return await response.json();
  } catch {
    throw new ConsoleApiError(
      "The server sent an unreadable response. Retry the connection.",
    );
  }
}

export async function fetchSnapshot(signal: AbortSignal): Promise<Snapshot> {
  const [server, inventory] = await Promise.all([
    readJson("/api/v1/server", signal),
    readJson("/api/v1/devices", signal),
  ]);
  const parsedServer = serverSchema.safeParse(server);
  const parsedInventory = inventorySchema.safeParse(inventory);
  if (!parsedServer.success || !parsedInventory.success) {
    throw new ConsoleApiError(
      "The server sent unexpected device information. Retry the connection.",
    );
  }
  return {
    server: parsedServer.data,
    devices: parsedInventory.data.devices,
    fetchedAt: new Date(),
  };
}
