# Console design

The console is for administrators finding a device and checking whether it can be
managed. Its primary surface is the device inventory, not a marketing dashboard.

- Palette: navy navigation `#172744`, paper workspace `#F6F8FC`, white surface
  `#FFFFFF`, blue action `#315CE8`, slate text `#24344D`, green presence `#22815D`.
- Typography: locally available Avenir Next for interface copy, with Segoe UI and
  system sans-serif fallbacks. Headings use the same family with deliberate weight
  and size changes; no remote font requests.
- Layout: left-aligned narrow navigation, a quiet page header, and one wide device
  table. On small screens, navigation becomes a compact header and table content
  scrolls within its own container.
- Distinctive element: the empty inventory uses a small topology illustration
  showing the relationship between the console and devices. No fabricated devices,
  decorative metric cards, or controls for unimplemented remote actions.

```text
+----------------+---------------------------------------------+
| MeshCentral    | Workspace / Devices                         |
|                | Devices                        Refresh      |
| Devices        | Presence summary                            |
|                | Search devices       Status      Platform   |
|                |---------------------------------------------|
|                | Device table / honest empty state            |
| Server status  |                                             |
+----------------+---------------------------------------------+
```

Review against the brief: a generic SaaS dashboard would introduce metric cards
and sample activity. Here, a single inventory surface and real connection status
take priority. Sign-in protects the workspace. Administrators manage People,
Groups, and Activity; operators manage their assigned groups; viewers see inventory
without remote controls. Group configuration requires an administrator and explicit
node fingerprint approval. The device dialog exposes Overview, Terminal, Files,
and Desktop with connection status and explicit connect/disconnect controls.
Desktop starts in view mode; input requires an explicit control checkbox.
Search, filters, refresh, error recovery, and the capability explanation must work
with keyboard input. Preserve visible focus and reduced-motion preferences.
