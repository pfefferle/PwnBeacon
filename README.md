# PwnBeacon

A BLE (Bluetooth Low Energy) adaptation of the [PwnGrid](https://pwnagrid.ai) protocol used by [Pwnagotchi](https://pwnagotchi.ai) devices.

The original PwnGrid protocol uses 802.11 WiFi beacon frames to broadcast JSON-encoded identity and status data. PwnBeacon reimplements this over BLE, enabling peer discovery and data exchange on devices that lack raw WiFi frame injection or where WiFi is unavailable.

## Protocol Overview

PwnBeacon operates in two layers:

### 1. Advertising (Discovery)

Each device continuously broadcasts a BLE advertisement containing a compact binary payload under a custom 128-bit service UUID. This allows passive peer detection without establishing a connection.

**Advertisement payload (max 21 bytes):**

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Protocol version (`0x01`) |
| 1 | 1 | Flags (bit 0: advertise, bit 1: connectable) |
| 2 | 2 | `pwnd_run` (uint16, little-endian) |
| 4 | 2 | `pwnd_tot` (uint16, little-endian) |
| 6 | 6 | Identity fingerprint (first 6 bytes of SHA-256) |
| 12 | 1 | Name length (N, max 8) |
| 13 | N | Name (UTF-8, truncated to 8 bytes) |

**Service UUID:** `b34c0000-0000-0000-1337-000000000001`

### 2. GATT Service (Full Data Exchange)

When a scanner discovers a peer, it can optionally connect to read the full PwnGrid-compatible identity via GATT characteristics.

| Characteristic | UUID | Properties | Description |
|----------------|------|------------|-------------|
| Identity | `b34c0000-0000-0000-1337-000000000002` | Read | Full JSON payload |
| Face | `b34c0000-0000-0000-1337-000000000003` | Read, Notify | Current face/mood string |
| Name | `b34c0000-0000-0000-1337-000000000004` | Read | Device name |
| Signal | `b34c0000-0000-0000-1337-000000000005` | Write | Ping/poke another unit |
| Message | `b34c0000-0000-0000-1337-000000000006` | Read, Write, Notify | Text messages between peers |

UUIDs are hand-crafted hex leetspeak: **"b34c0n 1337"**.

### JSON Payload (Identity Characteristic)

The JSON format is compatible with the original WiFi PwnGrid protocol:

```json
{
  "pal": true,
  "name": "PwnBeacon",
  "face": "(◕‿‿◕)",
  "epoch": 1,
  "grid_version": "2.0.0-ble",
  "identity": "32e9f315e92d...",
  "pwnd_run": 5,
  "pwnd_tot": 163,
  "session_id": "a2:00:64:e6:0b:8b",
  "timestamp": 1683387465,
  "uptime": 264,
  "version": "1.8.4"
}
```

## Files

| File | Description |
|------|-------------|
| `pwnbeacon.h` | Header — types, constants, UUIDs, public API |
| `pwnbeacon.cpp` | Implementation — BLE advertising, scanning, GATT server |
| `PwnBeacon.ino` | Arduino sketch — main loop with mood cycling and peer discovery |

## Compatibility

- JSON payload is backwards-compatible with WiFi PwnGrid
- Devices can run both WiFi PwnGrid and PwnBeacon simultaneously
- Works on ESP32 (dual WiFi+BLE), nRF52, M5Stack, and other BLE-capable MCUs

## Building

```bash
# PlatformIO
pio run

# Arduino IDE — open PwnBeacon.ino
```

## Hardware

- ESP32 (generic)
- M5Stack AtomS3
- M5StickC Plus

## License

MIT
