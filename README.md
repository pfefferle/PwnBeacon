# PwnBeacon

```
 ███████████                             ███████████                                                 
░░███░░░░░███                           ░░███░░░░░███     ( o_O)                             
 ░███    ░███ █████ ███ █████ ████████   ░███    ░███  ██████   ██████    ██████   ██████  ████████ 
 ░██████████ ░░███ ░███░░███ ░░███░░███  ░██████████  ███░░███ ░░░░░███  ███░░███ ███░░███░░███░░███ 
 ░███░░░░░░   ░███ ░███ ░███  ░███ ░███  ░███░░░░░███░███████   ███████ ░███ ░░░ ░███ ░███ ░███ ░███ 
 ░███         ░░███████████   ░███ ░███  ░███    ░███░███░░░   ███░░███ ░███  ███░███ ░███ ░███ ░███ 
 █████         ░░████░████    ████ █████ ███████████ ░░██████ ░░████████░░██████ ░░██████  ████ █████
░░░░░           ░░░░ ░░░░    ░░░░ ░░░░░ ░░░░░░░░░░░   ░░░░░░   ░░░░░░░░  ░░░░░░   ░░░░░░  ░░░░ ░░░░░ 
```

A BLE (Bluetooth Low Energy) peer discovery protocol inspired by [PwnGrid](https://pwnagotchi.ai). PwnBeacon lets devices find and identify each other over Bluetooth, using a compact binary advertisement format that fits within BLE's strict payload limits.

Built for the [Pwnagotchi](https://pwnagotchi.ai) ecosystem. Used in production by [Palnagotchi](https://github.com/pfefferle/palnagotchi).

## Why BLE?

WiFi PwnGrid requires raw 802.11 frame injection (monitor mode), which limits it to specific chipsets (ESP32, certain Linux drivers). PwnBeacon works on any BLE-capable device and can run alongside WiFi PwnGrid on dual-radio chips like the ESP32, doubling the chances of finding peers.

## Protocol

PwnBeacon operates in two layers:

### Layer 1: Advertising (Passive Discovery)

Each device broadcasts a BLE advertisement containing a compact binary payload as service data under a custom 128-bit UUID. Peers are discovered passively by scanning, no connection required.

**Service UUID:** `b34c0000-0000-0000-1337-000000000001`

**Advertisement payload (variable length, max 21 bytes):**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `version` | Protocol version (`0x01`) |
| 1 | 1 | `flags` | Bit 0: advertising, Bit 1: GATT connectable |
| 2 | 2 | `pwnd_run` | Peers found this session (uint16 LE) |
| 4 | 2 | `pwnd_tot` | Peers found total (uint16 LE) |
| 6 | 6 | `fingerprint` | First 6 bytes of SHA-256(identity) |
| 12 | 1 | `name_len` | Name length N (max 8) |
| 13 | N | `name` | Device name (UTF-8, truncated) |

The fingerprint is used for deduplication (instead of BLE MAC, which may rotate). The payload is variable-length to maximize the name bytes within BLE's 31-byte scan response limit (128-bit UUID overhead = 18 bytes, leaving ~13 for data).

### Layer 2: GATT Service (Full Data Exchange)

Peers can optionally connect to read the full PwnGrid-compatible identity via GATT characteristics:

| Characteristic | UUID | Properties | Description |
|----------------|------|------------|-------------|
| Identity | `...0002` | Read | Full JSON payload |
| Face | `...0003` | Read, Notify | Current face/mood |
| Name | `...0004` | Read | Device name |
| Signal | `...0005` | Write | Ping/poke |
| Message | `...0006` | Read, Write, Notify | Text messages |

All UUIDs follow the pattern `b34c0000-0000-0000-1337-0000000000XX` (hex leetspeak: "b34c0n 1337").

### Identity JSON

The GATT Identity characteristic (`...0002`) returns a JSON payload compatible with WiFi PwnGrid. This is the canonical data model — the peer struct mirrors these fields.

```json
{
  "pal": true,
  "name": "PwnBeacon",
  "face": "(O__O)",
  "epoch": 1,
  "grid_version": "2.0.0-ble",
  "identity": "32e9f315e92d974342c93d0fd952a914bfb4e6838953536ea6f63d54db6b9610",
  "pwnd_run": 5,
  "pwnd_tot": 163,
  "session_id": "a2:00:64:e6:0b:8b",
  "timestamp": 1683387465,
  "uptime": 264,
  "version": "1.8.4"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `pal` | bool | Always `true` — identifies PwnGrid-compatible devices |
| `name` | string | Device name (max 8 bytes in advertisement, full in JSON) |
| `face` | string | Current mood face, e.g. `"(O__O)"` |
| `epoch` | int | Training epoch counter |
| `grid_version` | string | PwnGrid protocol version (`"2.0.0-ble"` for PwnBeacon) |
| `identity` | string | 64-char hex public key / identity hash |
| `pwnd_run` | uint16 | Networks/peers pwned this session |
| `pwnd_tot` | uint16 | Networks/peers pwned total (all time) |
| `session_id` | string | BLE address or random session identifier |
| `timestamp` | int | Current time in seconds since boot |
| `uptime` | int | Uptime in seconds |
| `version` | string | Firmware version |

### Data Availability by Layer

| Field | Layer 1 (Advertising) | Layer 2 (GATT) |
|-------|----------------------|----------------|
| `name` | Truncated to 8 bytes | Full |
| `face` | - | Face characteristic |
| `identity` | First 6 bytes as fingerprint | Full 64-char hex |
| `pwnd_run` | uint16 | JSON |
| `pwnd_tot` | uint16 | JSON |
| `epoch`, `grid_version`, `session_id`, `timestamp`, `uptime`, `version` | - | JSON |

## Usage

```cpp
#include "pwnbeacon.h"

void setup() {
  pwnbeaconInit("MyDevice", "your-identity-hex-string");
  pwnbeaconSetFace("(O__O)");
  pwnbeaconAdvertise();
}

void loop() {
  // Non-blocking scan (returns immediately, callback handles results)
  if (!pwnbeaconIsScanning()) {
    pwnbeaconScan(3000);
  }

  // Periodically re-advertise to update payload
  pwnbeaconAdvertise();

  // Mark peers as gone after 2 minutes of silence
  pwnbeaconCheckGonePeers();

  // Access peer data
  uint8_t count = pwnbeaconGetPeerCount();
  pwnbeacon_peer_t* peers = pwnbeaconGetPeers();
}
```

### API

| Function | Description |
|----------|-------------|
| `pwnbeaconInit(name, identity)` | Initialize BLE, GATT server, and advertising |
| `pwnbeaconAdvertise()` | Start/update BLE advertisement |
| `pwnbeaconScan(ms)` | Start non-blocking BLE scan |
| `pwnbeaconIsScanning()` | Check if scan is in progress |
| `pwnbeaconCheckGonePeers()` | Mark peers not seen for 2 min as gone |
| `pwnbeaconSetFace(face)` | Update mood face (also notifies GATT subscribers) |
| `pwnbeaconSetPwnd(run, tot)` | Update pwned counters |
| `pwnbeaconGetPeers()` | Get peer array |
| `pwnbeaconGetPeerCount()` | Get number of discovered peers |
| `pwnbeaconGetLastFriendName()` | Name of the most recently discovered peer |
| `pwnbeaconGetClosestRssi()` | RSSI of the closest non-gone peer |
| `pwnbeaconSetMessageCallback(cb)` | Register callback for incoming messages |
| `pwnbeaconSendMessage(msg)` | Broadcast a text message via GATT notify |
| `pwnbeaconBuildIdentityJson()` | Get the full PwnGrid-compatible JSON string |

## WiFi + BLE Coexistence

On ESP32, WiFi and BLE share the same 2.4 GHz radio. To run both PwnGrid (WiFi) and PwnBeacon (BLE) on the same device, alternate between them:

```cpp
// WiFi phase: sniff + advertise on channels 1-11
if (wifi_phase) {
  pwngridTick(...);
}
// BLE phase: advertise + scan for ~3 seconds
else {
  pwnbeaconTick(...);
}
```

See [Palnagotchi](https://github.com/pfefferle/palnagotchi) for a complete implementation of WiFi/BLE time-sharing.

## Building

Requires [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) (lighter and faster than the default ESP32 BLE library).

```ini
# platformio.ini
[env:esp32]
platform = espressif32
framework = arduino
lib_deps =
  h2zero/NimBLE-Arduino
  bblanchon/ArduinoJson
```

Or open `PwnBeacon.ino` in Arduino IDE with the NimBLE and ArduinoJson libraries installed.

## Hardware

Tested on:

- ESP32 (generic devkit)
- M5Stack AtomS3 / AtomS3 Lite
- M5StickC Plus / Plus2
- M5Cardputer
- M5Stack Core

Should work on any ESP32-based board with BLE support.

## Compatibility

- **Pwnagotchi / PwnGrid**: JSON payload is backwards-compatible
- **Palnagotchi**: Uses PwnBeacon for BLE peer discovery alongside WiFi PwnGrid
- **Minigotchi**: Compatible face format for small displays
- Devices can run WiFi PwnGrid and PwnBeacon simultaneously on ESP32

## Files

| File | Description |
|------|-------------|
| `pwnbeacon.h` | Header: types, constants, UUIDs, public API |
| `pwnbeacon.cpp` | Implementation: NimBLE advertising, scanning, GATT server |
| `PwnBeacon.ino` | Example sketch with mood cycling and peer discovery |

## License

MIT
