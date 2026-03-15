#pragma once

#include "Arduino.h"

// --- PwnBeacon Service UUIDs ---
// Hand-crafted hex leetspeak: "b34c0n 1337"
#define PWNBEACON_SERVICE_UUID        "b34c0000-0000-0000-1337-000000000001"
#define PWNBEACON_IDENTITY_CHAR_UUID  "b34c0000-0000-0000-1337-000000000002"
#define PWNBEACON_FACE_CHAR_UUID      "b34c0000-0000-0000-1337-000000000003"
#define PWNBEACON_NAME_CHAR_UUID      "b34c0000-0000-0000-1337-000000000004"
#define PWNBEACON_SIGNAL_CHAR_UUID    "b34c0000-0000-0000-1337-000000000005"
#define PWNBEACON_MESSAGE_CHAR_UUID   "b34c0000-0000-0000-1337-000000000006"

// --- Protocol constants ---
#define PWNBEACON_PROTOCOL_VERSION  0x01
#define PWNBEACON_ADV_MAX_NAME_LEN  8
#define PWNBEACON_FINGERPRINT_LEN   6
#define PWNBEACON_MAX_PEERS         32
#define PWNBEACON_PEER_TIMEOUT_MS   120000  // 2 minutes

// --- Advertisement flags ---
#define PWNBEACON_FLAG_ADVERTISE    0x01
#define PWNBEACON_FLAG_CONNECTABLE  0x02

// --- Advertisement packet (compact binary, max 21 bytes) ---
//
// Designed to fit within a BLE scan response alongside a 128-bit
// service UUID (18 bytes overhead), leaving ~13 bytes for data.
// Variable-length: fixed header (13 bytes) + name (0-8 bytes).
//
typedef struct __attribute__((packed)) {
  uint8_t  version;                                // Protocol version (0x01)
  uint8_t  flags;                                  // Bitfield flags
  uint16_t pwnd_run;                               // Pwned this session (LE)
  uint16_t pwnd_tot;                               // Pwned total (LE)
  uint8_t  fingerprint[PWNBEACON_FINGERPRINT_LEN]; // First 6 bytes of identity SHA-256
  uint8_t  name_len;                               // Name length (max 8)
  char     name[PWNBEACON_ADV_MAX_NAME_LEN];       // Name (UTF-8, truncated)
} pwnbeacon_adv_t;

// --- Peer data ---
//
// Mirrors the Identity JSON fields defined in the protocol spec.
// Advertising populates: name, pwnd_run, pwnd_tot, fingerprint, rssi.
// GATT connection populates the remaining fields and sets full_data = true.
//
typedef struct {
  String    name;
  String    face;
  String    identity;
  String    grid_version;
  String    session_id;
  String    version;
  int       epoch;
  uint16_t  pwnd_run;
  uint16_t  pwnd_tot;
  int       timestamp;
  int       uptime;
  int8_t    rssi;
  uint32_t  last_seen;
  bool      gone;
  bool      full_data;
  uint8_t   fingerprint[PWNBEACON_FINGERPRINT_LEN];
} pwnbeacon_peer_t;

// --- Message callback type ---
typedef void (*pwnbeacon_message_cb_t)(const char* sender, const char* message);

// --- Public API ---
void              pwnbeaconInit(const char* name, const char* identity);
void              pwnbeaconSetFace(const char* face);
void              pwnbeaconSetPwnd(uint16_t run, uint16_t tot);
void              pwnbeaconAdvertise();
void              pwnbeaconScan(uint16_t duration_ms);
bool              pwnbeaconIsScanning();
void              pwnbeaconCheckGonePeers();
void              pwnbeaconSetMessageCallback(pwnbeacon_message_cb_t cb);
void              pwnbeaconSendMessage(const char* message);
pwnbeacon_peer_t* pwnbeaconGetPeers();
uint8_t           pwnbeaconGetPeerCount();
String            pwnbeaconGetLastFriendName();
int8_t            pwnbeaconGetClosestRssi();
String            pwnbeaconBuildIdentityJson();
