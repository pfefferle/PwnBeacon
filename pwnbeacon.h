#ifndef PWNBEACON_H
#define PWNBEACON_H

#include "Arduino.h"
#include "ArduinoJson.h"

// --- PwnBeacon Service UUIDs ---
// "beacon leet"
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
typedef struct {
  int       epoch;
  String    face;
  String    grid_version;
  String    identity;
  String    name;
  int       pwnd_run;
  int       pwnd_tot;
  String    session_id;
  int       timestamp;
  int       uptime;
  String    version;
  int8_t    rssi;
  uint32_t  last_seen;
  bool      gone;
  bool      full_data;  // true if populated via GATT connection
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
void              pwnbeaconCheckGonePeers();
void              pwnbeaconSetMessageCallback(pwnbeacon_message_cb_t cb);
void              pwnbeaconSendMessage(const char* message);
pwnbeacon_peer_t* pwnbeaconGetPeers();
uint8_t           pwnbeaconGetPeerCount();
String            pwnbeaconGetLastFriendName();
int8_t            pwnbeaconGetClosestRssi();
String            pwnbeaconBuildIdentityJson();

#endif // PWNBEACON_H
