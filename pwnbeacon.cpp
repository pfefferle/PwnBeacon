#include "pwnbeacon.h"
#include <ArduinoJson.h>
#include <NimBLEDevice.h>
#include <mbedtls/sha256.h>

// --- Local state ---
static pwnbeacon_peer_t peers[PWNBEACON_MAX_PEERS];
static uint8_t          peer_count = 0;
static String           last_friend_name = "";

static char     local_name[PWNBEACON_ADV_MAX_NAME_LEN + 1] = {0};
static char     local_identity[129] = {0};
static char     local_face[64] = "(O__O)";
static uint16_t local_pwnd_run = 0;
static uint16_t local_pwnd_tot = 0;
static uint8_t  local_fingerprint[PWNBEACON_FINGERPRINT_LEN] = {0};

static NimBLEServer*         ble_server = nullptr;
static NimBLECharacteristic* char_identity = nullptr;
static NimBLECharacteristic* char_face = nullptr;
static NimBLECharacteristic* char_name = nullptr;
static NimBLECharacteristic* char_signal = nullptr;
static NimBLECharacteristic* char_message = nullptr;
static NimBLEAdvertising*    ble_advertising = nullptr;

static pwnbeacon_message_cb_t message_callback = nullptr;
static bool ble_scanning = false;

// --- Helpers ---

static void computeFingerprint(const char* identity, uint8_t* out) {
  uint8_t hash[32];
  mbedtls_sha256((const unsigned char*)identity, strlen(identity), hash, 0);
  memcpy(out, hash, PWNBEACON_FINGERPRINT_LEN);
}

static void buildAdvPayload(uint8_t* buf, size_t* len) {
  pwnbeacon_adv_t adv;
  memset(&adv, 0, sizeof(adv));

  adv.version  = PWNBEACON_PROTOCOL_VERSION;
  adv.flags    = PWNBEACON_FLAG_ADVERTISE | PWNBEACON_FLAG_CONNECTABLE;
  adv.pwnd_run = local_pwnd_run;
  adv.pwnd_tot = local_pwnd_tot;
  memcpy(adv.fingerprint, local_fingerprint, PWNBEACON_FINGERPRINT_LEN);

  size_t name_len = strlen(local_name);
  if (name_len > PWNBEACON_ADV_MAX_NAME_LEN) {
    name_len = PWNBEACON_ADV_MAX_NAME_LEN;
  }
  adv.name_len = (uint8_t)name_len;
  memcpy(adv.name, local_name, name_len);

  *len = offsetof(pwnbeacon_adv_t, name) + name_len;
  memcpy(buf, &adv, *len);
}

static int findPeerByFingerprint(const uint8_t* fp) {
  for (uint8_t i = 0; i < peer_count; i++) {
    if (memcmp(peers[i].fingerprint, fp, PWNBEACON_FINGERPRINT_LEN) == 0) {
      return i;
    }
  }
  return -1;
}

static void addPeer(const uint8_t* data, size_t len, int8_t rssi,
                    const char* ble_name) {
  if (len < offsetof(pwnbeacon_adv_t, name)) {
    return;
  }

  pwnbeacon_adv_t adv;
  memset(&adv, 0, sizeof(adv));
  size_t copy_len = len < sizeof(adv) ? len : sizeof(adv);
  memcpy(&adv, data, copy_len);

  if (adv.version != PWNBEACON_PROTOCOL_VERSION) {
    return;
  }

  // Don't add ourselves
  if (memcmp(adv.fingerprint, local_fingerprint, PWNBEACON_FINGERPRINT_LEN) == 0) {
    return;
  }

  int idx = findPeerByFingerprint(adv.fingerprint);

  if (idx >= 0) {
    peers[idx].rssi      = rssi;
    peers[idx].last_seen = millis();
    peers[idx].gone      = false;
    peers[idx].pwnd_run  = adv.pwnd_run;
    peers[idx].pwnd_tot  = adv.pwnd_tot;
    return;
  }

  if (peer_count >= PWNBEACON_MAX_PEERS) {
    return;
  }

  uint8_t name_len = adv.name_len;
  if (name_len > PWNBEACON_ADV_MAX_NAME_LEN) {
    name_len = PWNBEACON_ADV_MAX_NAME_LEN;
  }

  memset(&peers[peer_count], 0, sizeof(pwnbeacon_peer_t));
  if (name_len > 0) {
    peers[peer_count].name = String(adv.name).substring(0, name_len);
  } else if (ble_name && strlen(ble_name) > 0) {
    peers[peer_count].name = String(ble_name);
  } else {
    peers[peer_count].name = "BLE peer";
  }
  peers[peer_count].pwnd_run  = adv.pwnd_run;
  peers[peer_count].pwnd_tot  = adv.pwnd_tot;
  peers[peer_count].rssi      = rssi;
  peers[peer_count].last_seen = millis();
  peers[peer_count].gone      = false;
  peers[peer_count].full_data = false;
  memcpy(peers[peer_count].fingerprint, adv.fingerprint, PWNBEACON_FINGERPRINT_LEN);

  last_friend_name = peers[peer_count].name;
  peer_count++;
}

// --- NimBLE Scan Callbacks ---
class PwnBeaconScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* device) override {
    int svcDataCount = device->getServiceDataCount();
    for (int i = 0; i < svcDataCount; i++) {
      if (device->getServiceDataUUID(i).equals(NimBLEUUID(PWNBEACON_SERVICE_UUID))) {
        std::string svcData = device->getServiceData(i);
        std::string devName = device->getName();
        addPeer((const uint8_t*)svcData.data(), svcData.length(),
                device->getRSSI(), devName.c_str());
        break;
      }
    }
  }

  void onScanEnd(const NimBLEScanResults& results, int reason) override {
    ble_scanning = false;
  }
};

static PwnBeaconScanCallbacks scanCallbacks;

// --- NimBLE Server Callbacks ---
class PwnBeaconServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* server, NimBLEConnInfo& connInfo) override {
    // Restart advertising so other peers can still discover us
    ble_advertising->start();
  }
};

// --- Signal (write) callback ---
class SignalCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* characteristic, NimBLEConnInfo& connInfo) override {
    // Signal received — can be used for ping/poke
  }
};

// --- Message (write) callback ---
class MessageCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* characteristic, NimBLEConnInfo& connInfo) override {
    std::string raw = characteristic->getValue();
    if (!message_callback) return;

    String val = String(raw.c_str());
    int sep = val.indexOf(':');
    if (sep > 0) {
      message_callback(val.substring(0, sep).c_str(), val.substring(sep + 1).c_str());
    } else {
      message_callback("unknown", val.c_str());
    }
  }
};

// --- Public API ---

String pwnbeaconBuildIdentityJson() {
  JsonDocument doc;

  doc["pal"]          = true;
  doc["name"]         = local_name;
  doc["face"]         = local_face;
  doc["epoch"]        = 1;
  doc["grid_version"] = "2.0.0-ble";
  doc["identity"]     = local_identity;
  doc["pwnd_run"]     = local_pwnd_run;
  doc["pwnd_tot"]     = local_pwnd_tot;
  doc["session_id"]   = NimBLEDevice::getAddress().toString().c_str();
  doc["timestamp"]    = (int)(millis() / 1000);
  doc["uptime"]       = (int)(millis() / 1000);
  doc["version"]      = "1.8.4";

  String json;
  serializeJson(doc, json);
  return json;
}

void pwnbeaconInit(const char* name, const char* identity) {
  strncpy(local_name, name, PWNBEACON_ADV_MAX_NAME_LEN);
  local_name[PWNBEACON_ADV_MAX_NAME_LEN] = '\0';
  strncpy(local_identity, identity, sizeof(local_identity) - 1);
  computeFingerprint(identity, local_fingerprint);

  NimBLEDevice::init(name);

  // Create GATT server
  ble_server = NimBLEDevice::createServer();
  ble_server->setCallbacks(new PwnBeaconServerCallbacks());

  NimBLEService* service = ble_server->createService(PWNBEACON_SERVICE_UUID);

  // Identity — full JSON payload (read)
  char_identity = service->createCharacteristic(
      PWNBEACON_IDENTITY_CHAR_UUID, NIMBLE_PROPERTY::READ);
  char_identity->setValue(pwnbeaconBuildIdentityJson());

  // Face — current mood (read + notify)
  char_face = service->createCharacteristic(
      PWNBEACON_FACE_CHAR_UUID,
      NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::NOTIFY);
  char_face->setValue(local_face);

  // Name (read)
  char_name = service->createCharacteristic(
      PWNBEACON_NAME_CHAR_UUID, NIMBLE_PROPERTY::READ);
  char_name->setValue(local_name);

  // Signal — write-only ping/poke
  char_signal = service->createCharacteristic(
      PWNBEACON_SIGNAL_CHAR_UUID, NIMBLE_PROPERTY::WRITE);
  char_signal->setCallbacks(new SignalCallbacks());

  // Message — read/write/notify for text messages
  char_message = service->createCharacteristic(
      PWNBEACON_MESSAGE_CHAR_UUID,
      NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::NOTIFY);
  char_message->setCallbacks(new MessageCallbacks());

  service->start();

  // Set up advertising
  ble_advertising = NimBLEDevice::getAdvertising();
  ble_advertising->addServiceUUID(NimBLEUUID(PWNBEACON_SERVICE_UUID));
  ble_advertising->setMinInterval(0x20);
  ble_advertising->setMaxInterval(0x40);
}

void pwnbeaconSetFace(const char* face) {
  strncpy(local_face, face, sizeof(local_face) - 1);
  local_face[sizeof(local_face) - 1] = '\0';

  if (char_face) {
    char_face->setValue(local_face);
    char_face->notify();
  }
  if (char_identity) {
    char_identity->setValue(pwnbeaconBuildIdentityJson());
  }
}

void pwnbeaconSetPwnd(uint16_t run, uint16_t tot) {
  local_pwnd_run = run;
  local_pwnd_tot = tot;

  if (char_identity) {
    char_identity->setValue(pwnbeaconBuildIdentityJson());
  }
}

void pwnbeaconAdvertise() {
  uint8_t adv_data[sizeof(pwnbeacon_adv_t)];
  size_t adv_len = 0;
  buildAdvPayload(adv_data, &adv_len);

  // BLE scan response: 31 bytes max, 128-bit UUID takes 18 bytes overhead,
  // leaving ~13 bytes for service data. Clamp to 10 for safety.
  if (adv_len > 10) {
    adv_len = 10;
  }

  NimBLEAdvertisementData advData;
  advData.setFlags(BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP);
  advData.setCompleteServices(NimBLEUUID(PWNBEACON_SERVICE_UUID));

  NimBLEAdvertisementData scanResp;
  scanResp.setServiceData(NimBLEUUID(PWNBEACON_SERVICE_UUID),
                          std::string((char*)adv_data, adv_len));

  ble_advertising->stop();
  ble_advertising->setAdvertisementData(advData);
  ble_advertising->setScanResponseData(scanResp);
  ble_advertising->start();
}

void pwnbeaconScan(uint16_t duration_ms) {
  if (ble_scanning) return;

  NimBLEScan* scanner = NimBLEDevice::getScan();
  scanner->setScanCallbacks(&scanCallbacks, true);
  scanner->setActiveScan(true);
  scanner->setInterval(45);
  scanner->setWindow(15);
  scanner->clearResults();

  ble_scanning = true;
  if (!scanner->start(duration_ms)) {
    ble_scanning = false;
  }
}

bool pwnbeaconIsScanning() {
  return ble_scanning;
}

void pwnbeaconCheckGonePeers() {
  uint32_t now = millis();
  for (uint8_t i = 0; i < peer_count; i++) {
    if (!peers[i].gone && (now - peers[i].last_seen) > PWNBEACON_PEER_TIMEOUT_MS) {
      peers[i].gone = true;
    }
  }
}

pwnbeacon_peer_t* pwnbeaconGetPeers() {
  return peers;
}

uint8_t pwnbeaconGetPeerCount() {
  return peer_count;
}

String pwnbeaconGetLastFriendName() {
  return last_friend_name;
}

int8_t pwnbeaconGetClosestRssi() {
  int8_t closest = -127;
  for (uint8_t i = 0; i < peer_count; i++) {
    if (!peers[i].gone && peers[i].rssi > closest) {
      closest = peers[i].rssi;
    }
  }
  return closest;
}

void pwnbeaconSetMessageCallback(pwnbeacon_message_cb_t cb) {
  message_callback = cb;
}

void pwnbeaconSendMessage(const char* message) {
  if (!char_message) return;

  String payload = String(local_name) + ":" + String(message);
  char_message->setValue(payload);
  char_message->notify();
}
