#include "pwnbeacon.h"
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#include <mbedtls/sha256.h>

// --- Local state ---
static pwnbeacon_peer_t peers[PWNBEACON_MAX_PEERS];
static uint8_t          peer_count = 0;
static String           last_friend_name = "";

static char     local_name[PWNBEACON_ADV_MAX_NAME_LEN + 1] = {0};
static char     local_identity[129] = {0};
static char     local_face[64] = "(◕‿‿◕)";
static uint16_t local_pwnd_run = 0;
static uint16_t local_pwnd_tot = 0;
static uint8_t  local_fingerprint[PWNBEACON_FINGERPRINT_LEN] = {0};

static BLEServer*         ble_server = nullptr;
static BLECharacteristic* char_identity = nullptr;
static BLECharacteristic* char_face = nullptr;
static BLECharacteristic* char_name = nullptr;
static BLECharacteristic* char_signal = nullptr;
static BLEAdvertising*    ble_advertising = nullptr;

// --- Helpers ---

// Compute first 6 bytes of SHA-256 of the identity hex string
static void computeFingerprint(const char* identity, uint8_t* out) {
  uint8_t hash[32];
  mbedtls_sha256((const unsigned char*)identity, strlen(identity), hash, 0);
  memcpy(out, hash, PWNBEACON_FINGERPRINT_LEN);
}

// Build the compact advertisement payload
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

  // Actual payload size = fixed fields + name_len (not full 8 bytes)
  *len = offsetof(pwnbeacon_adv_t, name) + name_len;
  memcpy(buf, &adv, *len);
}

// Find peer by fingerprint, returns index or -1
static int findPeerByFingerprint(const uint8_t* fp) {
  for (uint8_t i = 0; i < peer_count; i++) {
    if (memcmp(peers[i].fingerprint, fp, PWNBEACON_FINGERPRINT_LEN) == 0) {
      return i;
    }
  }
  return -1;
}

// Parse a received advertisement payload into peer data
static void parseAdvPayload(const uint8_t* data, size_t len, int8_t rssi) {
  if (len < offsetof(pwnbeacon_adv_t, name)) {
    return;  // Too short
  }

  pwnbeacon_adv_t adv;
  memset(&adv, 0, sizeof(adv));
  size_t copy_len = len < sizeof(adv) ? len : sizeof(adv);
  memcpy(&adv, data, copy_len);

  if (adv.version != PWNBEACON_PROTOCOL_VERSION) {
    return;  // Unknown version
  }

  // Don't add ourselves
  if (memcmp(adv.fingerprint, local_fingerprint, PWNBEACON_FINGERPRINT_LEN) == 0) {
    return;
  }

  int idx = findPeerByFingerprint(adv.fingerprint);

  if (idx >= 0) {
    // Update existing peer
    peers[idx].rssi      = rssi;
    peers[idx].last_seen = millis();
    peers[idx].gone      = false;
    peers[idx].pwnd_run  = adv.pwnd_run;
    peers[idx].pwnd_tot  = adv.pwnd_tot;
    return;
  }

  // Add new peer
  if (peer_count >= PWNBEACON_MAX_PEERS) {
    return;  // Peer list full
  }

  uint8_t name_len = adv.name_len;
  if (name_len > PWNBEACON_ADV_MAX_NAME_LEN) {
    name_len = PWNBEACON_ADV_MAX_NAME_LEN;
  }

  memset(&peers[peer_count], 0, sizeof(pwnbeacon_peer_t));
  peers[peer_count].name      = String(adv.name).substring(0, name_len);
  peers[peer_count].pwnd_run  = adv.pwnd_run;
  peers[peer_count].pwnd_tot  = adv.pwnd_tot;
  peers[peer_count].rssi      = rssi;
  peers[peer_count].last_seen = millis();
  peers[peer_count].gone      = false;
  peers[peer_count].full_data = false;
  memcpy(peers[peer_count].fingerprint, adv.fingerprint, PWNBEACON_FINGERPRINT_LEN);

  last_friend_name = peers[peer_count].name;
  peer_count++;

  Serial.printf("[PwnBeacon] New peer: %s (RSSI: %d)\n",
                last_friend_name.c_str(), rssi);
}

// --- BLE Scan Callback ---
class PwnBeaconScanCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    if (!advertisedDevice.haveServiceUUID()) {
      return;
    }
    if (!advertisedDevice.isAdvertisingService(BLEUUID(PWNBEACON_SERVICE_UUID))) {
      return;
    }

    if (advertisedDevice.haveServiceData()) {
      String svcData = advertisedDevice.getServiceData();
      parseAdvPayload((const uint8_t*)svcData.c_str(), svcData.length(),
                      advertisedDevice.getRSSI());
    }
  }
};

// --- BLE Server Callback ---
class PwnBeaconServerCallback : public BLEServerCallbacks {
  void onConnect(BLEServer* server) override {
    Serial.println("[PwnBeacon] Peer connected via GATT");
  }

  void onDisconnect(BLEServer* server) override {
    Serial.println("[PwnBeacon] Peer disconnected");
    // Restart advertising after disconnect
    ble_advertising->start();
  }
};

// --- Signal (write) callback ---
class PwnBeaconSignalCallback : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic* characteristic) override {
    String value = characteristic->getValue();
    Serial.printf("[PwnBeacon] Signal received: %s\n", value.c_str());
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
  doc["session_id"]   = BLEDevice::getAddress().toString().c_str();
  doc["timestamp"]    = (int)(millis() / 1000);
  doc["uptime"]       = (int)(millis() / 1000);
  doc["version"]      = "1.8.4";

  String json;
  serializeJson(doc, json);
  return json;
}

void pwnbeaconInit(const char* name, const char* identity) {
  // Store local identity
  strncpy(local_name, name, PWNBEACON_ADV_MAX_NAME_LEN);
  local_name[PWNBEACON_ADV_MAX_NAME_LEN] = '\0';
  strncpy(local_identity, identity, sizeof(local_identity) - 1);
  computeFingerprint(identity, local_fingerprint);

  // Initialize BLE
  BLEDevice::init(name);

  // Create GATT server
  ble_server = BLEDevice::createServer();
  ble_server->setCallbacks(new PwnBeaconServerCallback());

  BLEService* service = ble_server->createService(PWNBEACON_SERVICE_UUID);

  // Identity characteristic — full JSON payload
  char_identity = service->createCharacteristic(
      PWNBEACON_IDENTITY_CHAR_UUID,
      BLECharacteristic::PROPERTY_READ);
  char_identity->setValue(pwnbeaconBuildIdentityJson().c_str());

  // Face characteristic — current mood
  char_face = service->createCharacteristic(
      PWNBEACON_FACE_CHAR_UUID,
      BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
  char_face->addDescriptor(new BLE2902());
  char_face->setValue(local_face);

  // Name characteristic
  char_name = service->createCharacteristic(
      PWNBEACON_NAME_CHAR_UUID,
      BLECharacteristic::PROPERTY_READ);
  char_name->setValue(local_name);

  // Signal characteristic — write-only for pinging
  char_signal = service->createCharacteristic(
      PWNBEACON_SIGNAL_CHAR_UUID,
      BLECharacteristic::PROPERTY_WRITE);
  char_signal->setCallbacks(new PwnBeaconSignalCallback());

  service->start();

  // Set up advertising with service data
  ble_advertising = BLEDevice::getAdvertising();
  ble_advertising->addServiceUUID(PWNBEACON_SERVICE_UUID);
  ble_advertising->setScanResponse(true);
  ble_advertising->setMinPreferred(0x06);

  Serial.printf("[PwnBeacon] Initialized: %s [%s]\n", name,
                BLEDevice::getAddress().toString().c_str());
}

void pwnbeaconSetFace(const char* face) {
  strncpy(local_face, face, sizeof(local_face) - 1);
  local_face[sizeof(local_face) - 1] = '\0';

  if (char_face) {
    char_face->setValue(local_face);
    char_face->notify();
  }
  if (char_identity) {
    char_identity->setValue(pwnbeaconBuildIdentityJson().c_str());
  }
}

void pwnbeaconSetPwnd(uint16_t run, uint16_t tot) {
  local_pwnd_run = run;
  local_pwnd_tot = tot;

  if (char_identity) {
    char_identity->setValue(pwnbeaconBuildIdentityJson().c_str());
  }
}

void pwnbeaconAdvertise() {
  uint8_t adv_data[sizeof(pwnbeacon_adv_t)];
  size_t adv_len = 0;
  buildAdvPayload(adv_data, &adv_len);

  // Set service data in the advertisement
  BLEAdvertisementData scanResponse;
  scanResponse.setServiceData(BLEUUID(PWNBEACON_SERVICE_UUID),
                              std::string((char*)adv_data, adv_len));
  ble_advertising->setScanResponseData(scanResponse);
  ble_advertising->start();
}

void pwnbeaconScan(uint16_t duration_ms) {
  BLEScan* scanner = BLEDevice::getScan();
  scanner->setAdvertisedDeviceCallbacks(new PwnBeaconScanCallback(), true);
  scanner->setActiveScan(true);
  scanner->setInterval(100);
  scanner->setWindow(99);
  scanner->start(duration_ms / 1000, false);
  scanner->clearResults();
}

void pwnbeaconCheckGonePeers() {
  uint32_t now = millis();
  for (uint8_t i = 0; i < peer_count; i++) {
    if (!peers[i].gone && (now - peers[i].last_seen) > PWNBEACON_PEER_TIMEOUT_MS) {
      peers[i].gone = true;
      Serial.printf("[PwnBeacon] Peer gone: %s\n", peers[i].name.c_str());
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
