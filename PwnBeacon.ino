#include "pwnbeacon.h"

// --- Configuration ---
#define DEVICE_NAME "PwnBeacon"
#define DEVICE_IDENTITY "32e9f315e92d974342c93d0fd952a914bfb4e6838953536ea6f63d54db6b9610"

#define SCAN_DURATION_MS   3000   // BLE scan window
#define ADV_INTERVAL_MS    5000   // Re-advertise interval
#define MOOD_INTERVAL_MS   10000  // Mood change interval

// Pwnagotchi-style faces
const char* faces[] = {
    "(◕‿‿◕)",   // awake
    "( ⚆_⚆)",   // observing
    "(°▃▃°)",   // intense
    "(⌐■_■)",   // cool
    "(•‿‿•)",   // happy
    "(^‿‿^)",   // grateful
    "(ᵔ◡◡ᵔ)",  // excited
    "(✜‿‿✜)",   // smart
    "(♥‿‿♥)",   // friendly
    "(≖__≖)",   // demotivated
    "(-__-)",   // bored
    "(╥☁╥ )",   // sad
};
const int face_count = sizeof(faces) / sizeof(faces[0]);

uint32_t last_adv = 0;
uint32_t last_mood = 0;

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("=== PwnBeacon ===");
  Serial.println("BLE PwnGrid Protocol");

  pwnbeaconInit(DEVICE_NAME, DEVICE_IDENTITY);
  pwnbeaconSetFace(faces[0]);
  pwnbeaconAdvertise();

  Serial.println("Advertising started. Scanning for peers...");
}

void loop() {
  uint32_t now = millis();

  // Periodically change mood
  if (now - last_mood > MOOD_INTERVAL_MS) {
    int idx = random(0, face_count);
    pwnbeaconSetFace(faces[idx]);
    Serial.printf("Mood: %s\n", faces[idx]);
    last_mood = now;
  }

  // Periodically re-advertise
  if (now - last_adv > ADV_INTERVAL_MS) {
    pwnbeaconAdvertise();
    last_adv = now;
  }

  // Scan for peers
  pwnbeaconScan(SCAN_DURATION_MS);

  // Check for gone peers
  pwnbeaconCheckGonePeers();

  // Print peer count
  uint8_t count = pwnbeaconGetPeerCount();
  if (count > 0) {
    Serial.printf("Peers: %d | Closest RSSI: %d | Last: %s\n",
                  count, pwnbeaconGetClosestRssi(),
                  pwnbeaconGetLastFriendName().c_str());
  }
}
