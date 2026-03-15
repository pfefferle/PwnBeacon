#include "pwnbeacon.h"

// --- Configuration ---
#define DEVICE_NAME     "PwnBeacon"
#define DEVICE_IDENTITY "32e9f315e92d974342c93d0fd952a914bfb4e6838953536ea6f63d54db6b9610"

#define SCAN_DURATION_MS  3000
#define ADV_INTERVAL_MS   5000
#define MOOD_INTERVAL_MS  10000

const char* faces[] = {
    "(O__O)",   // awake
    "( O_O)",   // observing
    "(+__+)",   // intense
    "(-@_@)",   // cool
    "(0__0)",   // happy
    "(^__^)",   // grateful
    "(a__a)",   // excited
    "(*__*)",   // friendly
    "(@__@)",   // motivated
    "(>__<)",   // demotivated
    "(-__-)",   // bored
    "(T_T )",   // sad
};
const int face_count = sizeof(faces) / sizeof(faces[0]);

uint32_t last_adv = 0;
uint32_t last_mood = 0;

void setup() {
  Serial.begin(115200);
  delay(1000);

  pwnbeaconInit(DEVICE_NAME, DEVICE_IDENTITY);
  pwnbeaconSetFace(faces[0]);
  pwnbeaconAdvertise();
}

void loop() {
  uint32_t now = millis();

  if (now - last_mood > MOOD_INTERVAL_MS) {
    pwnbeaconSetFace(faces[random(0, face_count)]);
    last_mood = now;
  }

  if (now - last_adv > ADV_INTERVAL_MS) {
    pwnbeaconAdvertise();
    last_adv = now;
  }

  if (!pwnbeaconIsScanning()) {
    pwnbeaconScan(SCAN_DURATION_MS);
  }

  pwnbeaconCheckGonePeers();
}
