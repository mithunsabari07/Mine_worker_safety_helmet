#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// ========= CONFIGURATION =========
const char* ssid = "Varun";
const char* password = "VARUN0430";
const char* serverUrl = "http://YOUR_SERVER_IP:5000/api/helmet/data";

// Worker and Helmet IDs
const String WORKER_ID = "WKR001";
const String HELMET_ID = "HLM001";

// -------- PINS --------
#define GAS_PIN      34
#define TEMP_PIN     35
#define IR_PIN       15
#define BUZZER_PIN   26
#define SOS_PIN      4
#define BATTERY_PIN  36

// -------- THRESHOLDS --------
#define GAS_THRESHOLD    2700
#define TEMP_THRESHOLD   40.0
#define FALL_THRESHOLD   2700

// -------- VARIABLES --------
unsigned long lastSendTime = 0;
const unsigned long SEND_INTERVAL = 5000; // 5 seconds

bool buzzerState = false;
unsigned long buzzerStartTime = 0;
const unsigned long BUZZER_DURATION = 3000; // 3 seconds

// -------- ACCELEROMETER --------
int lastX = 0, lastY = 0, lastZ = 0;
int xVal, yVal, zVal;

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  
  // Initialize pins
  pinMode(IR_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(SOS_PIN, INPUT_PULLUP);
  
  digitalWrite(BUZZER_PIN, LOW);
  
  Serial.println("Smart Safety Helmet - ESP32");
  
  // Connect to WiFi
  connectToWiFi();
  
  // Initial sensor readings
  readAccelerometer();
  lastX = xVal;
  lastY = yVal;
  lastZ = zVal;
}

void connectToWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) {
    delay(500);
    Serial.print(".");
    attempts++;
  }
  
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi Connected!");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\nFailed to connect to WiFi");
  }
}

// ================= SENSOR FUNCTIONS =================
float readTemperature() {
  int rawTemp = analogRead(TEMP_PIN);
  float voltage = rawTemp * (3.3 / 4095.0);
  float temperature = (voltage - 0.5) * 100.0;
  return temperature;
}

int readGas() {
  return analogRead(GAS_PIN);
}

void readAccelerometer() {
  xVal = analogRead(32);
  yVal = analogRead(33);
  zVal = analogRead(25);
}

bool detectFall() {
  readAccelerometer();
  
  // Calculate change in acceleration
  int deltaX = abs(xVal - lastX);
  int deltaY = abs(yVal - lastY);
  int deltaZ = abs(zVal - lastZ);
  
  // Update last values
  lastX = xVal;
  lastY = yVal;
  lastZ = zVal;
  
  // Detect sudden change (fall)
  if (deltaX > FALL_THRESHOLD || deltaY > FALL_THRESHOLD || deltaZ > FALL_THRESHOLD) {
    return true;
  }
  
  return false;
}

bool isHelmetWorn() {
  return digitalRead(IR_PIN) == LOW;
}

float readBattery() {
  int raw = analogRead(BATTERY_PIN);
  float voltage = raw * (3.3 / 4095.0);
  return voltage * 2.0; // Voltage divider
}

bool isSOSPressed() {
  return digitalRead(SOS_PIN) == LOW;
}

// ================= BUZZER CONTROL =================
void controlBuzzer(bool state) {
  if (state && !buzzerState) {
    buzzerState = true;
    buzzerStartTime = millis();
    digitalWrite(BUZZER_PIN, HIGH);
  } else if (!state && buzzerState) {
    buzzerState = false;
    digitalWrite(BUZZER_PIN, LOW);
  }
  
  // Auto-off after duration
  if (buzzerState && (millis() - buzzerStartTime > BUZZER_DURATION)) {
    controlBuzzer(false);
  }
}

// ================= SEND DATA TO SERVER =================
void sendSensorData() {
  if (WiFi.status() != WL_CONNECTED) {
    connectToWiFi();
    return;
  }
  
  // Read sensors
  float temperature = readTemperature();
  int gas = readGas();
  bool helmetWorn = isHelmetWorn();
  bool fall = detectFall();
  bool sos = isSOSPressed();
  float battery = readBattery();
  
  // Create JSON payload
  DynamicJsonDocument doc(512);
  doc["worker_id"] = WORKER_ID;
  doc["helmet_id"] = HELMET_ID;
  doc["helmet_worn"] = helmetWorn;
  doc["gas"] = gas;
  doc["temperature"] = temperature;
  doc["fall"] = fall || sos; // Treat SOS as fall emergency
  doc["battery"] = battery;
  doc["timestamp"] = millis();
  
  String payload;
  serializeJson(doc, payload);
  
  Serial.println("Sending data: " + payload);
  
  // Send HTTP POST
  HTTPClient http;
  http.begin(serverUrl);
  http.addHeader("Content-Type", "application/json");
  
  int httpCode = http.POST(payload);
  
  if (httpCode > 0) {
    String response = http.getString();
    Serial.println("Response: " + response);
    
    // Parse response for buzzer control
    DynamicJsonDocument respDoc(256);
    DeserializationError error = deserializeJson(respDoc, response);
    
    if (!error) {
      String buzzerCmd = respDoc["buzzer"];
      if (buzzerCmd == "ON") {
        controlBuzzer(true);
      } else {
        controlBuzzer(false);
      }
      
      // Print risk info
      Serial.print("Risk Score: ");
      Serial.println(respDoc["risk_score"].as<int>());
      Serial.print("Risk Level: ");
      Serial.println(respDoc["risk_level"].as<String>());
    }
  } else {
    Serial.println("HTTP Error: " + String(httpCode));
  }
  
  http.end();
}

// ================= LOOP =================
void loop() {
  // Check SOS button
  if (isSOSPressed()) {
    Serial.println("SOS BUTTON PRESSED!");
    controlBuzzer(true);
    delay(1000); // Immediate response
  }
  
  // Send data at regular intervals
  if (millis() - lastSendTime > SEND_INTERVAL) {
    sendSensorData();
    lastSendTime = millis();
  }
  
  // Check local thresholds for immediate response
  float temp = readTemperature();
  int gasVal = readGas();
  
  if (temp > TEMP_THRESHOLD || gasVal > GAS_THRESHOLD) {
    controlBuzzer(true);
  }
  
  delay(100);
}
