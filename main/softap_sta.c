/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
/*  WiFi softAP & station Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <sys/param.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif_net_stack.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#if IP_NAPT
#include "lwip/lwip_napt.h"
#endif
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include <esp_http_server.h>
#include "esp_spiffs.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "lwip/etharp.h"

//#include <byteswap.h>

#define DNS_SERVER_PORT 53
#define DNS_RESPONSE_IP "172.217.14.238"  // Replace with the IP you want to redirect to

//#define TCPH_HDR_LEN(tcp_hdr) ((tcp_hdr)->tcp_off * 4)

#define GPIO_INPUT_PIN    GPIO_NUM_4   // Example GPIO pin, change as per your setup
#define GPIO_INPUT_PIN_SEL  (1ULL<<GPIO_INPUT_PIN)

#define NVS_NAMESPACE "storage"
#define NVS_KEY_STRING "my_string"
/* The examples use WiFi configuration that you can set via project configuration menu.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_ESP_WIFI_STA_SSID "mywifissid"
*/

/* STA Configuration */
#define EXAMPLE_ESP_WIFI_STA_SSID           CONFIG_ESP_WIFI_REMOTE_AP_SSID
#define EXAMPLE_ESP_WIFI_STA_PASSWD         CONFIG_ESP_WIFI_REMOTE_AP_PASSWORD
#define EXAMPLE_ESP_MAXIMUM_RETRY           CONFIG_ESP_MAXIMUM_STA_RETRY

#if CONFIG_ESP_WIFI_AUTH_OPEN
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_OPEN
#elif CONFIG_ESP_WIFI_AUTH_WEP
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WEP
#elif CONFIG_ESP_WIFI_AUTH_WPA_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WPA_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA_WPA2_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WPA_WPA2_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WPA2_WPA3_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WPA2_WPA3_PSK
#elif CONFIG_ESP_WIFI_AUTH_WAPI_PSK
#define ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD   WIFI_AUTH_WAPI_PSK
#endif

/* AP Configuration */
#define EXAMPLE_ESP_WIFI_AP_SSID            CONFIG_ESP_WIFI_AP_SSID
#define EXAMPLE_ESP_WIFI_AP_PASSWD          CONFIG_ESP_WIFI_AP_PASSWORD
#define EXAMPLE_ESP_WIFI_CHANNEL            CONFIG_ESP_WIFI_AP_CHANNEL
#define EXAMPLE_MAX_STA_CONN                CONFIG_ESP_MAX_STA_CONN_AP


/* The event group allows multiple bits for each event, but we only care about two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static const char *TAG_AP = "WiFi SoftAP";
static const char *TAG_STA = "WiFi Sta";
static const char *TAG = "espressif";

char ssidBuf[20];
char pwdBuf[20];
static int s_retry_num = 0;

#define INDEX_HTML_PATH "/spiffs/index.html"
char index_html[4096];
char response_data[4096];
int led_state = 0;

#define NVS_NAMESPACE "storage"
#define NVS_KEY_STRING1 "ssid"
#define NVS_KEY_STRING2 "pwd"

typedef struct dns_hijack_srv_handle_t {
	TaskHandle_t task_handle;
	int sockfd;
	ip4_addr_t resolve_ip;
} dns_hijack_srv_handle_t;

typedef struct __attribute__((packed)) dns_header_t {
	uint16_t ID;
	uint8_t  RD       :1;
	uint8_t  TC       :1;
	uint8_t  AA       :1;
	uint8_t  OPCODE   :4;
	uint8_t  QR       :1;
	uint8_t  RCODE    :4;
	uint8_t  Z        :3;
	uint8_t  RA       :1;
	uint16_t QDCOUNT;
	uint16_t ANCOUNT;
	uint16_t NSCOUNT;
	uint16_t ARCOUNT;
} dns_header_t;

typedef struct __attribute__((packed)) dns_hijack_answer_t {
	uint16_t NAME;
	uint16_t TYPE;
	uint16_t CLASS;
	uint32_t TTL;
	uint16_t RDLENGTH;
	uint32_t RDATA;
} dns_hijack_answer_t;

void dns_server_task(void *pvParameters)
{
    int sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[512];
    socklen_t addr_len = sizeof(client_addr);
    int recv_len;
    char client_ip[INET_ADDRSTRLEN];
    dns_hijack_srv_handle_t dns_hijack_srv_handle;ip4_addr_t resolve_ip;
    inet_pton(AF_INET, "192.168.4.1", &resolve_ip);
    dns_hijack_srv_handle.resolve_ip = resolve_ip;
    // Create a UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE("dns_server", "Failed to create socket");
        vTaskDelete(NULL);
    }
    // Bind the socket to the DNS server port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_SERVER_PORT);

    if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE("dns_server", "Failed to bind socket");
        close(sock);
        vTaskDelete(NULL);
    }
    ESP_LOGI("dns_server", "DNS server started on port %d", DNS_SERVER_PORT);

    while (1) {
        // Receive DNS query
        recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
        // Convert the client's IP address to a readable format
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

        if (recv_len > 0) {
            // Nul termination. To prevent pointer escape
            buffer[sizeof(buffer) - 1] = '\0';

            dns_header_t *header = (dns_header_t*) buffer;

            header->QR      = 1;
            header->OPCODE  = 0;
            header->AA      = 0;
            header->RD      = 1;
            header->RCODE   = 0;
            header->TC      = 0;
            header->Z       = 0;
            header->RA      = 1;
            header->ANCOUNT = header->QDCOUNT;
            header->NSCOUNT = 0;
            header->ARCOUNT = 0;

            // ptr points to the beginning of the QUESTION
            char *ptr = buffer + sizeof(dns_header_t);

            // Jump over QNAME
            while(*ptr++);

            // Jump over QTYPE
            ptr += 2;

            // Jump over QCLASS
            ptr += 2;

            dns_hijack_answer_t *answer = (dns_hijack_answer_t*) ptr;

            answer->NAME     = 0x0CC0;      //__bswap_16(0xC00C);
            answer->TYPE     = 0x0100;      //__bswap_16(1);
            answer->CLASS    = 0x0100;      //__bswap_16(1);
            answer->TTL      = 0;
            answer->RDLENGTH = 0x0400;      //__bswap_16(4);
            answer->RDATA    = dns_hijack_srv_handle.resolve_ip.addr;//            .resolve_ip.addr;

            // Jump over ANSWER
            ptr += sizeof(dns_hijack_answer_t);
            int sz = ptr-buffer;
            int err = sendto(sock, buffer, sz, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
            printf("no. of char %d\n", sz);
            for(int t = 0; t < sz; t++)
            {
                printf("%02X", buffer[t]);
            }
            printf("\n");
            if (err < 0) {
                ESP_LOGE(TAG, "Error occurred during sending");
                break;
            }

            taskYIELD();
          //  ESP_LOGI("dns_server", "Received DNS query");
            /*if(strncmp(client_ip,"192.168.4.2",11))
            {
        // Print the client's IP address
        printf("Incoming IP: %s\n", client_ip);
            // Modify the DNS response
            buffer[2] = 0x81;  // Set QR (response) and opcode
            buffer[3] = 0x80;  // Recursion Available

            // Respond with a specific IP address
            buffer[recv_len++] = 0xc0;
            buffer[recv_len++] = 0x0c;
            buffer[recv_len++] = 0x00;
            buffer[recv_len++] = 0x01;
            buffer[recv_len++] = 0x00;
            buffer[recv_len++] = 0x01;
                buffer[recv_len++] = 0x00;
                buffer[recv_len++] = 0x00;
                buffer[recv_len++] = 0x00;
            buffer[recv_len++] = 0x3c;
            buffer[recv_len++] = 0x00;
            buffer[recv_len++] = 0x04;
            buffer[recv_len++] = 192;  // Example IP: 192.168.4.1
            buffer[recv_len++] = 168;
            buffer[recv_len++] = 4;
            buffer[recv_len++] = 1;

            // Send the modified DNS response
            sendto(sock, buffer, recv_len, 0, (struct sockaddr*)&client_addr, addr_len);
            }*/
        }
    }

    close(sock);
    vTaskDelete(NULL);
}

static void wifi_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_DATA) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*) buf;
        uint8_t *data = pkt->payload;
        uint16_t len = pkt->rx_ctrl.sig_len;

        if (len >= sizeof(struct eth_hdr) + sizeof(struct ip_hdr)) {
            struct eth_hdr *eth_header = (struct eth_hdr*) data;
            struct ip_hdr *ip_header = (struct ip_hdr*) (data + sizeof(struct eth_hdr));
            //printf("Data length is greater then zero\n\r");
            if (IPH_PROTO(ip_header) == IP_PROTO_TCP) {
                struct tcp_hdr *tcp_header = (struct tcp_hdr*) (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
                //uint16_t tcp_header_len = (TCPH_HDR_LEN(tcp_header) >> 12) * 4; // Extract the TCP header length in bytes
                //printf("Protocol is TCP\n\r");
                // uint16_t payload_len = len - sizeof(struct eth_hdr) - IPH_HL(ip_header) * 4;// - tcp_header_len;
                // if (payload_len > 0) {
                //     const char *http_data = (const char*) (data + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) /*+ tcp_header_len*/);
                //     //printf("Payload size is greter then zero");
                //     printf("%s\n\r", http_data);
                //     if (strstr(http_data, "GET ") != NULL) {
                //         ESP_LOGI(TAG, "GET request detected");
                //     } else if (strstr(http_data, "POST ") != NULL) {
                //         ESP_LOGI(TAG, "POST request detected");
                //     }
                // }
                //for (int i = 0; i < len; i++) {
                   // printf("=>%.*s|\n", len, data);
                //}
               // printf("\n");
            }
        }
    }
}

void init_gpio()
{
    gpio_config_t io_conf;
    // Disable interrupt for the GPIO input pin
    io_conf.intr_type = GPIO_INTR_DISABLE;
    // Set as input mode
    io_conf.mode = GPIO_MODE_INPUT;
    // Bit mask of the pins that you want to set
    io_conf.pin_bit_mask = GPIO_INPUT_PIN_SEL;
    // Set pull-up mode
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    // Set pull-down mode
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    // Configure GPIO with the given settings
    gpio_config(&io_conf);
}

void storeString(const char *str, int nm) {
    nvs_handle_t nvs_handle;
    esp_err_t err;

    // Initialize NVS
    err = nvs_flash_init();
    if (err != ESP_OK) {
        printf("Error (%s) initializing NVS\n", esp_err_to_name(err));
        return;
    }

    // Open NVS namespace
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("Error (%s) opening NVS handle\n", esp_err_to_name(err));
        return;
    }

    // Write string to NVS
    printf("string to store = %s\n\r", str);
    if(nm == 0)
        err = nvs_set_str(nvs_handle, NVS_KEY_STRING1, str);
    else
        err = nvs_set_str(nvs_handle, NVS_KEY_STRING2, str);
    if (err != ESP_OK) {
        printf("Error (%s) writing NVS string\n", esp_err_to_name(err));
    } else {
        printf("String stored successfully\n");
    }

    // Commit changes to NVS
    err = nvs_commit(nvs_handle);
    if (err != ESP_OK) {
        printf("Error (%s) committing NVS\n", esp_err_to_name(err));
    }

    // Close NVS handle
    nvs_close(nvs_handle);
}

int retrieveString(char *buffer, size_t buffer_size, int nm) {
    nvs_handle_t nvs_handle;
    esp_err_t err;
    int ret;

    // Initialize NVS
    err = nvs_flash_init();
    if (err != ESP_OK) {
        printf("Error (%s) initializing NVS\n", esp_err_to_name(err));
        return 2;
    }

    // Open NVS namespace
    err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvs_handle);
    if (err != ESP_OK) {
        printf("Error (%s) opening NVS handle\n", esp_err_to_name(err));
        return 2;
    }

    // Read string from NVS
    if(nm == 0)
        err = nvs_get_str(nvs_handle, NVS_KEY_STRING1, buffer, &buffer_size);
    else
        err = nvs_get_str(nvs_handle, NVS_KEY_STRING2, buffer, &buffer_size);
    switch (err) {
        case ESP_OK:
            printf("String retrieved: %s\n", buffer);
            ret = 0;
            break;
        case ESP_ERR_NVS_NOT_FOUND:
            printf("The requested NVS key was not found\n");
            ret = 1;
            break;
        default:
            printf("Error (%s) reading NVS string\n", esp_err_to_name(err));
            ret = 2;
    }

    // Close NVS handle
    nvs_close(nvs_handle);
    return ret;
}

static void initi_web_page_buffer(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true};

    ESP_ERROR_CHECK(esp_vfs_spiffs_register(&conf));
    printf("step 1\n\r");
    memset((void *)index_html, 0, sizeof(index_html));
    struct stat st;
    if (stat(INDEX_HTML_PATH, &st))
    {
        ESP_LOGE(TAG, "index.html not found");
        return;
    }
    printf("step 2\n\r");

    FILE *fp = fopen(INDEX_HTML_PATH, "r");
    if (fread(index_html, st.st_size, 1, fp) == 0)
    {
        ESP_LOGE(TAG, "fread failed");
    }
    printf("step 3\n\r");
    fclose(fp);
}

/*esp_err_t send_web_page(httpd_req_t *req)
{
    int response;
    if(led_state)
    {
        sprintf(response_data, index_html, "ON");
    }
    else
    {
        sprintf(response_data, index_html, "OFF");
    }
    response = httpd_resp_send(req, response_data, HTTPD_RESP_USE_STRLEN);
    return response;
}*/

esp_err_t get_req_handler(httpd_req_t *req)
{
    int response;
    printf("get 1\n\r");
    sprintf(response_data, index_html, "ON");
    response = httpd_resp_send(req, response_data, HTTPD_RESP_USE_STRLEN);
    return response;
   // return send_web_page(req);
}

esp_err_t login_handler(httpd_req_t *req) {
    // Open index.html from SPIFFS
    FILE *fp = fopen("/spiffs/login.html", "r");
    if (fp == NULL) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    // Read contents and send as HTTP response
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        httpd_resp_sendstr_chunk(req, line);
    }

    // Close file
    fclose(fp);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

esp_err_t register_handler(httpd_req_t *req) {
    // Open index.html from SPIFFS
    FILE *fp = fopen("/spiffs/register.html", "r");
    if (fp == NULL) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    // Read contents and send as HTTP response
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        httpd_resp_sendstr_chunk(req, line);
    }

    // Close file
    fclose(fp);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

/*esp_err_t res_handler(httpd_req_t *req) {
    // Open index.html from SPIFFS
    FILE *fp = fopen("/spiffs/msg.html", "r");
    if (fp == NULL) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    // Read contents and send as HTTP response
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        httpd_resp_sendstr_chunk(req, line);
    }

    // Close file
    fclose(fp);
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}*/

/* An HTTP POST handler */
esp_err_t post_handler(httpd_req_t *req)
{
    char content[100];
    int content_length = req->content_len;
    if (content_length > sizeof(content)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Content too long");
        return ESP_FAIL;
    }
    int ret = httpd_req_recv(req, content, content_length);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    content[ret] = '\0';
    ESP_LOGI("POST_HANDLER", "Received data: %s", content);

    // Parse JSON data
    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    // Extract data1 and data2 from JSON
    cJSON *data1 = cJSON_GetObjectItem(root, "SSID");
    cJSON *data2 = cJSON_GetObjectItem(root, "PWD");
    // Here you can process the received data (content) as needed
    ESP_LOGI("POST_HANDLER", "Received data: %s %s", data1->valuestring, data2->valuestring);
    storeString((const char*)data1->valuestring, 0);
    storeString((const char*)data2->valuestring, 1);
    httpd_resp_send(req, "Data received successfully", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

httpd_uri_t uri_get = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = get_req_handler,
    .user_ctx = NULL};

httpd_uri_t uri_login = {
    .uri = "/login",
    .method = HTTP_GET,
    .handler = login_handler,
    .user_ctx = NULL};

httpd_uri_t uri_register = {
    .uri = "/register",
    .method = HTTP_GET,
    .handler = register_handler,
    .user_ctx = NULL};

httpd_uri_t post_uri = {
            .uri       = "/post",
            .method    = HTTP_POST,
            .handler   = post_handler,
            .user_ctx  = NULL
        };

httpd_handle_t setup_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_handle_t server = NULL;
    printf("serv 1\n\r");

    if (httpd_start(&server, &config) == ESP_OK)
    {
        printf("serv 2\n\r");
        httpd_register_uri_handler(server, &uri_get);
        httpd_register_uri_handler(server, &uri_login);
        httpd_register_uri_handler(server, &uri_register);
        httpd_register_uri_handler(server, &post_uri);
    }
    printf("serv 3\n\r");
    return server;
}

/* FreeRTOS event group to signal when we are connected/disconnected */
static EventGroupHandle_t s_wifi_event_group;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *) event_data;
        ESP_LOGI(TAG_AP, "Station "MACSTR" joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *) event_data;
        ESP_LOGI(TAG_AP, "Station "MACSTR" left, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        ESP_LOGI(TAG_STA, "Station started");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG_STA, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/* Initialize soft AP */
esp_netif_t *wifi_init_softap(void)
{
    esp_netif_t *esp_netif_ap = esp_netif_create_default_wifi_ap();

    wifi_config_t wifi_ap_config = {
        .ap = {
            .ssid = EXAMPLE_ESP_WIFI_AP_SSID,
            .ssid_len = strlen(EXAMPLE_ESP_WIFI_AP_SSID),
            .channel = EXAMPLE_ESP_WIFI_CHANNEL,
            .password = EXAMPLE_ESP_WIFI_AP_PASSWD,
            .max_connection = EXAMPLE_MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {
                .required = false,
            },
        },
    };

    if (strlen(EXAMPLE_ESP_WIFI_AP_PASSWD) == 0) {
        wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));

    ESP_LOGI(TAG_AP, "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             EXAMPLE_ESP_WIFI_AP_SSID, EXAMPLE_ESP_WIFI_AP_PASSWD, EXAMPLE_ESP_WIFI_CHANNEL);

    return esp_netif_ap;
}

/* Initialize wifi station */
esp_netif_t *wifi_init_sta(void)
{
    esp_netif_t *esp_netif_sta = esp_netif_create_default_wifi_sta();

    wifi_config_t wifi_sta_config = {
        .sta = {
            //.ssid = EXAMPLE_ESP_WIFI_STA_SSID,
            //.password = EXAMPLE_ESP_WIFI_STA_PASSWD,
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .failure_retry_cnt = EXAMPLE_ESP_MAXIMUM_RETRY,
            /* Authmode threshold resets to WPA2 as default if password matches WPA2 standards (pasword len => 8).
             * If you want to connect the device to deprecated WEP/WPA networks, Please set the threshold value
             * to WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK and set the password with length and format matching to
            * WIFI_AUTH_WEP/WIFI_AUTH_WPA_PSK standards.
             */
            .threshold.authmode = ESP_WIFI_SCAN_AUTH_MODE_THRESHOLD,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };
    strcpy((char *)wifi_sta_config.sta.ssid, ssidBuf);
    strcpy((char *)wifi_sta_config.sta.password, pwdBuf);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config) );

    ESP_LOGI(TAG_STA, "wifi_init_sta finished.");

    return esp_netif_sta;
}

void softap_set_dns_addr(esp_netif_t *esp_netif_ap){
    esp_netif_dns_info_t dns;
    dns.ip.u_addr.ip4.addr = ipaddr_addr("8.8.8.8");
    dns.ip.type = IPADDR_TYPE_V4;
    uint8_t dhcps_dns_value = 2;
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(esp_netif_ap));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(esp_netif_ap, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value)));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(esp_netif_ap, ESP_NETIF_DNS_MAIN, &dns));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_start(esp_netif_ap));
}

void app_main(void)
{
    init_gpio();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    //Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Initialize event group */
    s_wifi_event_group = xEventGroupCreate();

    /* Register Event handler */
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                    ESP_EVENT_ANY_ID,
                    &wifi_event_handler,
                    NULL,
                    NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                    IP_EVENT_STA_GOT_IP,
                    &wifi_event_handler,
                    NULL,
                    NULL));

    /*Initialize WiFi */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    int input_val = gpio_get_level(GPIO_INPUT_PIN);
    printf("GPIO input value: %d\n", input_val);
    if(input_val == 0)
    {
        printf("Default credential\n\r");
        strcpy(ssidBuf, "Infinit");
        strcpy(pwdBuf, "infinit123");
    }
    else
    {     
        printf("Custom credential\n\r");
        retrieveString(ssidBuf, sizeof(ssidBuf), 0);
        retrieveString(pwdBuf, sizeof(pwdBuf), 1);
    }
    /* Initialize AP */
    ESP_LOGI(TAG_AP, "ESP_WIFI_MODE_AP");
    esp_netif_t *esp_netif_ap = wifi_init_softap();

  //  softap_set_dns_addr(esp_netif_ap);

    /* Initialize STA */
    ESP_LOGI(TAG_STA, "ESP_WIFI_MODE_STA");
    esp_netif_t *esp_netif_sta = wifi_init_sta();

    //esp_wifi_set_promiscuous(true);
    //esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_rx_cb);

    /* Start WiFi */
    ESP_ERROR_CHECK(esp_wifi_start() );

    /*
     * Wait until either the connection is established (WIFI_CONNECTED_BIT) or
     * connection failed for the maximum number of re-tries (WIFI_FAIL_BIT).
     * The bits are set by event_handler() (see above)
     */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE,
                                           pdFALSE,
                                           portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned,
     * hence we can test which event actually happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG_STA, "connected to ap SSID:%s password:%s",
                 EXAMPLE_ESP_WIFI_STA_SSID, EXAMPLE_ESP_WIFI_STA_PASSWD);
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG_STA, "Failed to connect to SSID:%s, password:%s",
                 EXAMPLE_ESP_WIFI_STA_SSID, EXAMPLE_ESP_WIFI_STA_PASSWD);
    } else {
        ESP_LOGE(TAG_STA, "UNEXPECTED EVENT");
        return;
    }

    /* Set sta as the default interface */
    esp_netif_set_default_netif(esp_netif_sta);

    /* Enable napt on the AP netif */
    if (esp_netif_napt_enable(esp_netif_ap) != ESP_OK) {
        ESP_LOGE(TAG_STA, "NAPT not enabled on the netif: %p", esp_netif_ap);
    }
        initi_web_page_buffer();
        setup_server();
    // Start the DNS server task
    //xTaskCreate(&dns_server_task, "dns_server_task", 4096, NULL, 5, NULL);
}
