#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/uart.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "lwip/sockets.h"

#define WIFI_SSID "M"
#define WIFI_PASS "12345678"

#define TARGET_IP "172.20.10.3"
#define TARGET_PORT 8080

#define MAX_FRAME 2000
#define QUEUE_DEPTH 64

#define PCAP_UART_NUM UART_NUM_0

typedef struct
{
    uint16_t len;
    uint32_t exec_time_us; /* Thời gian thực thi hàm capture (us) */
    uint8_t data[];
} pkt_t;

static QueueHandle_t pkt_q;

// --- CẤU TRÚC HEADER PCAP CHUẨN ---
typedef struct __attribute__((packed))
{
    uint32_t magic_number;  /* 0xa1b2c3d4 */
    uint16_t version_major; /* 2 */
    uint16_t version_minor; /* 4 */
    int32_t thiszone;       /* GMT = 0 */
    uint32_t sigfigs;       /* 0 */
    uint32_t snaplen;       /* Max len = 65535 */
    uint32_t network;       /* Ethernet = 1 */
} pcap_global_header_t;

typedef struct __attribute__((packed))
{
    uint32_t ts_sec;   /* Phần giây của exec_time_us */
    uint32_t ts_usec;  /* Phần micro-giây của exec_time_us */
    uint32_t incl_len; /* Độ dài frame trong PCAP */
    uint32_t orig_len; /* Độ dài frame thực tế */
} pcap_packet_header_t;

static void send_pcap_global_header(void)
{
    pcap_global_header_t gh = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1};
    uart_write_bytes(PCAP_UART_NUM, (const char *)&gh, sizeof(gh));
}

// Hàm capture dữ liệu và đo thời gian thực thi (Execution Time)
static inline void capture(uint8_t dir, const void *buf, size_t len)
{
    int64_t t_start = esp_timer_get_time();

    if (buf == NULL || len < 14 || len > MAX_FRAME || pkt_q == NULL)
        return;

    pkt_t *p = malloc(sizeof(pkt_t) + len);
    if (p == NULL)
        return;

    p->len = (uint16_t)len;
    memcpy(p->data, buf, len);

    // Chốt thời gian hoàn tất xử lý bộ nhớ trước khi đẩy vào queue
    int64_t t_end = esp_timer_get_time();
    p->exec_time_us = (uint32_t)(t_end - t_start);

    // Đẩy vào queue (không chờ), nếu queue đầy thì drop để tránh block Wi-Fi/LwIP
    if (xQueueSend(pkt_q, &p, 0) != pdTRUE)
    {
        free(p);
    }
}

// --- CÁC HÀM HOOK LWIP / WI-FI ---
extern esp_err_t __real_esp_netif_receive(esp_netif_t *n, void *buffer, size_t len, void *eb);
esp_err_t __wrap_esp_netif_receive(esp_netif_t *n, void *buffer, size_t len, void *eb)
{
    capture(0, buffer, len);
    return __real_esp_netif_receive(n, buffer, len, eb);
}

extern esp_err_t __real_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len);
esp_err_t __wrap_esp_wifi_internal_tx(wifi_interface_t ifx, void *buffer, uint16_t len)
{
    capture(1, buffer, len);
    return __real_esp_wifi_internal_tx(ifx, buffer, len);
}

extern esp_err_t __real_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf);
esp_err_t __wrap_esp_wifi_internal_tx_by_ref(wifi_interface_t ifx, void *buffer, size_t len, void *netstack_buf)
{
    capture(1, buffer, len);
    return __real_esp_wifi_internal_tx_by_ref(ifx, buffer, len, netstack_buf);
}

// --- TASK ĐẨY DỮ LIỆU RA UART ---
static void pkt_task(void *pv)
{
    pkt_t *p;
    send_pcap_global_header();

    while (1)
    {
        if (xQueueReceive(pkt_q, &p, portMAX_DELAY) == pdTRUE)
        {
            pcap_packet_header_t ph;
            // Đưa trực tiếp exec_time_us vào trường Time của PCAP
            ph.ts_sec = p->exec_time_us / 1000000UL;
            ph.ts_usec = p->exec_time_us % 1000000UL;
            ph.incl_len = p->len;
            ph.orig_len = p->len;

            // Gửi Packet Header (16 bytes) + Payload gốc
            uart_write_bytes(PCAP_UART_NUM, (const char *)&ph, sizeof(ph));
            uart_write_bytes(PCAP_UART_NUM, (const char *)p->data, p->len);

            free(p);
        }
    }
}

// --- TASK GỬI CÁC BẢN TIN TEST TX ---
static void test_tx_task(void *pv)
{
    // Chờ 3 giây để PC khởi động xong Wireshark pipe
    vTaskDelay(pdMS_TO_TICKS(3000));

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_addr.s_addr = inet_addr(TARGET_IP);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(TARGET_PORT);

    int test_sizes[] = {32, 64, 128, 256, 512, 1024, 1400};
    size_t num_sizes = sizeof(test_sizes) / sizeof(test_sizes[0]);

    uint8_t *tx_buf = malloc(1400);
    if (tx_buf != NULL)
    {
        memset(tx_buf, 0xAA, 1400);
        for (size_t s = 0; s < num_sizes; s++)
        {
            int current_size = test_sizes[s];
            for (int i = 0; i < 50; i++)
            {
                sendto(sock, tx_buf, current_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                vTaskDelay(pdMS_TO_TICKS(15));
            }
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        free(tx_buf);
    }

    close(sock);
    vTaskDelete(NULL);
}

static void event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED)
    {
        esp_wifi_connect();
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP)
    {
        esp_wifi_set_ps(WIFI_PS_NONE);
        xTaskCreate(test_tx_task, "test_tx_task", 4096, NULL, 5, NULL);
    }
}

static void wifi_init_sta(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();

    esp_netif_dhcpc_stop(netif);
    esp_netif_ip_info_t ip_info;
    esp_netif_set_ip4_addr(&ip_info.ip, 172, 20, 10, 10);
    esp_netif_set_ip4_addr(&ip_info.gw, 172, 20, 10, 1);
    esp_netif_set_ip4_addr(&ip_info.netmask, 255, 255, 255, 240);
    esp_netif_set_ip_info(netif, &ip_info);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

    wifi_config_t wc = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wc));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void app_main(void)
{
    esp_log_level_set("*", ESP_LOG_NONE);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    uart_config_t uart_config = {
        .baud_rate = 921600,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE};
    uart_param_config(PCAP_UART_NUM, &uart_config);
    uart_driver_install(PCAP_UART_NUM, 4096, 0, 0, NULL, 0);

    pkt_q = xQueueCreate(QUEUE_DEPTH, sizeof(pkt_t *));
    xTaskCreate(pkt_task, "pkt_task", 4096, NULL, 4, NULL);

    wifi_init_sta();
}