# ESP32 Node Monitor

ESP32 thu thập các frame đi qua Wi-Fi STA bằng linker wrapper của ESP-IDF, đóng gói thành luồng PCAP và gửi qua UART0. Script Python đọc luồng này, chuyển tiếp sang Wireshark và tạo thống kê độ trễ cho các gói UDP test.

> Đây không phải Wi-Fi monitor mode. Chương trình chỉ thu được frame đi qua network stack/Wi-Fi driver của chính ESP32.

## Luồng hoạt động

```text
Wi-Fi driver / network stack
        |
        +-- __wrap_esp_netif_receive()       RX
        +-- __wrap_esp_wifi_internal_tx()    TX
        +-- __wrap_esp_wifi_internal_tx_by_ref() TX
        |
        +-- capture(): sao chép frame vào heap
        |
        +-- FreeRTOS queue pkt_q (64 con trỏ)
        |
        +-- pkt_task(): ghi PCAP qua UART0
        |
        +-- esp32_wireshark.py -> Wireshark
```

`capture()` sao chép frame rồi gửi con trỏ vào queue với thời gian chờ bằng 0. Nếu heap không đủ, queue đầy hoặc frame không hợp lệ thì frame bị bỏ qua; luồng Wi-Fi vẫn tiếp tục hoạt động.

## Định dạng dữ liệu UART

UART0 dùng cấu hình `921600 baud, 8N1`. Luồng dữ liệu là PCAP little-endian:

1. Global header PCAP 24 byte, gửi một lần khi `pkt_task` bắt đầu.
2. Với mỗi frame:
   - Packet header PCAP 16 byte: `ts_sec`, `ts_usec`, `incl_len`, `orig_len`.
   - Payload đúng `incl_len` byte.

Không có dữ liệu bổ sung giữa packet header và payload. Điều này cần khớp với `esp32_wireshark.py`; nếu chèn thêm byte, parser sẽ lệch stream và Wireshark có thể báo `frame too long`.

Các timestamp được lấy từ `esp_timer_get_time()`, nên là thời gian tương đối kể từ lúc ESP32 khởi động, không phải Unix time. `incl_len` và `orig_len` đều bằng kích thước frame được capture.

UART là kênh nhị phân. Không chạy monitor hoặc log ASCII trên cùng UART khi đang thu PCAP.

## Linker wrapper

Các wrapper được khai báo trong [main/CMakeLists.txt](main/CMakeLists.txt):

```cmake
-Wl,--wrap=esp_netif_receive
-Wl,--wrap=esp_wifi_internal_tx
-Wl,--wrap=esp_wifi_internal_tx_by_ref
```

Wrapper gọi `capture()` trước rồi gọi lại hàm thật thông qua `__real_*`. Các symbol này là API nội bộ/phụ thuộc phiên bản ESP-IDF, nên có thể thay đổi khi đổi IDF hoặc target.

## Cấu hình hiện tại

Các macro nằm trong [main/test_esp_main.c](main/test_esp_main.c):

- `WIFI_SSID`, `WIFI_PASS`: thông tin Access Point.
- ESP32 dùng IP tĩnh `172.20.10.10`, gateway `172.20.10.1`, netmask `255.255.255.240`.
- `MAX_FRAME = 2000`: frame lớn hơn giá trị này bị bỏ qua.
- `QUEUE_DEPTH = 64`: số con trỏ tối đa chờ trong queue.
- `PCAP_UART_NUM = UART_NUM_0`.
- Gói UDP test được gửi tới `172.20.10.3:8080`.

Nên thay SSID/mật khẩu bằng cấu hình riêng và không commit mật khẩu thật vào repository.

## Kịch bản test UDP

Sau khi ESP32 nhận IP, `test_tx_task()` tự gửi 50 gói cho mỗi kích thước:

```text
32, 64, 128, 256, 512, 1024, 1400 byte
```

Các gói này tạo dữ liệu TEST_TX. Script Python đồng thời gửi cùng kịch bản từ máy tính tới ESP32 để tạo dữ liệu TEST_RX.

## Chạy script Python và Wireshark

Trong [esp32_wireshark.py](esp32_wireshark.py), kiểm tra các biến:

```python
COM_PORT = "COM10"
BAUD_RATE = 921600
ESP32_IP = "172.20.10.10"
UDP_PORT = 8080
WIRESHARK_PATH = r"C:\Program Files\Wireshark\Wireshark.exe"
```

Cài dependency:

```sh
pip install pyserial pandas tabulate
```

Sau khi flash firmware, đóng mọi terminal đang mở COM port rồi chạy:

```sh
python esp32_wireshark.py
```

Script sẽ:

1. Chờ magic PCAP `d4 c3 b2 a1` từ UART.
2. Mở Wireshark với input stdin.
3. Gửi UDP test từ máy tính tới ESP32.
4. Lọc các frame IPv4/UDP có source hoặc destination port `8080`.
5. Ghi bốn file CSV:
   - `hook_latency_test_tx_raw.csv`
   - `hook_latency_test_tx_summary.csv`
   - `hook_latency_test_rx_raw.csv`
   - `hook_latency_test_rx_summary.csv`

## Build và flash

Yêu cầu ESP-IDF đã được cấu hình trong terminal:

```sh
idf.py set-target esp32
idf.py build
idf.py -p PORT flash
```

Không chạy `idf.py monitor` cùng lúc vì nó sẽ đọc hoặc làm lẫn luồng PCAP nhị phân trên UART0.

## Giới hạn

- Frame có thể bị mất khi queue đầy, thiếu heap hoặc tốc độ capture vượt băng thông UART.
- `malloc()` được gọi cho mỗi frame; tải cao có thể gây phân mảnh heap.
- Frame được ghi nguyên dạng và có thể chứa dữ liệu nhạy cảm.
- Tham số `dir` được truyền vào `capture()` nhưng hiện chưa được lưu vào `pkt_t` hoặc PCAP; script suy luận TEST_TX/TEST_RX dựa trên địa chỉ IP và port UDP.
- Chương trình chưa lọc VLAN, IPv4/IPv6 hoặc protocol ngoài phần lọc test của script.

## Cấu trúc dự án

```text
.
├── CMakeLists.txt
├── README.md
├── esp32_wireshark.py
└── main
    ├── CMakeLists.txt
    └── test_esp_main.c
```
