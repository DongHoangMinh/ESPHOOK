# ESP32 Node Monitor

Firmware ESP32 thu các frame mạng đi qua một số điểm trong network stack/Wi-Fi driver, đóng gói dữ liệu thành luồng PCAP và gửi qua UART0. Script Python trên máy tính đọc luồng PCAP, chuyển tiếp trực tiếp vào Wireshark, đồng thời nhận diện các gói UDP thử nghiệm để xuất thống kê thời gian xử lý của hàm capture.

> **Giới hạn quan trọng:** Đây không phải Wi-Fi monitor mode và không thu toàn bộ frame 802.11 trong không khí. Firmware chỉ quan sát dữ liệu đi qua các hook được liên kết vào ESP-IDF của chính thiết bị. Nội dung frame thu được phụ thuộc vị trí và định dạng dữ liệu tại các hook này.

## Mục tiêu và thành phần

- Firmware ESP-IDF chạy trên ESP32, kết nối Wi-Fi ở chế độ Station với IP tĩnh.
- Các linker wrapper chặn đường nhận và truyền frame, sao chép frame vào hàng đợi không chờ.
- Một FreeRTOS task chuyển frame thành bản ghi PCAP và ghi nhị phân lên UART0.
- `esp32_wireshark.py` đọc UART, mở Wireshark bằng giao diện stdin, phát UDP thử nghiệm từ PC và ghi bốn file CSV.

## Kiến trúc luồng dữ liệu

```text
ESP-IDF / Wi-Fi
  ├─ esp_netif_receive()                 (RX hook)
  ├─ esp_wifi_internal_tx()              (TX hook)
  └─ esp_wifi_internal_tx_by_ref()        (TX hook)
             │
             ▼
        capture(): kiểm tra, malloc, sao chép frame,
                   đo thời gian xử lý và enqueue không chờ
             │
             ▼
        pkt_q (tối đa 64 con trỏ)
             │
             ▼
        pkt_task(): PCAP global header + packet records
             │ UART0, 921600 baud, 8N1
             ▼
        esp32_wireshark.py ──► Wireshark (stdin)
                         └──► phân loại UDP test, thống kê CSV
```

Các wrapper gọi `capture()` rồi chuyển tiếp lời gọi đến hàm thật (`__real_*`), do đó mục đích là quan sát mà không thay thế xử lý mạng gốc. Việc sao chép và enqueue được thực hiện đồng bộ trong đường hook; queue send dùng timeout bằng 0 để tránh chờ khi hàng đợi đầy.

## Yêu cầu

### Phần cứng và mạng

- Board ESP32 tương thích với target `esp32` và cáp USB/UART.
- Máy tính có thể mở cổng COM của ESP32 và chạy Wireshark.
- ESP32 và máy tính cùng mạng có khả năng liên lạc UDP hai chiều.
- Cấu hình mạng hiện được đặt trực tiếp trong mã nguồn:
  - ESP32: `172.20.10.10`
  - Gateway: `172.20.10.1`
  - Netmask: `255.255.255.240` (`/28`)
  - Đích gói test TX từ ESP32: `172.20.10.3:8080`

Đảm bảo các địa chỉ trên phù hợp với mạng thử nghiệm, không bị thiết bị khác sử dụng và gateway hỗ trợ subnet này. Máy tính chạy script cần có địa chỉ có thể gửi gói tới ESP32. Firewall có thể cần cho phép UDP port 8080.

### Phần mềm

- ESP-IDF đã cài đặt và môi trường ESP-IDF đã được khởi tạo.
- Python 3.
- Wireshark đã cài đặt.
- Các thư viện Python:

```powershell
py -m pip install pyserial pandas tabulate
```

## Cấu hình trước khi chạy

### Wi-Fi và UDP trong firmware

Sửa các hằng số ở đầu `main/test_esp_main.c` để dùng thông tin mạng của bạn:

```c
#define WIFI_SSID "your-ssid"
#define WIFI_PASS "your-password"
#define TARGET_IP "172.20.10.3"
#define TARGET_PORT 8080
```

Địa chỉ IP tĩnh được thiết lập trong `wifi_init_sta()`. Cần cập nhật đồng bộ nếu subnet hoặc địa chỉ ESP32 thay đổi. Không commit mật khẩu Wi-Fi thật vào repository dùng chung.

Một số thông số firmware:

| Thông số | Giá trị hiện tại | Ý nghĩa |
|---|---:|---|
| `MAX_FRAME` | 2000 byte | Frame lớn hơn mức này bị bỏ qua |
| `QUEUE_DEPTH` | 64 | Số frame tối đa đang chờ task UART |
| `PCAP_UART_NUM` | UART0 | Kênh phát luồng PCAP nhị phân |
| UART | 921600, 8N1 | Tốc độ và định dạng serial |
| UDP port thử nghiệm | 8080 | Port dùng để nhận diện gói test |

### Cấu hình script Python

Trong `esp32_wireshark.py`, kiểm tra các giá trị sau:

```python
COM_PORT = "COM10"
BAUD_RATE = 921600
ESP32_IP = "172.20.10.10"
UDP_PORT = 8080
WIRESHARK_PATH = r"C:\Program Files\Wireshark\Wireshark.exe"
```

Đổi `COM_PORT` theo cổng đang gắn với board và `WIRESHARK_PATH` theo nơi cài Wireshark. `ESP32_IP` phải khớp IP tĩnh trong firmware. Nếu không muốn dùng đường dẫn cài đặt mặc định, cập nhật biến này trước khi chạy.

## Build và flash firmware

Mở terminal đã cấu hình ESP-IDF tại thư mục dự án, sau đó chạy:

```powershell
idf.py set-target esp32
idf.py build
idf.py -p COM10 flash
```

Thay `COM10` bằng cổng serial của board. Có thể dùng CMake Tools hoặc ESP-IDF extension trong VS Code để build/flash thay cho các lệnh trên.

Firmware dùng linker wrapping trong `main/CMakeLists.txt`:

```cmake
-Wl,--wrap=esp_netif_receive
-Wl,--wrap=esp_wifi_internal_tx
-Wl,--wrap=esp_wifi_internal_tx_by_ref
```

Đây là các symbol nội bộ/phụ thuộc phiên bản ESP-IDF. Khi đổi phiên bản IDF hoặc target, symbol và chữ ký hàm có thể thay đổi, khiến build hoặc hook không còn hoạt động như dự kiến.

## Chạy bộ thu và xem Wireshark

1. Flash firmware và khởi động ESP32.
2. Đóng các chương trình đang giữ cổng COM. Không mở serial monitor trên cùng UART0 trong lúc thu, vì UART0 đang mang PCAP nhị phân.
3. Cập nhật cấu hình trong `esp32_wireshark.py`.
4. Từ thư mục dự án, chạy:

```powershell
py esp32_wireshark.py
```

5. Script mở serial, tìm PCAP Global Header, khởi chạy Wireshark với capture interface stdin (`-i -`) rồi bắt đầu đọc liên tục.
6. Script tạo thêm luồng gửi UDP từ PC đến ESP32. Nhấn `Ctrl+C` để dừng đọc và xuất các bảng thống kê.

Firmware cũng khởi chạy `test_tx_task()` sau khi nhận IP. Task này đợi 3 giây rồi gửi tới `172.20.10.3:8080`. Script phía PC đợi 3 giây sau khi Wireshark được mở rồi gửi UDP tới `ESP32_IP:8080` để tạo tải chiều nhận. Vì vậy cần chạy script và firmware cùng lúc, và máy tính phải là host đích `TARGET_IP` nếu muốn nhận các gói test TX từ ESP32.

Mỗi chiều thử nghiệm dùng payload kích thước `32, 64, 128, 256, 512, 1024, 1400` byte, 50 gói mỗi kích thước. Firmware gửi cách nhau 15 ms giữa các gói và nghỉ 200 ms giữa các kích thước. Script PC gửi cách nhau 20 ms và nghỉ 500 ms giữa các kích thước. Thời lượng gần đúng của mỗi đợt phát vì vậy khác nhau.

## Luồng PCAP qua UART

UART được sử dụng như một kênh nhị phân thuần. Firmware phát PCAP little-endian:

1. Global Header PCAP 24 byte, phát một lần khi `pkt_task` chạy.
2. Mỗi bản ghi gồm Packet Header 16 byte (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`), theo sau ngay bởi `incl_len` byte payload.

Không có byte log hoặc delimiter xen giữa header và payload. Thêm log ASCII lên UART0 trong lúc capture sẽ làm sai cấu trúc luồng và có thể khiến Wireshark đọc lỗi.

### Ý nghĩa timestamp

Mặc dù các trường PCAP có tên `ts_sec` và `ts_usec`, firmware không ghi thời điểm bắt gói. `capture()` đo khoảng thời gian từ lúc bắt đầu đến sau khi cấp phát và sao chép frame, lưu số microsecond đó vào `exec_time_us`; `pkt_task` tách giá trị này thành giây và microsecond để ghi vào PCAP. Vì vậy `ts_usec` được script dùng làm `Do_Tre_us` là thời gian thực thi phần capture được đo, không phải độ trễ mạng, thời gian truyền UART hay timestamp đồng hồ thực.

`incl_len` và `orig_len` hiện đều bằng kích thước frame đã copy. `orig_len` trong CSV do đó phản ánh kích thước frame mà hook cung cấp, không nhất thiết là kích thước của gói UDP application payload.

## Phân loại và thống kê gói UDP

Script kiểm tra payload bắt được để chọn IPv4/UDP có source hoặc destination port 8080:

- `TEST_TX`: source IP là IP ESP32.
- `TEST_RX`: destination IP là IP ESP32.

Các gói khớp được gom thành hai tập dữ liệu. Với mỗi chiều, script tạo bảng chi tiết và bảng tổng hợp theo `Kich_Thuoc_Bytes`; thống kê gồm số lần thu, nhỏ nhất, lớn nhất, trung bình và độ lệch chuẩn của `Do_Tre_us`.

Việc nhận diện hiện giả định frame có Ethernet header 14 byte, EtherType IPv4 tại offset cố định và IPv4 header không có option (UDP header ở offset cố định). Đây là bộ lọc đơn giản cho kịch bản thử nghiệm hiện tại, không phải bộ phân tích IP tổng quát. VLAN, IPv6, IPv4 options hoặc frame có định dạng khác có thể không được nhận diện đúng. Bản thân Wireshark vẫn nhận luồng PCAP độc lập với logic lọc CSV của script.

## File kết quả

Các file được ghi vào thư mục làm việc hiện tại khi chạy script:

| File | Nội dung |
|---|---|
| `hook_latency_test_tx_raw.csv` | Từng gói được phân loại TEST_TX |
| `hook_latency_test_tx_summary.csv` | Thống kê TEST_TX theo kích thước frame |
| `hook_latency_test_rx_raw.csv` | Từng gói được phân loại TEST_RX |
| `hook_latency_test_rx_summary.csv` | Thống kê TEST_RX theo kích thước frame |

File raw có các cột `STT`, `Kich_Thuoc_Bytes`, `Thoi_Gian_Sec`, `Do_Tre_us`. File summary có số lần thu, min/max, trung bình và độ lệch chuẩn. CSV được xuất với mã hóa UTF-8 có BOM để thuận tiện mở bằng Excel. Nếu file đang mở và bị khóa, hãy đóng ứng dụng đang sử dụng file rồi chạy lại.

Các file CSV đang có sẵn trong repository là kết quả của một lần chạy trước; chạy script sẽ ghi đè các file trùng tên.

## Cấu trúc repository

```text
.
├── CMakeLists.txt              # Khai báo project ESP-IDF
├── README.md
├── esp32_wireshark.py          # Đọc UART, mở Wireshark, xuất thống kê
├── main/
│   ├── CMakeLists.txt          # Component và linker wrappers
│   └── test_esp_main.c         # Firmware ESP32
├── sdkconfig                   # Cấu hình ESP-IDF hiện tại
└── hook_latency_test_*.csv     # Kết quả mẫu/đã xuất
```

Thư mục `build/` chứa sản phẩm build cục bộ và thường không cần đưa vào tài liệu hoặc quản lý phiên bản.

## Giới hạn và lưu ý khi diễn giải kết quả

- Frame bị bỏ nếu buffer không hợp lệ, độ dài dưới 14 byte hoặc lớn hơn 2000 byte, không cấp phát được heap, queue đầy hoặc tốc độ UART không theo kịp.
- `malloc()` được gọi cho mỗi frame; tải cao có thể tăng áp lực và phân mảnh heap.
- Queue send không chờ để tránh chặn đường mạng, đổi lại frame có thể mất mà hiện không có bộ đếm drop trong báo cáo.
- UART 921600 baud có băng thông hữu hạn; capture đầy đủ không được đảm bảo khi tải lớn.
- Đoạn thời gian được ghi là thời gian xử lý phần kiểm tra/cấp phát/sao chép trong `capture()`. Nó không đo toàn bộ độ trễ của Wi-Fi, IP stack, UDP, hay thời gian từ đầu-cuối giữa PC và ESP32.
- Tham số `dir` được truyền vào `capture()` nhưng hiện không được lưu trong packet hoặc PCAP. Script phân loại bằng địa chỉ IP và port, nên gói không thuộc kịch bản UDP thử nghiệm không xuất hiện trong CSV dù có thể được hiển thị trên Wireshark.
- Dữ liệu frame được gửi nguyên dạng qua UART và có thể chứa thông tin nhạy cảm. Chỉ capture trên thiết bị/mạng bạn được phép kiểm tra.
- Các hook dựa trên symbol nội bộ ESP-IDF, không phải API ổn định giữa mọi phiên bản.

## Xử lý sự cố

| Hiện tượng | Kiểm tra |
|---|---|
| Script không mở được COM | Đóng serial monitor/terminal khác, xác nhận đúng cổng và quyền truy cập |
| Không tìm thấy PCAP header | Kiểm tra board đã chạy firmware, đúng baud 921600 và UART0 không bị log/thiết bị khác chiếm dụng |
| Wireshark không mở | Kiểm tra `WIRESHARK_PATH` và cài đặt Wireshark |
| Không có TEST_TX | Đảm bảo `TARGET_IP` là IP máy tính, máy tính đang cùng mạng và port 8080 không bị firewall chặn |
| Không có TEST_RX | Đảm bảo ESP32 đã kết nối Wi-Fi với IP 172.20.10.10; kiểm tra máy tính gửi được đến ESP32 và firewall/mạng cho phép UDP |
| Có PCAP trong Wireshark nhưng CSV trống | Gói có thể không phải IPv4/UDP port 8080 hoặc không khớp các giả định offset của bộ lọc |
| Wireshark báo frame/packet lỗi | Đảm bảo UART chỉ mang PCAP, không chạy monitor chung UART và baud/script đúng cấu hình |
| CSV không ghi được | Đóng file trong Excel hoặc ứng dụng khác rồi chạy lại |

## Giấy phép và phạm vi sử dụng

Chưa có tệp giấy phép trong repository. Hãy xác định và thêm giấy phép phù hợp nếu dự án được phân phối công khai.

