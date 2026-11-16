import socket
import struct
import subprocess
import threading
import time
import pandas as pd
import serial
from tabulate import tabulate

# ================= CẤU HÌNH HỆ THỐNG =================
COM_PORT = "COM10"               # Cổng Serial của ESP32
BAUD_RATE = 921600
ESP32_IP = "172.20.10.10"        # IP tĩnh của ESP32
UDP_PORT = 8080                  # Cổng thử nghiệm
WIRESHARK_PATH = r"C:\Program Files\Wireshark\Wireshark.exe"

ESP32_IP_BYTES = socket.inet_aton(ESP32_IP)
# =====================================================

PCAP_MAGIC = b"\xd4\xc3\xb2\xa1"
GLOBAL_HDR_SIZE = 24
PACKET_HDR_SIZE = 16
PACKET_HDR_FMT = "<IIII"

def udp_sender_thread():
    """Luồng phụ: Tự động phát dữ liệu UDP từ PC sang ESP32 (Tạo tải Test RX)"""
    time.sleep(3)
    print("\n[>>>] BẮT ĐẦU PHÁT LUỒNG UDP SANG ESP32 (TẠO TẢI TEST RX)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    test_sizes = [32, 64, 128, 256, 512, 1024, 1400]
    for size in test_sizes:
        payload = b"A" * size
        print(f"      -> Bắn 50 gói kích thước {size} bytes...")
        for _ in range(50):
            sock.sendto(payload, (ESP32_IP, UDP_PORT))
            time.sleep(0.02)
        time.sleep(0.5)
        
    sock.close()
    print("[✓] Đã hoàn thành kịch bản phát UDP từ PC.\n")

def read_exact(ser, n, proc=None):
    """Đọc chính xác n bytes từ Serial và đẩy sang Wireshark (Live Pipe)"""
    data = bytearray()
    while len(data) < n:
        chunk = ser.read(n - len(data))
        if not chunk:
            continue
        data.extend(chunk)
        if proc and proc.poll() is None:
            try:
                proc.stdin.write(chunk)
                proc.stdin.flush()
            except IOError:
                pass
    return bytes(data)

def process_stream_data(df, direction):
    """Xử lý dữ liệu thô và tạo thống kê cho một chiều (TX hoặc RX)"""
    if df is None or df.empty:
        return None, None

    # 1. Chuẩn hóa Bảng Chi tiết từng gói tin (Raw Table)
    raw_df = df.copy().reset_index(drop=True)
    raw_df["STT"] = raw_df.index + 1
    raw_df = raw_df[["STT", "orig_len", "ts_sec", "latency_us"]]
    raw_df.columns = ["STT", "Kich_Thuoc_Bytes", "Thoi_Gian_Sec", "Do_Tre_us"]

    # 2. Thống kê Gom nhóm theo Kích thước gói (Summary Table)
    summary_df = (
        raw_df.groupby("Kich_Thuoc_Bytes")["Do_Tre_us"]
        .agg(
            So_Lan_Thu="count",
            Min_us="min",
            Max_us="max",
            Trung_Binh_us="mean",
            Do_Lech_Chuan_us="std",
        )
        .reset_index()
    )
    summary_df["Trung_Binh_us"] = summary_df["Trung_Binh_us"].round(2)
    summary_df["Do_Lech_Chuan_us"] = summary_df["Do_Lech_Chuan_us"].round(2)

    return raw_df, summary_df

def export_four_tables(df_tx, df_rx):
    """Kết xuất đúng 4 Bảng dữ liệu ra Console và lưu 4 File CSV"""
    tx_raw, tx_sum = process_stream_data(df_tx, "TX")
    rx_raw, rx_sum = process_stream_data(df_rx, "RX")

    try:
        print("\n" + "=" * 85)
        print("           BÁO CÁO THỐNG KÊ CHI TIẾT VÀ TỔNG HỢP 4 BẢNG (TEST TX / RX)")
        print("=" * 85)

        # ------------------- CHIỀU TEST_TX -------------------
        if tx_raw is not None:
            tx_raw.to_csv("hook_latency_test_tx_raw.csv", index=False, encoding="utf-8-sig")
            tx_sum.to_csv("hook_latency_test_tx_summary.csv", index=False, encoding="utf-8-sig")

            print("\n[BẢNG 1] DANH SÁCH GÓI TIN CHI TIẾT CHIỀU PHÁT (TEST_TX RAW - Mẫu 10 gói đầu):")
            print(tabulate(tx_raw.head(10), headers="keys", tablefmt="grid", showindex=False))
            print(f"--> [✓] Đã lưu 100% ({len(tx_raw)} gói) vào file: hook_latency_test_tx_raw.csv")

            print("\n[BẢNG 3] BẢNG THỐNG KÊ TỔNG HỢP CHIỀU PHÁT (TEST_TX SUMMARY):")
            print(tabulate(tx_sum, headers="keys", tablefmt="grid", showindex=False))
            print("--> [✓] Đã lưu báo cáo tổng hợp vào file: hook_latency_test_tx_summary.csv")
        else:
            print("\n[-] Không có dữ liệu luồng TEST_TX.")

        # ------------------- CHIỀU TEST_RX -------------------
        if rx_raw is not None:
            rx_raw.to_csv("hook_latency_test_rx_raw.csv", index=False, encoding="utf-8-sig")
            rx_sum.to_csv("hook_latency_test_rx_summary.csv", index=False, encoding="utf-8-sig")

            print("\n[BẢNG 2] DANH SÁCH GÓI TIN CHI TIẾT CHIỀU NHẬN (TEST_RX RAW - Mẫu 10 gói đầu):")
            print(tabulate(rx_raw.head(10), headers="keys", tablefmt="grid", showindex=False))
            print(f"--> [✓] Đã lưu 100% ({len(rx_raw)} gói) vào file: hook_latency_test_rx_raw.csv")

            print("\n[BẢNG 4] BẢNG THỐNG KÊ TỔNG HỢP CHIỀU NHẬN (TEST_RX SUMMARY):")
            print(tabulate(rx_sum, headers="keys", tablefmt="grid", showindex=False))
            print("--> [✓] Đã lưu báo cáo tổng hợp vào file: hook_latency_test_rx_summary.csv")
        else:
            print("\n[-] Không có dữ liệu luồng TEST_RX.")

        print("\n" + "=" * 85 + "\n")

    except PermissionError:
        print("\n[❌ LỖI KHÓA FILE EXCEL] Không thể ghi file CSV! Hãy ĐÓNG FILE EXCEL đang mở và chạy lại.\n")
    except Exception as e:
        print(f"\n[❌ LỖI GHI FILE]: {e}")

def main():
    print(f"[+] Mở kết nối Serial {COM_PORT} ({BAUD_RATE} bps)...")
    try:
        ser = serial.Serial(COM_PORT, BAUD_RATE, timeout=1)
    except Exception as e:
        print(f"[-] Lỗi Serial: {e}")
        return

    print("[+] Đang chờ PCAP Global Header từ ESP32...")
    buffer = bytearray()
    valid_global_hdr = None

    while True:
        b = ser.read(1)
        if not b:
            continue
        buffer.extend(b)
        idx = buffer.find(PCAP_MAGIC)
        if idx != -1:
            while len(buffer) - idx < GLOBAL_HDR_SIZE:
                buffer.extend(ser.read(GLOBAL_HDR_SIZE - (len(buffer) - idx)))
            valid_global_hdr = bytes(buffer[idx : idx + GLOBAL_HDR_SIZE])
            print("[+] Tìm thấy PCAP Header! Khởi tạo Wireshark...")
            break
        if len(buffer) > 4096:
            buffer = buffer[-4:]

    cmd = [WIRESHARK_PATH, "-k", "-i", "-"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    proc.stdin.write(valid_global_hdr)
    proc.stdin.flush()

    threading.Thread(target=udp_sender_thread, daemon=True).start()

    records = []
    print("[+] Đang ghi nhận độ trễ (Lọc cứng Port 8080)... Nhấn Ctrl+C để Kết thúc.\n")

    try:
        while True:
            pkt_hdr_raw = read_exact(ser, PACKET_HDR_SIZE, proc)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(PACKET_HDR_FMT, pkt_hdr_raw)
            payload = read_exact(ser, incl_len, proc)

            # LỌC BẢN TIN TEST (IPv4 -> UDP -> PORT 8080)
            direction = None
            if len(payload) >= 42 and payload[12:14] == b"\x08\x00":
                protocol = payload[23]
                if protocol == 17:  # UDP
                    src_ip = payload[26:30]
                    dst_ip = payload[30:34]
                    src_port, dst_port = struct.unpack(">HH", payload[34:38])

                    if src_port == UDP_PORT or dst_port == UDP_PORT:
                        if src_ip == ESP32_IP_BYTES:
                            direction = "TEST_TX"
                        elif dst_ip == ESP32_IP_BYTES:
                            direction = "TEST_RX"

            if direction:
                records.append({
                    "direction": direction,
                    "orig_len": orig_len,
                    "ts_sec": ts_sec,
                    "latency_us": ts_usec
                })

    except KeyboardInterrupt:
        print("\n[!] Đã dừng thu thập dữ liệu.")

    finally:
        ser.close()
        if proc.poll() is None:
            proc.terminate()

    # ================= KẾT XUẤT 4 BẢNG ĐỘC LẬP =================
    if records:
        df = pd.DataFrame(records)
        df_tx = df[df["direction"] == "TEST_TX"].drop(columns=["direction"])
        df_rx = df[df["direction"] == "TEST_RX"].drop(columns=["direction"])
        export_four_tables(df_tx, df_rx)
    else:
        print("[-] Không bắt được bản tin test UDP Port 8080 nào.")

if __name__ == "__main__":
    main()