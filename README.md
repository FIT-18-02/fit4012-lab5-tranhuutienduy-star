# FIT4012 - Lab 5: AES-128 (Trần Hữu Tiến Duy - 1871020191)

## 1. Cấu trúc repo
Dự án được tổ chức theo cấu trúc chuẩn của FIT4012 bao gồm các thành phần mã nguồn, kịch bản kiểm thử và tài liệu hướng dẫn.

## 2. Cách chạy chương trình

### Cách 1: Sử dụng Makefile
Nếu môi trường hỗ trợ make, có thể biên dịch và chạy nhanh bằng lệnh:
- Lệnh: make
- Chạy mã hóa: printf "hello FIT4012 AES\n" | ./encrypt
- Chạy giải mã: ./decrypt

### Cách 2: Biên dịch trực tiếp bằng g++
Lệnh biên dịch thủ công (chuẩn C++17):
- g++ -std=c++17 -Wall -Wextra -pedantic encrypt.cpp -o encrypt
- g++ -std=c++17 -Wall -Wextra -pedantic decrypt.cpp -o decrypt
- Sau đó chạy: echo "hello FIT4012 AES" | ./encrypt
- Và: ./decrypt

## 3. Input / Output
- Đầu vào (Input):
    - encrypt.cpp: Nhận văn bản trực tiếp từ bàn phím qua cin.getline().
    - decrypt.cpp: Tự động đọc bản mã từ file message.aes.
    - Khóa (Key): Đọc khóa 128-bit (16 byte hex) từ tệp keyfile.
- Đầu ra (Output):
    - encrypt: Hiển thị mã hex lên màn hình và ghi vào file message.aes.
    - decrypt: Giải mã và hiển thị lại văn bản gốc dưới dạng ký tự và mã hex.

## 4. Cơ chế Padding (Phần đệm)
Chương trình sử dụng Zero Padding. Nếu dữ liệu không đủ 16 byte, các byte 0x00 sẽ được thêm vào cuối khối để đảm bảo đúng kích thước 128-bit của AES.

## 5. Kiểm thử (Tests)
Hệ thống đi kèm với 5 kịch bản kiểm thử tự động trong thư mục tests/ để đảm bảo tính đúng đắn của thuật toán:
- test_aes_compile.sh
- test_encrypt_decrypt_roundtrip.sh
- test_multiblock_padding.sh
- test_tamper_negative.sh
- test_wrong_key_negative.sh

## 6. Minh chứng thực thi (Logs)
Mọi kết quả chạy thử nghiệm và thông tin log được lưu trữ tại thư mục logs/ bao gồm output khi build và chạy thành công.
## 7. Ethics & Safe use / An toàn sử dụng
Mã nguồn này được phát triển cho mục đích học tập và nghiên cứu trong khuôn khổ học phần An toàn thông tin tại Đại học Đại Nam. Tuyệt đối không sử dụng mã nguồn này cho các ứng dụng thực tế hoặc bảo mật dữ liệu nhạy cảm, vì cơ chế Zero Padding và cách quản lý khóa đơn giản trong bài thực hành này không đủ khả năng chống lại các cuộc tấn công mạng hiện đại.
