# Report 1 page - Lab 5 AES-128

## Student Information

- Full Name: Trần Hữu Tiến Duy
- Student ID:1871020191

---

## Mục tiêu

Bài thực hành giúp sinh viên hiểu quy trình mã hóa và giải mã AES-128 ở mức nhập môn, bao gồm xử lý block 128-bit, mở rộng khóa, các phép biến đổi theo vòng và cơ chế padding đơn giản.

## Cách làm / Method

Repo sử dụng 3 file mã nguồn chính: `encrypt.cpp`, `decrypt.cpp`, `structures.h`.

- `encrypt.cpp` thực hiện mã hóa plaintext và ghi ciphertext ra file `message.aes`
- `decrypt.cpp` đọc file `message.aes` để giải mã
- `structures.h` chứa S-box, inverse S-box, bảng tra cứu GF(2^8), RCon và hàm KeyExpansion

Repo được tổ chức theo starter repository của FIT4012 với:
- `Makefile`
- `CMakeLists.txt`
- thư mục `tests/`
- thư mục `logs/`
- GitHub Actions CI workflow

## Kết quả / Result

Chương trình hỗ trợ:
- AES-128 encryption
- AES-128 decryption
- zero padding cho plaintext nhiều block
- đọc khóa từ file `keyfile`
- ghi ciphertext ra file `message.aes`

Các test cơ bản trong repo gồm:
- compile test
- encrypt/decrypt roundtrip test
- multiblock padding test
- tamper negative test
- wrong key negative test

## Kết luận / Conclusion

Bài lab giúp minh họa quy trình hoạt động cơ bản của AES-128 gồm:
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey
- KeyExpansion

Ngoài ra bài lab cũng cho thấy hạn chế của cách đọc/ghi binary bằng C-style string và zero padding. Trong tương lai có thể cải tiến bằng:
- PKCS#7 padding
- binary-safe file handling
- chuẩn hóa test vector AES
- gom encrypt/decrypt vào một chương trình duy nhất

This lab repository was tested with compile, round-trip, multiblock, tamper and wrong-key scenarios.
