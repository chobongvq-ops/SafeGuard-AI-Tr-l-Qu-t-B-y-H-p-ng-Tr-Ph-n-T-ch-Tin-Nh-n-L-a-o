# SafeGuard AI – Trợ Lý Quét Bẫy Hợp Đồng Trọ & Phân Tích Tin Nhắn Lừa Đảo
SafeGuard AI là hệ thống thông minh hỗ trợ sinh viên và người dùng trực tuyến nhận diện và phòng tránh rủi ro từ các bẫy hợp đồng thuê trọ lừa đảo, cũng như các tin nhắn giả mạo, lừa đảo tài chính trên không gian mạng.
## Product Backlog

| Mã thẻ | User Story | Priority | Story Points | Assignee |
| :--- | :--- | :---: | :---: | :--- |
| `N2SA-5` | Người dùng dán hoặc tải nội dung hợp đồng thuê trọ để kiểm tra điều khoản có dấu hiệu bẫy | High | 5 | Duy |
| `N2SA-6` | Người dùng dán nội dung tin nhắn hoặc đường link nghi ngờ để phát hiện dấu hiệu lừa đảo | High | 5 | Duy |
| `N2SA-7` | Người dùng xem mức độ rủi ro và danh sách câu chữ/điều khoản cảnh báo chi tiết | High | 8 | Kiên |
| `N2SA-8` | Người dùng xem gợi ý cách xử lý và lưu ý an toàn khi gặp hợp đồng/tin nhắn rủi ro | Medium | 5 | Kiên |
| `N2SA-9` | Người dùng xem lại lịch sử các lần đã kiểm tra hợp đồng và tin nhắn | Medium | 3 | Bảo Gia |
| `N2SA-10` | Người dùng thao tác trên giao diện web gọn gàng trên máy tính và điện thoại | Medium | 3 | Hoàng Anh (Nhóm trưởng) |
| `N2SA-11` | Quản trị viên cập nhật thêm từ khóa, mẫu bẫy hợp đồng và kịch bản lừa đảo mới | Low | 5 | Hoàng Anh (Nhóm trưởng) |

*Tổng ước lượng: **34 Story Points** cho 7 User Story.*
## Kiến trúc hệ thống (System Architecture)

**SafeGuard AI** được thiết kế theo mô hình hệ thống web phân tầng gọn nhẹ, hỗ trợ người dùng kiểm tra rủi ro hợp đồng thuê trọ, tin nhắn/đường dẫn nghi ngờ và xem gợi ý xử lý an toàn.

### 1. Cấu trúc thành phần chính trong repository
1. **Tầng giao diện người dùng (`templates/` & giao diện web):** Tiếp nhận nội dung/tệp hợp đồng, tin nhắn hoặc đường dẫn từ người dùng; hiển thị mức độ rủi ro, danh sách dấu hiệu bất thường, gợi ý xử lý và lịch sử kiểm tra.
2. **Tầng điều phối & xử lý (`app.py`, `main.py`):** Tiếp nhận yêu cầu từ giao diện web, điều phối luồng xử lý kiểm tra, đánh giá mức độ rủi ro, sinh gợi ý phòng tránh/xử lý và kết nối với tầng dữ liệu.
3. **Tầng dữ liệu & quy tắc (`database.py`):** Lưu trữ lịch sử các lần kiểm tra, danh mục từ khóa/mẫu bẫy hợp đồng thuê trọ, kịch bản lừa đảo và dữ liệu cấu hình phục vụ đối chiếu, cập nhật.
4. **Tài liệu & quản lý dự án (`README.md`, `requirements.txt`):** Mô tả tổng quan hệ thống, danh sách thư viện phụ thuộc, bảng Product Backlog và định hướng kiến trúc.

### 2. Luồng xử lý nghiệp vụ cơ bản
1. Người dùng nhập/dán hoặc tải nội dung hợp đồng thuê trọ, tin nhắn hoặc đường dẫn trên giao diện web.
2. Tầng ứng dụng (`app.py` / `main.py`) nhận dữ liệu đầu vào và đối chiếu với quy tắc/mẫu rủi ro/dữ liệu lưu trữ qua `database.py`.
3. Hệ thống tổng hợp kết quả gồm **mức độ rủi ro**, **các dấu hiệu/điều khoản cần lưu ý** và **gợi ý cách xử lý an toàn**, đồng thời ghi nhận vào lịch sử kiểm tra.
4. Người dùng xem kết quả trực tiếp trên giao diện và có thể tra cứu lại lịch sử kiểm tra khi cần.
