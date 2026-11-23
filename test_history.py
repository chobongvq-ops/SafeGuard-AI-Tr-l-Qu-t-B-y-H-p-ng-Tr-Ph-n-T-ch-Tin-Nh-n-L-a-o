from database import get_check_history, save_check_history

if __name__ == "__main__":
    print("--- 1. CHẠY THỬ HÀM LƯU LỊCH SỬ ---")
    id1 = save_check_history(
        content_type="contract",
        input_text="Hợp đồng thuê phòng trọ đặt cọc 3 tháng không hoàn trả...",
        risk_level="DANGER",
        warning_summary="Phát hiện điều khoản cọc bất hợp lý và không rõ thông tin chủ nhà.",
    )
    print(f"✅ Đã lưu bản ghi 1 với ID: {id1}")

    id2 = save_check_history(
        content_type="message",
        input_text="Anh/chị chuyển tiền gấp vào tài khoản này để nhận quà...",
        risk_level="WARNING",
        warning_summary="Tin nhắn chứa hành vi giục giã chuyển tiền nghi ngờ giả mạo.",
    )
    print(f"✅ Đã lưu bản ghi 2 với ID: {id2}")

    print("\n--- 2. CHẠY THỬ HÀM LẤY LỊCH SỬ ---")
    history = get_check_history(limit=10)
    for item in history:
        print(
            f"[{item['created_at']}] [{item['content_type'].upper()}] "
            f"- Rủi ro: {item['risk_level']}"
        )
        print(f"   Nội dung: {item['input_text'][:40]}...")
        print(f"   Cảnh báo: {item['warning_summary']}\n")
