"""
SafeGuard AI - Unit Tests cho Core Logic (main.py)
Phụ trách: Kiên Phạm (KP)
Jira: N2SA-7, N2SA-8
Chạy kiểm thử: python -m unittest test_main.py -v
"""

import unittest
from main import (
    SafeGuardAnalyzer,
    analyze_content,
    analyze_contract_text,
    analyze_link_url,
    analyze_message_text,
)


class TestSafeGuardAnalyzer(unittest.TestCase):
    """Bộ test kiểm chứng phân loại rủi ro (N2SA-7), gợi ý xử lý (N2SA-8) và chuẩn JSON cho app.py."""

    def test_empty_input_returns_error(self) -> None:
        result = analyze_contract_text("   ")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["type"], "contract")
        self.assertEqual(result["risk_level"], "Không xác định")
        self.assertEqual(result["warning_count"], 0)

    def test_invalid_input_type_returns_error(self) -> None:
        result = analyze_content("Nội dung bất kỳ", input_type="video")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")

    def test_high_risk_contract_and_warning_sorting(self) -> None:
        text = (
            "Phòng trọ giá rẻ nhiều người đang hỏi chốt gấp, yêu cầu cọc giữ chỗ 2 triệu trước khi xem phòng. "
            "Không cần ký hợp đồng, không hoàn lại cọc trong mọi trường hợp."
        )
        result = analyze_contract_text(text)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "contract")
        self.assertEqual(result["risk_level"], "Cao")
        self.assertGreaterEqual(result["risk_score"], 65)
        self.assertGreaterEqual(result["warning_count"], 3)
        self.assertTrue(len(result["recommendations"]) >= 2)

        # Kiểm tra cảnh báo được sắp xếp giảm dần theo mức độ: Cao -> Trung bình -> Thấp
        severity_ranks = [
            SafeGuardAnalyzer.SEVERITY_ORDER[w["severity"]] for w in result["warnings"]
        ]
        self.assertEqual(severity_ranks, sorted(severity_ranks, reverse=True))

    def test_safe_contract_low_risk(self) -> None:
        text = (
            "Hợp đồng thuê phòng trọ thời hạn 12 tháng, giá thuê 3 triệu/tháng, "
            "tiền điện 3.500đ/kWh, hoàn cọc khi báo trước 30 ngày."
        )
        result = analyze_contract_text(text)

        self.assertTrue(result["success"])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Thấp")
        self.assertEqual(result["warning_count"], 0)
        self.assertTrue(len(result["recommendations"]) >= 2)

    def test_high_risk_message_with_embedded_apk_link(self) -> None:
        msg = (
            "Công an thông báo bạn liên quan điều tra rửa tiền, yêu cầu cập nhật VNeID qua đường dẫn "
            "http://vneid-xacminh.xyz/capnhat.apk và cung cấp mã OTP ngay."
        )
        result = analyze_message_text(msg)
        codes = {w["code"] for w in result["warnings"]}

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "message")
        self.assertEqual(result["risk_level"], "Cao")
        self.assertEqual(result["risk_score"], 100)
        self.assertIn("MSG_ASK_OTP_OR_PASSWORD", codes)
        self.assertIn("MSG_IMPERSONATE_AUTHORITY", codes)
        self.assertIn("LINK_BRAND_IMPERSONATION", codes)
        self.assertIn("LINK_APK_DOWNLOAD", codes)

        # Đảm bảo không có cảnh báo trùng mã và không có gợi ý trùng câu
        raw_codes = [w["code"] for w in result["warnings"]]
        self.assertEqual(len(raw_codes), len(set(raw_codes)))
        self.assertEqual(len(result["recommendations"]), len(set(result["recommendations"])))

    def test_medium_risk_message(self) -> None:
        msg = "Bạn ơi cho mình mượn 2 triệu gấp tí trả nhé."
        result = analyze_message_text(msg)
        codes = {w["code"] for w in result["warnings"]}

        self.assertTrue(result["success"])
        self.assertEqual(result["risk_level"], "Trung bình")
        self.assertEqual(result["risk_score"], 30)
        self.assertIn("MSG_BORROW_MONEY_URGENT", codes)

    def test_safe_message_low_risk(self) -> None:
        msg = "Chiều nay 3 giờ nhóm mình họp ở thư viện làm bài tập nhé."
        result = analyze_message_text(msg)

        self.assertTrue(result["success"])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Thấp")
        self.assertEqual(result["warning_count"], 0)

    def test_phishing_link_impersonation(self) -> None:
        result = analyze_link_url("http://vcb-xacminh.xyz/login")
        codes = {w["code"] for w in result["warnings"]}

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "link")
        self.assertEqual(result["risk_level"], "Cao")
        self.assertIn("LINK_BRAND_IMPERSONATION", codes)
        self.assertIn("LINK_SUSPICIOUS_TLD", codes)
        self.assertIn("LINK_NO_HTTPS", codes)

    def test_official_bank_domain_not_flagged(self) -> None:
        result = analyze_link_url("https://www.vietcombank.com.vn/ca-nhan")

        self.assertTrue(result["success"])
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Thấp")
        self.assertEqual(result["warning_count"], 0)

    def test_shortened_and_raw_ip_apk_links(self) -> None:
        short_res = analyze_link_url("https://bit.ly/khuyen-mai-123")
        self.assertIn("LINK_SHORTENED", {w["code"] for w in short_res["warnings"]})

        ip_res = analyze_link_url("http://192.168.1.10/dichvucong.apk")
        ip_codes = {w["code"] for w in ip_res["warnings"]}
        self.assertEqual(ip_res["risk_level"], "Cao")
        self.assertIn("LINK_RAW_IP", ip_codes)
        self.assertIn("LINK_APK_DOWNLOAD", ip_codes)

    def test_json_keys_compatible_with_app_py(self) -> None:
        result = analyze_contract_text("Hợp đồng thuê phòng minh bạch.")
        required_keys = {
            "success",
            "status",
            "type",
            "message",
            "risk_score",
            "risk_level",
            "warning_count",
            "warnings",
            "recommendations",
        }
        self.assertTrue(required_keys.issubset(result.keys()))


if __name__ == "__main__":
    unittest.main()