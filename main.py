"""
SafeGuard AI - Core Risk Analysis Engine (main.py)
Phụ trách: Kiên Phạm (KP)
Jira:
- N2SA-7: Phân loại mức độ rủi ro và trả về danh sách dấu hiệu/cảnh báo.
- N2SA-8: Sinh gợi ý cách xử lý cụ thể và chuẩn hóa kết quả trả về cho app.py.
"""

from datetime import datetime
import re
from typing import Any, Dict, List
from urllib.parse import urlparse


class SafeGuardAnalyzer:
    """
    Lớp xử lý logic cốt lõi cho hệ thống SafeGuard AI.
    Hỗ trợ phân tích 3 loại đầu vào: 'contract' (hợp đồng), 'message' (tin nhắn), 'link' (đường dẫn).
    """

    # Các loại đầu vào hợp lệ được hệ thống hỗ trợ
    SUPPORTED_TYPES = {"contract", "message", "link"}

    def __init__(self) -> None:
        """
        Khởi tạo bộ quy tắc (rule-based) cơ bản cho giai đoạn đầu.
        Mỗi quy tắc gồm: mã cảnh báo, tiêu đề, mô tả chi tiết, mức độ, trọng số điểm và từ khóa mẫu.
        """
        self.contract_rules: List[Dict[str, Any]] = [
            {
                "code": "CONTRACT_DEPOSIT_BEFORE_VIEW",
                "title": "Yêu cầu đặt cọc trước khi xem phòng",
                "detail": "Có dấu hiệu yêu cầu chuyển tiền giữ chỗ/cọc trước khi đến xem phòng thực tế.",
                "severity": "Cao",
                "weight": 45,
                "patterns": [
                    r"cọc\s*(trước|giữ\s*chỗ)",
                    r"chuyển\s*khoản\s*trước\s*khi\s*xem",
                    r"giữ\s*phòng.*cọc",
                ],
            },
            {
                "code": "CONTRACT_NO_REFUND_TRAP",
                "title": "Điều khoản mất cọc bất thường",
                "detail": "Hợp đồng chứa điều khoản không hoàn cọc hoặc phạt cọc thiếu minh bạch.",
                "severity": "Trung bình",
                "weight": 30,
                "patterns": [
                    r"không\s*hoàn\s*(lại\s*)?cọc",
                    r"mất\s*cọc\s*trong\s*mọi\s*trường\s*hợp",
                ],
            },
            {
                "code": "CONTRACT_VAGUE_FEE",
                "title": "Chi phí điện nước/phí phụ thu không rõ ràng",
                "detail": "Thiếu đơn giá cố định hoặc có dấu hiệu thu phí dịch vụ bất hợp lý.",
                "severity": "Thấp",
                "weight": 15,
                "patterns": [
                    r"phí\s*phát\s*sinh\s*theo\s*chủ\s*nhà",
                    r"giá\s*điện.*thỏa\s*thuận\s*sau",
                ],
            },
        ]

        self.message_rules: List[Dict[str, Any]] = [
            {
                "code": "MSG_ASK_OTP_OR_PASSWORD",
                "title": "Yêu cầu cung cấp mã OTP hoặc mật khẩu",
                "detail": "Tổ chức uy tín và ngân hàng không bao giờ yêu cầu người dùng gửi mã OTP/mật khẩu.",
                "severity": "Cao",
                "weight": 50,
                "patterns": [
                    r"(gửi|cung\s*cấp|nhập)\s*(mã\s*)?otp",
                    r"mật\s*khẩu\s*(ngân\s*hàng|tài\s*khoản)",
                ],
            },
            {
                "code": "MSG_URGENT_ACCOUNT_LOCK",
                "title": "Đe dọa khóa tài khoản hoặc tạo áp lực thời gian",
                "detail": "Kẻ lừa đảo thường gây hoảng loạn để nạn nhân thao tác vội vàng.",
                "severity": "Cao",
                "weight": 40,
                "patterns": [
                    r"(tài\s*khoản|thẻ).*(bị\s*khóa|tạm\s*ngưng)",
                    r"xác\s*minh\s*ngay\s*trong\s*\d+\s*(giờ|phút)",
                ],
            },
            {
                "code": "MSG_EASY_MONEY_SCAM",
                "title": "Dấu hiệu lừa đảo tài chính / việc nhẹ lương cao",
                "detail": "Hứa hẹn lợi nhuận cao bất thường, làm nhiệm vụ nhận hoa hồng hoặc trúng thưởng.",
                "severity": "Trung bình",
                "weight": 35,
                "patterns": [
                    r"việc\s*nhẹ\s*lương\s*cao",
                    r"làm\s*nhiệm\s*vụ.*hoa\s*hồng",
                    r"chúc\s*mừng.*trúng\s*thưởng",
                ],
            },
        ]

        # Các tên miền rút gọn hoặc đuôi tên miền hay bị lợi dụng để che giấu link lừa đảo
        self.shortener_domains = {"bit.ly", "tinyurl.com", "t.co", "bom.so", "rb.gy"}
        self.suspicious_tlds = (".xyz", ".top", ".click", ".tk", ".ml", ".vip")

    # =========================================================================
    # NHÓM 1: PHÂN TÍCH NỘI DUNG ĐẦU VÀO (PHỤC VỤ N2SA-7)
    # =========================================================================

    def _scan_with_rules(self, text: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Hàm phụ trợ: Quét văn bản theo danh sách quy tắc regex và trả về các cảnh báo khớp.
        """
        warnings: List[Dict[str, Any]] = []
        normalized_text = text.lower()

        for rule in rules:
            if any(re.search(pattern, normalized_text) for pattern in rule["patterns"]):
                warnings.append(
                    {
                        "code": rule["code"],
                        "title": rule["title"],
                        "detail": rule["detail"],
                        "severity": rule["severity"],
                        "weight": rule["weight"],
                    }
                )
        return warnings

    def analyze_contract(self, content: str) -> List[Dict[str, Any]]:
        """
        Phân tích nội dung hợp đồng thuê trọ để tìm điều khoản rủi ro hoặc dấu hiệu lừa đảo.
        TODO (giai đoạn sau): Bổ sung kiểm tra thiếu thông tin CCCD chủ nhà, địa chỉ cụ thể, hoặc tích hợp AI.
        """
        return self._scan_with_rules(content, self.contract_rules)

    def analyze_message(self, content: str) -> List[Dict[str, Any]]:
        """
        Phân tích tin nhắn/email nghi ngờ giả mạo hoặc lừa đảo tài chính.
        Ngoài kiểm tra từ khóa, còn kiểm tra xem trong tin nhắn có nhúng đường link lạ hay không.
        """
        warnings = self._scan_with_rules(content, self.message_rules)

        # Kiểm tra xem tin nhắn có chứa URL hay không
        urls = re.findall(r"https?://[^\s]+", content)
        for url in urls:
            warnings.extend(self.analyze_link(url))

        return warnings

    def analyze_link(self, url: str) -> List[Dict[str, Any]]:
        """
        Phân tích đường dẫn (URL) để phát hiện link giả mạo, thiếu bảo mật hoặc che giấu đích đến.
        """
        warnings: List[Dict[str, Any]] = []
        cleaned_url = url.strip()

        # Tự động thêm scheme nếu người dùng chỉ dán tên miền (ví dụ: vcb-xacminh.xyz)
        parsed = urlparse(cleaned_url if "://" in cleaned_url else f"http://{cleaned_url}")
        domain = parsed.netloc.lower()

        if parsed.scheme == "http":
            warnings.append(
                {
                    "code": "LINK_NO_HTTPS",
                    "title": "Đường dẫn không sử dụng mã hóa HTTPS",
                    "detail": "Liên kết dùng giao thức HTTP không an toàn, dễ bị đánh cắp dữ liệu.",
                    "severity": "Trung bình",
                    "weight": 25,
                }
            )

        if any(short_domain in domain for short_domain in self.shortener_domains):
            warnings.append(
                {
                    "code": "LINK_SHORTENED",
                    "title": "Sử dụng link rút gọn che giấu đích đến",
                    "detail": "Link rút gọn có thể chuyển hướng tới trang giả mạo mà người dùng không biết trước.",
                    "severity": "Trung bình",
                    "weight": 25,
                }
            )

        if domain.endswith(self.suspicious_tlds):
            warnings.append(
                {
                    "code": "LINK_SUSPICIOUS_TLD",
                    "title": "Đuôi tên miền có độ tin cậy thấp",
                    "detail": f"Tên miền '{domain}' dùng hậu tố thường xuất hiện trong các chiến dịch lừa đảo.",
                    "severity": "Cao",
                    "weight": 40,
                }
            )

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]):
            warnings.append(
                {
                    "code": "LINK_RAW_IP",
                    "title": "Đường dẫn trỏ trực tiếp tới địa chỉ IP",
                    "detail": "Website chính thống hiếm khi yêu cầu người dùng truy cập qua địa chỉ IP thô.",
                    "severity": "Cao",
                    "weight": 45,
                }
            )

        return warnings

    # =========================================================================
    # NHÓM 2: TÍNH ĐIỂM & PHÂN LOẠI MỨC ĐỘ RỦI RO (PHỤC VỤ N2SA-7)
    # =========================================================================

    def calculate_risk(self, warnings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tính tổng điểm rủi ro (thang 0 - 100) từ danh sách cảnh báo và xếp loại mức độ.
        Quy ước:
        - 0 đến 29: Thấp
        - 30 đến 64: Trung bình
        - 65 đến 100: Cao
        """
        total_score = sum(item.get("weight", 0) for item in warnings)
        risk_score = min(total_score, 100)  # Giới hạn tối đa là 100

        if risk_score >= 65:
            risk_level = "Cao"
        elif risk_score >= 30:
            risk_level = "Trung bình"
        else:
            risk_level = "Thấp"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    # =========================================================================
    # NHÓM 3: SINH GỢI Ý CÁCH XỬ LÝ (PHỤC VỤ N2SA-8)
    # =========================================================================

    def generate_recommendations(
        self, risk_level: str, input_type: str, warnings: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Sinh danh sách gợi ý hành động cụ thể dựa trên mức độ rủi ro và loại nội dung.
        """
        recommendations: List[str] = []

        if risk_level == "Cao":
            recommendations.append("Dừng ngay mọi giao dịch chuyển tiền hoặc cung cấp thông tin cá nhân.")
        elif risk_level == "Trung bình":
            recommendations.append("Tạm dừng thao tác và kiểm chứng lại thông tin qua kênh chính thức.")
        else:
            recommendations.append("Chưa phát hiện dấu hiệu lừa đảo rõ ràng, nhưng vẫn nên giữ cảnh giác.")

        # Bổ sung gợi ý chuyên biệt theo từng loại đầu vào
        if input_type == "contract":
            recommendations.extend(
                [
                    "Đến xem phòng trực tiếp và kiểm tra CCCD/giấy tờ sở hữu của người cho thuê.",
                    "Đọc kỹ điều khoản hoàn cọc, giá điện nước và yêu cầu ghi rõ vào hợp đồng trước khi ký.",
                ]
            )
        elif input_type == "message":
            recommendations.extend(
                [
                    "Không chia sẻ mã OTP, mật khẩu ngân hàng hay ảnh chụp CCCD qua tin nhắn.",
                    "Gọi trực tiếp số tổng đài chính thức của ngân hàng/đơn vị liên quan để xác minh.",
                ]
            )
        elif input_type == "link":
            recommendations.extend(
                [
                    "Không đăng nhập tài khoản hoặc điền thông tin thẻ vào đường dẫn nghi ngờ.",
                    "Tự gõ địa chỉ website chính thức trên trình duyệt thay vì bấm vào link nhận được.",
                ]
            )

        # Gợi ý thêm nếu phát hiện cảnh báo cụ thể
        warning_codes = {w["code"] for w in warnings}
        if "MSG_ASK_OTP_OR_PASSWORD" in warning_codes:
            recommendations.append("Nếu đã lỡ cung cấp OTP/mật khẩu, hãy khóa thẻ và đổi mật khẩu ngân hàng ngay lập tức.")

        return recommendations

    # =========================================================================
    # HÀM ĐIỀU PHỐI CHÍNH (ENTRY POINT CHO app.py)
    # =========================================================================

    def analyze(self, content: str, input_type: str = "message") -> Dict[str, Any]:
        """
        Hàm tổng hợp nhận đầu vào từ app.py, chạy phân tích và trả về JSON thống nhất.
        """
        timestamp = datetime.now().isoformat(timespec="seconds")

        # 1. Kiểm tra dữ liệu đầu vào hợp lệ
        if not content or not content.strip():
            return {
                "status": "error",
                "analyzed_at": timestamp,
                "input_type": input_type,
                "risk_score": 0,
                "risk_level": "Không xác định",
                "summary": "Nội dung đầu vào đang trống. Vui lòng nhập văn bản hoặc đường dẫn cần kiểm tra.",
                "warnings": [],
                "recommendations": ["Nhập nội dung hợp đồng, tin nhắn hoặc đường link để hệ thống phân tích."],
            }

        if input_type not in self.SUPPORTED_TYPES:
            return {
                "status": "error",
                "analyzed_at": timestamp,
                "input_type": input_type,
                "risk_score": 0,
                "risk_level": "Không xác định",
                "summary": f"Loại nội dung '{input_type}' không được hỗ trợ. Chỉ chấp nhận: {sorted(self.SUPPORTED_TYPES)}.",
                "warnings": [],
                "recommendations": ["Chọn đúng loại nội dung cần kiểm tra: contract, message hoặc link."],
            }

        # 2. Điều hướng sang hàm phân tích tương ứng
        if input_type == "contract":
            warnings = self.analyze_contract(content)
        elif input_type == "message":
            warnings = self.analyze_message(content)
        else:
            warnings = self.analyze_link(content)

        # 3. Tính điểm và xếp loại mức độ rủi ro (N2SA-7)
        risk_info = self.calculate_risk(warnings)
        risk_score = risk_info["risk_score"]
        risk_level = risk_info["risk_level"]

        # 4. Sinh gợi ý xử lý (N2SA-8)
        recommendations = self.generate_recommendations(risk_level, input_type, warnings)

        # 5. Tạo câu tóm tắt ngắn gọn cho giao diện
        if warnings:
            summary = f"Phát hiện {len(warnings)} dấu hiệu nghi ngờ — Mức độ rủi ro: {risk_level} ({risk_score}/100)."
        else:
            summary = f"Không phát hiện dấu hiệu rủi ro nổi bật — Mức độ rủi ro: {risk_level} ({risk_score}/100)."

        return {
            "status": "success",
            "analyzed_at": timestamp,
            "input_type": input_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "summary": summary,
            "warnings": warnings,
            "recommendations": recommendations,
        }


# Hàm wrapper giúp app.py (Việt Duy) gọi ngắn gọn chỉ với 1 dòng import:
# from main import analyze_content
_default_analyzer = SafeGuardAnalyzer()


def analyze_content(content: str, input_type: str = "message") -> Dict[str, Any]:
    """
    Hàm giao tiếp chính dành cho app.py gọi vào tầng logic xử lý.
    """
    return _default_analyzer.analyze(content=content, input_type=input_type)


# =========================================================================
# CHẠY THỬ CỤC BỘ (LOCAL TEST)
# =========================================================================
if __name__ == "__main__":
    import json

    sample_contract = (
        "Phòng trọ full nội thất giá rẻ, yêu cầu cọc giữ chỗ 2 triệu trước khi xem phòng. "
        "Lưu ý không hoàn lại cọc trong mọi trường hợp."
    )
    sample_message = (
        "Tài khoản ngân hàng của bạn sắp bị khóa. Vui lòng cung cấp mã OTP "
        "và xác minh ngay trong 15 phút tại http://vcb-xacminh.xyz"
    )

    print("=== KẾT QUẢ TEST HỢP ĐỒNG ===")
    print(json.dumps(analyze_content(sample_contract, "contract"), ensure_ascii=False, indent=2))

    print("\n=== KẾT QUẢ TEST TIN NHẮN ===")
    print(json.dumps(analyze_content(sample_message, "message"), ensure_ascii=False, indent=2))