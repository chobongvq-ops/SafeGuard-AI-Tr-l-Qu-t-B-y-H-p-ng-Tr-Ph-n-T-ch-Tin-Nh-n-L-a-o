"""
SafeGuard AI - Core Risk Analysis Engine (main.py)
Phụ trách: Kiên Phạm (KP)
Jira:
- N2SA-7: Mở rộng nhận diện rủi ro, tính điểm và sắp xếp cảnh báo theo mức độ.
- N2SA-8: Sinh gợi ý xử lý chi tiết theo từng dấu hiệu và đồng bộ JSON với app.py.
"""

from datetime import datetime
import re
from typing import Any, Dict, List
from urllib.parse import urlparse


class SafeGuardAnalyzer:
    """
    Lớp xử lý logic cốt lõi cho hệ thống SafeGuard AI.
    Hỗ trợ 3 loại đầu vào: 'contract' (hợp đồng), 'message' (tin nhắn), 'link' (đường dẫn).
    """

    SUPPORTED_TYPES = {"contract", "message", "link"}
    SEVERITY_ORDER = {"Cao": 3, "Trung bình": 2, "Thấp": 1}

    def __init__(self) -> None:
        """
        Khởi tạo bộ quy tắc phát hiện rủi ro (N2SA-7) và bảng gợi ý xử lý (N2SA-8).
        """
        self.contract_rules: List[Dict[str, Any]] = [
            {
                "code": "CONTRACT_DEPOSIT_BEFORE_VIEW",
                "title": "Yêu cầu đặt cọc trước khi xem phòng",
                "detail": "Nội dung hối thúc chuyển tiền cọc/giữ chỗ trước khi kiểm tra phòng thực tế.",
                "severity": "Cao",
                "weight": 45,
                "patterns": [
                    r"cọc\s*(trước|giữ\s*chỗ|giữ\s*phòng)",
                    r"chuyển\s*(khoản|tiền)\s*trước\s*khi\s*xem",
                    r"giữ\s*phòng.*(cọc|chuyển\s*khoản)",
                ],
            },
            {
                "code": "CONTRACT_NO_REFUND_TRAP",
                "title": "Điều khoản mất cọc bất thường",
                "detail": "Hợp đồng quy định không hoàn cọc hoặc phạt cọc một chiều, thiếu minh bạch.",
                "severity": "Cao",
                "weight": 35,
                "patterns": [
                    r"không\s*hoàn\s*(lại\s*)?(tiền\s*)?cọc",
                    r"mất\s*(toàn\s*bộ\s*)?cọc\s*trong\s*mọi\s*trường\s*hợp",
                    r"bỏ\s*cọc.*chịu\s*phạt\s*gấp",
                ],
            },
            {
                "code": "CONTRACT_INFORMAL_NO_PAPER",
                "title": "Né tránh ký hợp đồng giấy hoặc xác minh danh tính",
                "detail": "Dấu hiệu giao dịch miệng, không cho xem CCCD/giấy tờ chủ nhà hoặc nhận tiền qua tài khoản người lạ.",
                "severity": "Cao",
                "weight": 40,
                "patterns": [
                    r"không\s*cần\s*(ký\s*)?hợp\s*đồng",
                    r"thỏa\s*thuận\s*miệng",
                    r"chuyển\s*(khoản|tiền)\s*(vào|qua)\s*(stk|tài\s*khoản)\s*(người\s*nhà|bạn|khác\s*tên)",
                ],
            },
            {
                "code": "CONTRACT_UNFAIR_TERMINATION",
                "title": "Điều khoản chấm dứt hợp đồng bất lợi cho người thuê",
                "detail": "Chủ nhà có quyền lấy lại phòng hoặc tăng giá đột ngột mà không cần báo trước.",
                "severity": "Trung bình",
                "weight": 25,
                "patterns": [
                    r"(đơn\s*phương\s*chấm\s*dứt|lấy\s*lại\s*phòng|đuổi).*không\s*(cần\s*)?báo\s*trước",
                    r"tăng\s*giá\s*(phòng|thuê)\s*bất\s*cứ\s*lúc\s*nào",
                ],
            },
            {
                "code": "CONTRACT_URGENCY_PRESSURE",
                "title": "Tạo áp lực chốt gấp bằng giá rẻ bất thường",
                "detail": "Chiêu trò thường gặp nhằm khiến sinh viên/người thuê chuyển cọc vội vàng khi chưa xác minh.",
                "severity": "Trung bình",
                "weight": 20,
                "patterns": [
                    r"nhiều\s*người\s*(đang\s*)?(hỏi|xem).*chốt\s*gấp",
                    r"ưu\s*tiên\s*ai\s*(cọc|chuyển\s*khoản)\s*trước",
                    r"chốt\s*ngay\s*trong\s*(hôm\s*nay|\d+\s*giờ)",
                ],
            },
            {
                "code": "CONTRACT_VAGUE_FEE",
                "title": "Chi phí điện nước / phụ phí không rõ ràng",
                "detail": "Thiếu đơn giá cố định hoặc để mở khả năng thu thêm phí dịch vụ tùy ý.",
                "severity": "Thấp",
                "weight": 15,
                "patterns": [
                    r"phí\s*(phát\s*sinh|dịch\s*vụ)\s*theo\s*(chủ\s*nhà|thực\s*tế\s*không\s*cố\s*định)",
                    r"giá\s*(điện|nước).*thỏa\s*thuận\s*sau",
                    r"phụ\s*thu\s*khác\s*do\s*bên\s*a\s*quyết\s*định",
                ],
            },
        ]

        self.message_rules: List[Dict[str, Any]] = [
            {
                "code": "MSG_ASK_OTP_OR_PASSWORD",
                "title": "Yêu cầu cung cấp mã OTP, mật khẩu hoặc mã thẻ",
                "detail": "Ngân hàng và tổ chức uy tín không bao giờ yêu cầu người dùng đọc hoặc gửi mã OTP/mật khẩu/CVV.",
                "severity": "Cao",
                "weight": 50,
                "patterns": [
                    r"(gửi|cung\s*cấp|nhập|đọc)\s*(mã\s*)?(otp|pin|cvv)",
                    r"mật\s*khẩu\s*(ngân\s*hàng|tài\s*khoản|app)",
                ],
            },
            {
                "code": "MSG_IMPERSONATE_AUTHORITY",
                "title": "Dấu hiệu giả danh cơ quan công an, VNeID hoặc đơn vị nhà nước",
                "detail": "Kẻ gian thường mạo danh công an, tòa án, thuế, điện lực yêu cầu cập nhật VNeID hoặc chuyển tiền xác minh.",
                "severity": "Cao",
                "weight": 45,
                "patterns": [
                    r"(công\s*an|viện\s*kiểm\s*sát|tòa\s*án).*(lệnh\s*bắt|điều\s*tra|rửa\s*tiền|chuyển\s*tiền)",
                    r"(cập\s*nhật|đồng\s*bộ|kích\s*hoạt)\s*vneid.*(link|app|đường\s*dẫn)",
                    r"(cắt\s*điện|nợ\s*thuế|phạt\s*nguội).*(chuyển\s*khoản|xác\s*minh\s*ngay)",
                ],
            },
            {
                "code": "MSG_ASK_INSTALL_APK",
                "title": "Yêu cầu tải file cài đặt (.apk) ngoài kho ứng dụng",
                "detail": "Cài ứng dụng từ file .apk hoặc đường link lạ có nguy cơ bị chiếm quyền điều khiển điện thoại và rút sạch tiền.",
                "severity": "Cao",
                "weight": 45,
                "patterns": [
                    r"(tải|cài\s*đặt).*\.(apk|exe)",
                    r"cài\s*(app|ứng\s*dụng).*(link|trình\s*duyệt|ngoài\s*ch\s*play)",
                ],
            },
            {
                "code": "MSG_URGENT_ACCOUNT_LOCK",
                "title": "Đe dọa khóa tài khoản hoặc tạo áp lực thời gian",
                "detail": "Tin nhắn cố tình gây hoảng loạn để nạn nhân thao tác vội vàng mà không kịp kiểm chứng.",
                "severity": "Cao",
                "weight": 40,
                "patterns": [
                    r"(tài\s*khoản|thẻ|ví).*(bị\s*khóa|tạm\s*ngưng|đóng\s*băng)",
                    r"(xác\s*minh|cập\s*nhật)\s*ngay\s*trong\s*\d+\s*(giờ|phút)",
                    r"hủy\s*giao\s*dịch\s*tại\s*(link|đây)",
                ],
            },
            {
                "code": "MSG_EASY_MONEY_SCAM",
                "title": "Dấu hiệu lừa đảo việc nhẹ lương cao / trúng thưởng",
                "detail": "Hứa hẹn hoa hồng cao bất thường, làm nhiệm vụ nạp tiền hoặc yêu cầu đóng phí nhận thưởng.",
                "severity": "Trung bình",
                "weight": 35,
                "patterns": [
                    r"việc\s*nhẹ\s*lương\s*cao",
                    r"(làm\s*nhiệm\s*vụ|cộng\s*tác\s*viên).*(hoa\s*hồng|nạp\s*tiền)",
                    r"chúc\s*mừng.*trúng\s*thưởng",
                    r"lãi\s*suất\s*cao.*cam\s*kết\s*không\s*rủi\s*ro",
                ],
            },
            {
                "code": "MSG_BORROW_MONEY_URGENT",
                "title": "Dấu hiệu giả mạo người quen nhắn mượn tiền gấp",
                "detail": "Yêu cầu chuyển khoản gấp hoặc nhờ chuyển hộ tiền vào số tài khoản mang tên người lạ.",
                "severity": "Trung bình",
                "weight": 30,
                "patterns": [
                    r"(mượn|vay|chuyển\s*giúp|chuyển\s*hộ).*(gấp|tí\s*trả|lát\s*trả)",
                    r"chuyển\s*vào\s*(stk|tài\s*khoản)\s*(này|bạn\s*mình).*gấp",
                ],
            },
        ]

        # Danh sách phục vụ kiểm tra đường dẫn (link)
        self.shortener_domains = {
            "bit.ly", "tinyurl.com", "t.co", "bom.so", "rb.gy", "is.gd", "shorturl.at", "s.net.vn"
        }
        self.suspicious_tlds = (
            ".xyz", ".top", ".click", ".tk", ".ml", ".vip", ".cc", ".buzz", ".site", ".online"
        )
        self.brand_keywords = {
            "vietcombank", "vcb", "techcombank", "mbbank", "bidv", "agribank",
            "vpbank", "tpbank", "vietinbank", "sacombank", "momo", "zalopay",
            "vneid", "dichvucong", "congan", "evn",
        }
        self.official_domains = {
            "vietcombank.com.vn", "techcombank.com", "techcombank.com.vn",
            "mbbank.com.vn", "bidv.com.vn", "agribank.com.vn", "vpbank.com.vn",
            "tpb.vn", "vietinbank.vn", "sacombank.com.vn", "momo.vn",
            "zalopay.vn", "vneid.gov.vn", "dichvucong.gov.vn", "bocongan.gov.vn",
            "evn.com.vn",
        }

        # Gợi ý xử lý chi tiết theo từng mã cảnh báo (N2SA-8)
        self.warning_advice_map: Dict[str, str] = {
            "CONTRACT_DEPOSIT_BEFORE_VIEW": "Tuyệt đối không chuyển tiền cọc giữ chỗ khi chưa trực tiếp xem phòng và xác minh người cho thuê.",
            "CONTRACT_NO_REFUND_TRAP": "Yêu cầu sửa lại điều khoản hoàn cọc rõ ràng (trường hợp được nhận lại cọc và thời hạn báo trước) trước khi ký.",
            "CONTRACT_INFORMAL_NO_PAPER": "Chỉ ký hợp đồng giấy có đủ chữ ký hai bên, đối chiếu CCCD của chủ trọ và chỉ chuyển tiền vào tài khoản chính chủ.",
            "CONTRACT_UNFAIR_TERMINATION": "Đề nghị bổ sung điều khoản cả hai bên phải báo trước tối thiểu 30 ngày nếu chấm dứt hợp đồng hoặc điều chỉnh giá.",
            "CONTRACT_URGENCY_PRESSURE": "Không để bị thúc ép chuyển tiền vội; hãy kiểm tra giá mặt bằng khu vực và hỏi cư dân xung quanh.",
            "CONTRACT_VAGUE_FEE": "Yêu cầu ghi cụ thể đơn giá điện, nước, internet, gửi xe và các phụ phí cố định trực tiếp vào hợp đồng.",
            "MSG_ASK_OTP_OR_PASSWORD": "Không gửi mã OTP/mật khẩu cho bất kỳ ai. Nếu đã lỡ cung cấp, hãy khóa thẻ và đổi mật khẩu ngân hàng ngay lập tức.",
            "MSG_IMPERSONATE_AUTHORITY": "Cơ quan công an/nhà nước không làm việc qua tin nhắn hay yêu cầu chuyển tiền xác minh; hãy liên hệ trực tiếp công an địa phương nếu cần kiểm chứng.",
            "MSG_ASK_INSTALL_APK": "Tuyệt đối không tải hay cài file .apk từ link lạ. Nếu lỡ cài, hãy ngắt Wi-Fi/4G, gỡ ứng dụng và mang máy đi kiểm tra bảo mật.",
            "MSG_URGENT_ACCOUNT_LOCK": "Không bấm vào liên kết trong tin nhắn; hãy mở ứng dụng ngân hàng chính thức hoặc gọi số tổng đài in trên mặt sau thẻ để kiểm tra.",
            "MSG_EASY_MONEY_SCAM": "Không nạp tiền làm nhiệm vụ, không đóng phí nhận thưởng và chặn ngay tài khoản gửi tin nhắn.",
            "MSG_BORROW_MONEY_URGENT": "Gọi video trực tiếp qua số điện thoại thông thường để xác nhận giọng nói và khuôn mặt trước khi chuyển tiền cho người quen.",
            "LINK_BRAND_IMPERSONATION": "Đường dẫn có dấu hiệu giả mạo thương hiệu lớn; tự gõ địa chỉ website chính thức trên trình duyệt thay vì bấm vào link này.",
            "LINK_APK_DOWNLOAD": "Không tải tệp cài đặt từ đường dẫn nghi ngờ để tránh mã độc đánh cắp tài khoản.",
            "LINK_NO_HTTPS": "Tránh nhập mật khẩu, số thẻ hay thông tin cá nhân trên trang web không có mã hóa HTTPS.",
            "LINK_SHORTENED": "Không bấm trực tiếp vào link rút gọn không rõ nguồn gốc; hãy kiểm tra đích đến trước khi truy cập.",
            "LINK_SUSPICIOUS_TLD": "Cảnh giác cao với tên miền dùng hậu tố lạ và không đăng nhập tài khoản tại trang này.",
            "LINK_RAW_IP": "Thoát ngay trang web dùng địa chỉ IP thô vì các dịch vụ chính thống luôn dùng tên miền rõ ràng.",
            "LINK_OBFUSCATED_URL": "Đường dẫn có cấu trúc bất thường nhằm đánh lừa người xem; tuyệt đối không truy cập.",
        }

    # =========================================================================
    # NHÓM 1: PHÂN TÍCH NỘI DUNG ĐẦU VÀO (PHỤC VỤ N2SA-7)
    # =========================================================================

    def _scan_with_rules(self, text: str, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Quét văn bản theo bộ quy tắc regex, trả về danh sách cảnh báo kèm cụm từ khớp.
        """
        warnings: List[Dict[str, Any]] = []
        normalized_text = text.lower()

        for rule in rules:
            matched_phrase = ""
            for pattern in rule["patterns"]:
                match = re.search(pattern, normalized_text)
                if match:
                    matched_phrase = match.group(0)
                    break

            if matched_phrase:
                warnings.append(
                    {
                        "code": rule["code"],
                        "title": rule["title"],
                        "detail": rule["detail"],
                        "severity": rule["severity"],
                        "weight": rule["weight"],
                        "matched_text": matched_phrase,
                    }
                )
        return warnings

    def _deduplicate_and_sort_warnings(self, warnings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Loại bỏ cảnh báo trùng mã (giữ bản đầu tiên) và sắp xếp theo mức độ giảm dần: Cao -> Trung bình -> Thấp.
        """
        unique_map: Dict[str, Dict[str, Any]] = {}
        for item in warnings:
            code = item["code"]
            if code not in unique_map:
                unique_map[code] = item

        return sorted(
            unique_map.values(),
            key=lambda w: (self.SEVERITY_ORDER.get(w["severity"], 0), w.get("weight", 0)),
            reverse=True,
        )

    def _is_official_domain(self, domain: str) -> bool:
        """
        Kiểm tra tên miền có thuộc danh sách tên miền chính thức hay không (bao gồm subdomain hợp lệ).
        """
        return any(
            domain == official or domain.endswith(f".{official}")
            for official in self.official_domains
        )

    def analyze_contract(self, content: str) -> List[Dict[str, Any]]:
        """
        Phân tích nội dung hợp đồng thuê trọ tìm điều khoản rủi ro và dấu hiệu lừa đảo.
        """
        warnings = self._scan_with_rules(content, self.contract_rules)
        return self._deduplicate_and_sort_warnings(warnings)

    def analyze_message(self, content: str) -> List[Dict[str, Any]]:
        """
        Phân tích tin nhắn nghi ngờ giả mạo, lừa đảo tài chính và tự động quét các URL nhúng bên trong.
        """
        warnings = self._scan_with_rules(content, self.message_rules)

        # Tự động trích xuất và kiểm tra đường dẫn đính kèm trong tin nhắn
        urls = re.findall(r"https?://[^\s<>\"']+", content)
        for url in urls:
            warnings.extend(self.analyze_link(url))

        return self._deduplicate_and_sort_warnings(warnings)

    def analyze_link(self, url: str) -> List[Dict[str, Any]]:
        """
        Phân tích đường dẫn (URL) phát hiện link giả mạo thương hiệu, thiếu HTTPS, link rút gọn, IP thô hoặc file .apk.
        """
        warnings: List[Dict[str, Any]] = []
        cleaned_url = url.strip()

        parsed = urlparse(cleaned_url if "://" in cleaned_url else f"http://{cleaned_url}")
        netloc = parsed.netloc.lower()
        domain = netloc.split("@")[-1].split(":")[0]
        path = parsed.path.lower()

        if parsed.scheme == "http":
            warnings.append(
                {
                    "code": "LINK_NO_HTTPS",
                    "title": "Đường dẫn không sử dụng mã hóa HTTPS",
                    "detail": "Liên kết dùng giao thức HTTP không an toàn, dữ liệu nhập vào dễ bị đánh cắp.",
                    "severity": "Trung bình",
                    "weight": 25,
                    "matched_text": "http://",
                }
            )

        if "@" in netloc or domain.count("-") >= 3 or domain.count(".") >= 4:
            warnings.append(
                {
                    "code": "LINK_OBFUSCATED_URL",
                    "title": "Cấu trúc đường dẫn bất thường / che giấu tên miền",
                    "detail": f"URL '{cleaned_url}' chứa ký tự '@' hoặc nhiều phân đoạn bất thường hay dùng để lừa người đọc.",
                    "severity": "Trung bình",
                    "weight": 30,
                    "matched_text": domain or netloc,
                }
            )

        if any(domain == short_d or domain.endswith(f".{short_d}") for short_d in self.shortener_domains):
            warnings.append(
                {
                    "code": "LINK_SHORTENED",
                    "title": "Sử dụng link rút gọn che giấu đích đến",
                    "detail": "Link rút gọn có thể chuyển hướng sang trang giả mạo mà người dùng không nhìn thấy tên miền thật.",
                    "severity": "Trung bình",
                    "weight": 25,
                    "matched_text": domain,
                }
            )

        if domain.endswith(self.suspicious_tlds):
            warnings.append(
                {
                    "code": "LINK_SUSPICIOUS_TLD",
                    "title": "Đuôi tên miền có độ tin cậy thấp",
                    "detail": f"Tên miền '{domain}' dùng hậu tố thường xuyên bị lợi dụng trong các chiến dịch lừa đảo.",
                    "severity": "Cao",
                    "weight": 40,
                    "matched_text": domain,
                }
            )

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            warnings.append(
                {
                    "code": "LINK_RAW_IP",
                    "title": "Đường dẫn trỏ trực tiếp tới địa chỉ IP",
                    "detail": "Website chính thống hầu như không bao giờ yêu cầu người dùng truy cập qua địa chỉ IP thô.",
                    "severity": "Cao",
                    "weight": 45,
                    "matched_text": domain,
                }
            )

        domain_tokens = set(re.split(r"[.\-_]+", domain))
        matched_brands = domain_tokens.intersection(self.brand_keywords)
        if matched_brands and not self._is_official_domain(domain):
            brand_name = sorted(matched_brands)[0]
            warnings.append(
                {
                    "code": "LINK_BRAND_IMPERSONATION",
                    "title": "Nghi vấn giả mạo tên miền ngân hàng / cơ quan uy tín",
                    "detail": f"Tên miền '{domain}' chứa từ khóa '{brand_name}' nhưng không thuộc hệ thống tên miền chính thức.",
                    "severity": "Cao",
                    "weight": 45,
                    "matched_text": domain,
                }
            )

        if path.endswith((".apk", ".exe")):
            warnings.append(
                {
                    "code": "LINK_APK_DOWNLOAD",
                    "title": "Đường dẫn tải trực tiếp tệp cài đặt (.apk / .exe)",
                    "detail": "Nguy cơ rất cao chứa mã độc đánh cắp mã OTP và chiếm quyền điều khiển thiết bị.",
                    "severity": "Cao",
                    "weight": 45,
                    "matched_text": path,
                }
            )

        return self._deduplicate_and_sort_warnings(warnings)

    # =========================================================================
    # NHÓM 2: TÍNH ĐIỂM & PHÂN LOẠI MỨC ĐỘ RỦI RO (PHỤC VỤ N2SA-7)
    # =========================================================================

    def calculate_risk(self, warnings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tính điểm rủi ro (0 - 100) và phân loại:
        - 0 đến 29: Thấp
        - 30 đến 64: Trung bình
        - 65 đến 100: Cao
        """
        total_score = sum(item.get("weight", 0) for item in warnings)
        risk_score = min(total_score, 100)

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
        Sinh danh sách gợi ý hành động cụ thể, không trùng lặp, ưu tiên theo đúng các cảnh báo phát hiện được.
        """
        recommendations: List[str] = []

        # 1. Hành động tổng quan theo mức độ rủi ro
        if risk_level == "Cao":
            recommendations.append("Dừng ngay mọi giao dịch chuyển tiền, ký kết hoặc cung cấp thông tin cá nhân.")
        elif risk_level == "Trung bình":
            recommendations.append("Tạm dừng thao tác và kiểm chứng kỹ thông tin qua kênh chính thức trước khi tiếp tục.")
        else:
            recommendations.append("Chưa phát hiện dấu hiệu lừa đảo nổi bật, tuy nhiên vẫn nên kiểm tra kỹ thông tin đối tác.")

        # 2. Hành động chi tiết gắn với từng cảnh báo cụ thể đã phát hiện
        for warning in warnings:
            specific_advice = self.warning_advice_map.get(warning["code"])
            if specific_advice and specific_advice not in recommendations:
                recommendations.append(specific_advice)

        # 3. Gợi ý mặc định theo loại đầu vào nếu chưa có cảnh báo cụ thể nào
        if not warnings:
            if input_type == "contract":
                recommendations.append("Luôn đọc kỹ điều khoản tiền cọc, giá điện nước và đối chiếu giấy tờ chủ nhà trước khi ký.")
            elif input_type == "message":
                recommendations.append("Giữ nguyên tắc không chia sẻ mã OTP, mật khẩu hay ảnh CCCD qua tin nhắn.")
            elif input_type == "link":
                recommendations.append("Kiểm tra kỹ tên miền chính xác và biểu tượng khóa HTTPS trước khi đăng nhập.")

        return recommendations

    # =========================================================================
    # HÀM ĐIỀU PHỐI CHÍNH (ENTRY POINT CHO app.py)
    # =========================================================================

    def analyze(self, content: str, input_type: str = "message") -> Dict[str, Any]:
        """
        Hàm tổng hợp nhận đầu vào từ app.py, trả về JSON thống nhất cho giao diện và lưu lịch sử.
        Bao gồm cả nhóm khóa chuẩn của app.py ('success', 'type', 'message') và nhóm dữ liệu phân tích chi tiết.
        """
        timestamp = datetime.now().isoformat(timespec="seconds")

        if not content or not content.strip():
            error_msg = "Nội dung đầu vào đang trống. Vui lòng nhập văn bản hoặc đường dẫn cần kiểm tra."
            return {
                "success": False,
                "status": "error",
                "type": input_type,
                "input_type": input_type,
                "analyzed_at": timestamp,
                "risk_score": 0,
                "risk_level": "Không xác định",
                "warning_count": 0,
                "message": error_msg,
                "summary": error_msg,
                "warnings": [],
                "recommendations": ["Nhập nội dung hợp đồng, tin nhắn hoặc đường link để hệ thống phân tích."],
            }

        if input_type not in self.SUPPORTED_TYPES:
            error_msg = f"Loại nội dung '{input_type}' không được hỗ trợ. Chỉ chấp nhận: {sorted(self.SUPPORTED_TYPES)}."
            return {
                "success": False,
                "status": "error",
                "type": input_type,
                "input_type": input_type,
                "analyzed_at": timestamp,
                "risk_score": 0,
                "risk_level": "Không xác định",
                "warning_count": 0,
                "message": error_msg,
                "summary": error_msg,
                "warnings": [],
                "recommendations": ["Chọn đúng loại nội dung cần kiểm tra: contract, message hoặc link."],
            }

        # Điều hướng phân tích theo loại đầu vào
        if input_type == "contract":
            warnings = self.analyze_contract(content)
        elif input_type == "message":
            warnings = self.analyze_message(content)
        else:
            warnings = self.analyze_link(content)

        # Tính điểm và xếp loại rủi ro (N2SA-7)
        risk_info = self.calculate_risk(warnings)
        risk_score = risk_info["risk_score"]
        risk_level = risk_info["risk_level"]

        # Sinh gợi ý xử lý chi tiết (N2SA-8)
        recommendations = self.generate_recommendations(risk_level, input_type, warnings)

        if warnings:
            summary = f"Phát hiện {len(warnings)} dấu hiệu nghi ngờ — Mức độ rủi ro: {risk_level} ({risk_score}/100)."
        else:
            summary = f"Không phát hiện dấu hiệu rủi ro nổi bật — Mức độ rủi ro: {risk_level} ({risk_score}/100)."

        return {
            "success": True,
            "status": "success",
            "type": input_type,
            "input_type": input_type,
            "analyzed_at": timestamp,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "warning_count": len(warnings),
            "message": summary,
            "summary": summary,
            "warnings": warnings,
            "recommendations": recommendations,
        }


# =========================================================================
# CÁC HÀM GIAO TIẾP CHO app.py (VIỆT DUY CHỈ CẦN IMPORT VÀ GỌI)
# =========================================================================
_default_analyzer = SafeGuardAnalyzer()


def analyze_content(content: str, input_type: str = "message") -> Dict[str, Any]:
    """Hàm tổng hợp dùng chung cho cả 3 loại đầu vào."""
    return _default_analyzer.analyze(content=content, input_type=input_type)


def analyze_contract_text(content: str) -> Dict[str, Any]:
    """Hàm gọi nhanh cho route /check-contract trong app.py."""
    return _default_analyzer.analyze(content=content, input_type="contract")


def analyze_message_text(content: str) -> Dict[str, Any]:
    """Hàm gọi nhanh cho route /check-message trong app.py."""
    return _default_analyzer.analyze(content=content, input_type="message")


def analyze_link_url(url: str) -> Dict[str, Any]:
    """Hàm gọi nhanh cho route /check-link trong app.py."""
    return _default_analyzer.analyze(content=url, input_type="link")


# =========================================================================
# CHẠY THỬ CỤC BỘ (LOCAL TEST)
# =========================================================================
if __name__ == "__main__":
    import json

    sample_contract = (
        "Phòng trọ giá rẻ nhiều người đang hỏi chốt gấp, yêu cầu cọc giữ chỗ 2 triệu trước khi xem phòng. "
        "Không cần ký hợp đồng, lưu ý không hoàn lại cọc trong mọi trường hợp."
    )
    sample_message = (
        "Công an thông báo bạn liên quan điều tra rửa tiền, yêu cầu cập nhật VNeID qua đường dẫn "
        "http://vneid-xacminh.xyz/capnhat.apk và cung cấp mã OTP ngay trong 10 phút."
    )
    sample_link = "http://vcb-xacminh-baomat-nhanh.xyz/login"

    print("=== TEST 1: HỢP ĐỒNG THUÊ TRỌ ===")
    print(json.dumps(analyze_contract_text(sample_contract), ensure_ascii=False, indent=2))

    print("\n=== TEST 2: TIN NHẮN LỪA ĐẢO ===")
    print(json.dumps(analyze_message_text(sample_message), ensure_ascii=False, indent=2))

    print("\n=== TEST 3: ĐƯỜNG DẪN GIẢ MẠO ===")
    print(json.dumps(analyze_link_url(sample_link), ensure_ascii=False, indent=2))