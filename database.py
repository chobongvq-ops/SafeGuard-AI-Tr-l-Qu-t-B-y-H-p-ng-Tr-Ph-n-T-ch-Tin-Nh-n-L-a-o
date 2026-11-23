from contextlib import closing
from datetime import datetime
import sqlite3

# Tên cơ sở dữ liệu dùng chung cho toàn dự án SafeGuard AI
DB_NAME = "safeguard_ai.db"

VALID_CONTENT_TYPES = {"contract", "message", "financial"}
VALID_RISK_LEVELS = {"SAFE", "WARNING", "DANGER"}


def get_connection() -> sqlite3.Connection:
    """Khởi tạo kết nối SQLite và trả về Row để dễ chuyển thành dict."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# =====================================================================
# PHẦN XỬ LÝ LỊCH SỬ KIỂM TRA (Dành riêng cho Bảo Gia - Thẻ N2SA-9)
# =====================================================================
def init_history_db() -> None:
    """
    Khởi tạo bảng check_history lưu trữ lịch sử kiểm tra.
    Tách biệt hoàn toàn với bảng cấu hình từ khóa/mẫu bẫy (N2SA-11).
    """
    with closing(get_connection()) as conn:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS check_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_type TEXT NOT NULL,     -- Loại kiểm tra: 'contract', 'message', 'financial'
                    input_text TEXT NOT NULL,       -- Nội dung/Đoạn văn bản đã gửi kiểm tra
                    risk_level TEXT NOT NULL,       -- Mức rủi ro: 'SAFE', 'WARNING', 'DANGER'
                    warning_summary TEXT DEFAULT '',-- Tóm tắt các cảnh báo phát hiện được
                    created_at TEXT NOT NULL        -- Thời điểm tạo bản ghi (ISO format)
                )
                """
            )


def save_check_history(
    content_type: str,
    input_text: str,
    risk_level: str,
    warning_summary: str = "",
) -> int:
    """
    Lưu kết quả của một lần kiểm tra rủi ro vào CSDL.
    Trả về id của bản ghi vừa tạo.
    """
    normalized_type = content_type.strip().lower()
    normalized_risk = risk_level.strip().upper()

    if normalized_type not in VALID_CONTENT_TYPES:
        raise ValueError(
            f"content_type không hợp lệ: '{content_type}'. "
            f"Chỉ chấp nhận {sorted(VALID_CONTENT_TYPES)}."
        )

    if normalized_risk not in VALID_RISK_LEVELS:
        raise ValueError(
            f"risk_level không hợp lệ: '{risk_level}'. "
            f"Chỉ chấp nhận {sorted(VALID_RISK_LEVELS)}."
        )

    init_history_db()
    created_at = datetime.now().isoformat(timespec="seconds")

    with closing(get_connection()) as conn:
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO check_history (
                    content_type, input_text, risk_level, warning_summary, created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    normalized_type,
                    input_text,
                    normalized_risk,
                    warning_summary,
                    created_at,
                ),
            )
            return int(cursor.lastrowid)


def get_check_history(
    limit: int = 50,
    content_type: str | None = None,
    risk_level: str | None = None,
) -> list[dict]:
    """
    Lấy danh sách các lần kiểm tra đã lưu (mới nhất hiển thị trước).
    Hỗ trợ lọc tùy chọn theo content_type hoặc risk_level.
    """
    init_history_db()

    query = """
        SELECT id, content_type, input_text, risk_level, warning_summary, created_at
        FROM check_history
    """
    conditions: list[str] = []
    params: list[object] = []

    if content_type:
        conditions.append("content_type = ?")
        params.append(content_type.strip().lower())

    if risk_level:
        conditions.append("risk_level = ?")
        params.append(risk_level.strip().upper())

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, limit))

    with closing(get_connection()) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]
