
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

# Giới hạn dữ liệu đầu vào
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB


@app.route("/")
def index():
    """Trang chủ SafeGuard AI."""
    return render_template("index.html")


@app.route("/check-contract", methods=["POST"])
def check_contract():
    """Tiếp nhận nội dung hợp đồng thuê trọ."""

    content = request.form.get("content", "").strip()

    if not content:
        return jsonify({
            "success": False,
            "message": "Vui lòng nhập nội dung hợp đồng."
        }), 400

    # TODO: Gọi hàm phân tích từ main.py

    return jsonify({
        "success": True,
        "type": "contract",
        "message": "Đã tiếp nhận hợp đồng."
    })


@app.route("/check-message", methods=["POST"])
def check_message():
    """Tiếp nhận nội dung tin nhắn."""

    content = request.form.get("content", "").strip()

    if not content:
        return jsonify({
            "success": False,
            "message": "Vui lòng nhập nội dung tin nhắn."
        }), 400

    # TODO: Gọi hàm phân tích từ main.py

    return jsonify({
        "success": True,
        "type": "message",
        "message": "Đã tiếp nhận tin nhắn."
    })


@app.route("/check-link", methods=["POST"])
def check_link():
    """Tiếp nhận đường link cần kiểm tra."""

    url = request.form.get("url", "").strip()

    if not url:
        return jsonify({
            "success": False,
            "message": "Vui lòng nhập đường link."
        }), 400

    # TODO: Gọi hàm phân tích từ main.py

    return jsonify({
        "success": True,
        "type": "link",
        "message": "Đã tiếp nhận đường link."
    })


if __name__ == "__main__":
    app.run(debug=True)

