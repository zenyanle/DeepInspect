# api.py
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
from event_handling import attack_events, snapshot_events
from reporting import generate_markdown_report

app = Flask(__name__, static_folder='frontend/dist')
CORS(app)  # 启用 CORS 以允许前端访问


# --- API 端点 ---
@app.route('/api/events/http', methods=['GET'])
def get_http_events():
    """返回 HTTP 攻击事件的 JSON 数据"""
    return jsonify(attack_events)

@app.route('/api/events/snapshot', methods=['GET'])
def get_snapshot_events():
    """返回快照事件的 JSON 数据"""
    return jsonify(snapshot_events)

@app.route('/api/report/markdown', methods=['GET'])
def get_markdown_report():
    """返回 Markdown 格式的报告"""
    time_period = request.args.get('period', 'Demo 数据综合分析')
    markdown = generate_markdown_report(attack_events, snapshot_events, time_period, GEMINI_API_KEY) # 需要从 config 或者其他地方获取 GEMINI_API_KEY
    return jsonify({"markdown": markdown})

@app.route('/api/report/summary', methods=['GET'])
def get_report_summary():
    """返回报告摘要统计信息"""
    if not attack_events and not snapshot_events:
        return jsonify({
            "totalEvents": 0,
            "avgThreatScore": 0,
            "attackTypes": [],
            "timeline": []
        })

    # 统计数据
    total_http_events = len(attack_events)
    total_snapshot_events = len(snapshot_events)

    # 攻击类型统计
    attack_types = {}
    for event in attack_events:
        attack_type = event["attack_type"]
        if attack_type not in attack_types:
            attack_types[attack_type] = 0
        attack_types[attack_type] += 1

    # 平均威胁分数
    total_score = 0
    for event in attack_events:
        total_score += event["overall_threat_score"]

    avg_score = total_score / total_http_events if total_http_events > 0 else 0

    # 时间线数据
    timeline = []
    for event in sorted(attack_events, key=lambda e: e["timestamp"]):
        timeline.append({
            "timestamp": event["timestamp"],
            "type": "http",
            "score": event["overall_threat_score"],
            "attack": event["attack_type"]
        })

    for event in sorted(snapshot_events, key=lambda e: e["timestamp"]):
        timeline.append({
            "timestamp": event["timestamp"],
            "type": "snapshot",
            "score": event["overall_threat_score"]
        })

    return jsonify({
        "totalHttpEvents": total_http_events,
        "totalSnapshotEvents": total_snapshot_events,
        "avgThreatScore": round(avg_score, 1),
        "attackTypes": [{"name": k, "count": v} for k, v in attack_types.items()],
        "timeline": sorted(timeline, key=lambda x: x["timestamp"])
    })

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    """提供前端静态文件"""
    if path and path.find('.') != -1:  # 有文件扩展名的请求
        return send_from_directory('frontend/dist', path)
    return send_from_directory('frontend/dist', 'index.html')
