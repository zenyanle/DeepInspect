# main.py
from api import app
import data_processing
import reporting
import event_handling
from config import GEMINI_API_KEY
import llm_http
import llm_snapshot


if __name__ == "__main__":
    print("firewall 启动，使用 Demo 数据进行综合分析...")
    data_processing.process_demo_requests(llm_http, llm_snapshot, event_handling) #  处理 HTTP 和快照 Demo 数据

    report = reporting.generate_report(event_handling.attack_events) #  仍然生成 JSON 报告，可以考虑拆分为 HTTP 和 Snapshot 报告
    print("\n--- 生成详细 JSON 报告 (HTTP 事件) ---")
    print(report)

    markdown_report = reporting.generate_markdown_report(event_handling.attack_events, event_handling.snapshot_events, "Demo 数据综合分析", GEMINI_API_KEY) #  传递 snapshot_events
    print("\n--- 生成 Markdown 报告 (综合 HTTP 和快照事件) ---")
    print(markdown_report)

    print("\n--- 启动 Web 服务器 ---")
    app.run(host='0.0.0.0', port=5000, debug=True)
