# reporting.py
import datetime
import json
import requests
from config import GEMINI_API_ENDPOINT, GEMINI_API_KEY

def generate_report(events):
    """生成报告 (完善版本，包含批次统计和评分)"""
    report_str = "--- firewall 攻击检测报告 ---\n"
    report_str += f"报告生成时间: {datetime.datetime.now().isoformat()}\n\n"

    if not events:
        report_str += "未检测到任何 HTTP 攻击事件批次。\n"
        return report_str

    report_str += "--- 攻击类型统计摘要 (按批次) ---\n"
    attack_type_stats = {} # 使用字典存储每个攻击类型的统计信息
    total_overall_threat_score = 0
    total_batches = len(events)

    for event in events:
        main_attack_type = event["attack_type"]
        attack_type_score_detail = event["attack_type_score"]
        overall_threat_score = event["overall_threat_score"]

        total_overall_threat_score += overall_threat_score

        if main_attack_type != "Normal": #  只统计非 Normal 的主要攻击类型
            if main_attack_type not in attack_type_stats:
                attack_type_stats[main_attack_type] = {
                    "count": 0, # 批次数
                    "total_score": 0, #  这里统计的是 *主要* 攻击类型的评分，也可以考虑统计 max(attack_type_score_detail.values())
                    "average_score": 0
                }
            attack_type_stats[main_attack_type]["count"] += 1
            #  计算主要攻击类型的评分 (这里可以用 max_attack_score 或 attack_type_score_detail[main_attack_type.lower().replace(" ", "_").replace("(", "").replace(")", "")])
            max_score_for_event = 0
            for score in attack_type_score_detail.values():
                max_score_for_event = max(max_score_for_event, score)
            attack_type_stats[main_attack_type]["total_score"] += max_score_for_event


    # 计算平均分
    for attack_type in attack_type_stats:
        count = attack_type_stats[attack_type]["count"]
        total_score = attack_type_stats[attack_type]["total_score"]
        attack_type_stats[attack_type]["average_score"] = total_score / count if count > 0 else 0

    report_str += "各攻击类型统计 (主要攻击类型，按批次):\n"
    for attack_type, stats in attack_type_stats.items():
        report_str += f"- {attack_type}: {stats['count']} 批次, 平均最高评分: {stats['average_score']:.1f}\n" #  修改描述为 "平均最高评分"

    if total_batches > 0:
        average_overall_threat_score = total_overall_threat_score / total_batches
        report_str += f"\n总体风险评分 (所有批次平均): {average_overall_threat_score:.1f}\n"


    report_str += "\n--- 详细HTTP攻击事件批次列表 ---\n"
    for i, event in enumerate(events):
        report_str += f"--- 事件批次 #{i+1} ---\n" # Batch event number
        report_str += f"时间戳: {event['timestamp']}\n"
        report_str += f"批次索引: {event['batch_index']}\n" # Batch index
        report_str += f"请求列表:\n" # Request list in batch
        for req in event["requests"]:
             report_str += f"  - Method: {req['method']}, Path: {req['path']}\n" # Simplified request info in report
        report_str += f"主要攻击类型: {event['attack_type']}\n"
        report_str += f"各攻击类型评分: {json.dumps(event['attack_type_score'], indent=2)}\n" #  展示详细的 attack_type_score
        report_str += f"总体威胁评分: {event['overall_threat_score']:.1f}\n"
        if event.get("attack_analysis"): # 添加 attack_analysis 和 mitigation_advice 到报告
            report_str += f"攻击分析: {event['attack_analysis']}\n"
            report_str += f"防护建议: {event['mitigation_advice']}\n"
        report_str += "\n\n"

    return report_str

def generate_markdown_report(events, snapshot_events, time_period_description, gemini_api_key):
    """生成时间段全部批次的 Markdown 报告"""
    report_content = f"## firewall 报告 ({time_period_description})\n\n"

    if not events and not snapshot_events:
        return report_content + "**未检测到任何 HTTP 攻击事件或快照异常事件。**"

    if events:
        report_content += "### HTTP 攻击事件摘要:\n\n"
        events_summary = ""
        for event in events:
            main_attack_type = event["attack_type"]
            overall_threat_score = event["overall_threat_score"]
            batch_index = event["batch_index"]
            timestamp = event["timestamp"]

            events_summary += f"- **HTTP 批次 {batch_index}**:  时间 `{timestamp}`, 主要攻击类型 `{main_attack_type}`, 总体威胁评分 `{overall_threat_score:.1f}`\n"
            if event.get("attack_analysis"):
                events_summary += f"  - 分析: {event['attack_analysis']}\n"
                events_summary += f"  - 建议: {event['mitigation_advice']}\n"
        report_content += events_summary + "\n"

    if snapshot_events:
        report_content += "### 快照异常事件摘要:\n\n"
        snapshot_summary = ""
        for event in snapshot_events:
            overall_threat_score = event["overall_threat_score"]
            tcp_flood_score = event["tcp_flood_score"]
            timestamp = event["timestamp"]
            snapshot_summary += f"- **快照**: 时间 `{timestamp}`, 总体威胁评分 `{overall_threat_score:.1f}`, TCP Flood 评分 `{tcp_flood_score:.1f}`\n"
            if event.get("analysis"):
                snapshot_summary += f"  - 分析: {event['analysis']}\n"
                snapshot_summary += f"  - 建议: {event['mitigation_advice']}\n"
            ip_scores = event.get("ip_scores", {})
            if ip_scores:
                snapshot_summary += "  - 风险 IP 地址:\n"
                for ip, score in ip_scores.items():
                    snapshot_summary += f"    - `{ip}`: 风险评分 `{score:.1f}`\n"

        report_content += snapshot_summary + "\n"


    full_report_prompt = f"""
    请根据以下 firewall 和快照分析事件摘要，为时间段 **{time_period_description}** 生成一份 Markdown 格式的综合报告。
    报告应包括：
    - 报告总标题，包含时间段描述
    - HTTP 攻击事件摘要 (如果存在)
    - 快照异常事件摘要 (如果存在)
    - 总体安全态势评估 (基于 HTTP 和快照事件的综合分析)
    - 关键安全发现和建议 (综合 HTTP 和快照分析结果，给出整体的安全建议)

    --- HTTP 攻击事件摘要 ---
    {events_summary if events else "无 HTTP 攻击事件"}

    --- 快照异常事件摘要 ---
    {snapshot_summary if snapshot_events else "无快照异常事件"}

    请返回 **Markdown 格式** 的完整报告。
    """

    headers = {
        'Content-Type': 'application/json',
    }
    params = {
        'key': gemini_api_key
    }
    data = {
        "contents": [{
            "parts": [{"text": full_report_prompt}]
        }]
    }
    try:
        response = requests.post(GEMINI_API_ENDPOINT, headers=headers, params=params, json=data)
        response.raise_for_status() # 检查 HTTP 错误
        markdown_output = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        return report_content + "\n" + markdown_output #  Combine initial summary and LLM-generated full report
    except requests.exceptions.RequestException as e:
        print(f"Gemini API 调用失败 (生成 Markdown 报告): {e}")
        return "生成 Markdown 报告失败，请查看日志。"
