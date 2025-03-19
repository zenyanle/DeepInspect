# event_handling.py
import datetime

attack_events = []
snapshot_events = [] #  用于记录快照事件

def record_http_event(http_request_batch, attack_type, attack_type_score, overall_threat_score, batch_index, attack_analysis=None, mitigation_advice=None):
    """记录攻击批次事件 (包含细化评分, **以及分析和建议**)"""
    attack_events.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "batch_index": batch_index, # 记录批次索引
        "requests": http_request_batch, # 记录整个请求批次
        "attack_type": attack_type, # 记录检测到的主要攻击类型 (最高分)
        "attack_type_score": attack_type_score, # 记录所有攻击类型的评分
        "overall_threat_score": overall_threat_score,
        "attack_analysis": attack_analysis, # 记录 attack_analysis
        "mitigation_advice": mitigation_advice # 记录 mitigation_advice
    })

def record_snapshot_event(snapshot_data, overall_threat_score, tcp_flood_score, ip_scores, analysis=None, mitigation_advice=None):
    """记录快照分析事件"""
    snapshot_events.append({
        "timestamp": datetime.datetime.now().isoformat(),
        "snapshot_data": snapshot_data,
        "overall_threat_score": overall_threat_score,
        "tcp_flood_score": tcp_flood_score,
        "ip_scores": ip_scores,
        "analysis": analysis,
        "mitigation_advice": mitigation_advice
    })
