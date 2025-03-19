# llm_snapshot.py
import requests
import json
from config import GEMINI_API_ENDPOINT, GEMINI_API_KEY, DEFAULT_SCORE_THRESHOLD

def analyze_snapshot_with_llm(snapshot_data, event_handling_module):
    """使用 LLM 分析快照数据"""
    prompt_content = generate_llm_prompt_snapshot(snapshot_data)
    llm_response = call_gemini_api_snapshot(prompt_content)
    if llm_response:
        snapshot_analysis_result = parse_llm_response_snapshot(llm_response)
        if snapshot_analysis_result:
            overall_threat_score = snapshot_analysis_result.get("overall_threat_score")
            tcp_flood_score = snapshot_analysis_result["attack_type_score"].get("tcp_flood", 0.0)
            ip_scores = snapshot_analysis_result.get("ip_scores", {})
            analysis = snapshot_analysis_result.get("snapshot_analysis")
            mitigation_advice = snapshot_analysis_result.get("mitigation_advice")

            if overall_threat_score >= DEFAULT_SCORE_THRESHOLD:
                event_handling_module.record_snapshot_event(snapshot_data, overall_threat_score, tcp_flood_score, ip_scores, analysis, mitigation_advice)
                json_response = generate_json_response_snapshot(overall_threat_score, tcp_flood_score, ip_scores, analysis, mitigation_advice)
                print("--- 快照攻击检测结果 (JSON) ---")
                print(json_response)
            else:
                json_response = generate_json_response_snapshot(overall_threat_score, tcp_flood_score, ip_scores)
                print("--- 快照分析结果 (JSON) ---")
                print(json_response)


def generate_llm_prompt_snapshot(snapshot_data):
    """生成 LLM Prompt for Snapshot Analysis"""

    snapshot_json = json.dumps(snapshot_data, indent=2)

    prompt = f"""
    你是一个网络安全专家，负责分析防火墙快照数据，以检测潜在的网络攻击和安全风险。

    请分析以下防火墙快照数据 (JSON 格式)，并完成以下任务：

    1. **总体威胁评分 (Overall Threat Score):**  评估快照数据所反映的总体网络安全威胁程度，评分范围 0.0-10.0 (1 位小数)。
       - 0-3:  低风险，网络流量正常。
       - 4-6:  中等风险，可能存在潜在异常或可疑活动，需要进一步关注。
       - 7-10: 高风险，很可能存在正在进行的网络攻击或严重安全问题。

    2. **特定攻击类型评分 (Attack Type Scores):**  针对以下攻击类型，给出 0.0-10.0 的风险评分 (1 位小数)：
       - TCP Flood:  评估快照数据中是否存在 TCP Flood 攻击的迹象。

    3. **IP 地址风险评分 (IP Risk Scores):**  从快照数据中，识别出风险最高的 **Top 3** 源 IP 地址，并为每个 IP 地址给出 0.0-10.0 的风险评分 (1 位小数)。
       - 评分应基于该 IP 地址在快照数据中的行为特征 (例如，数据包数量、连接频率等)

    4. **攻击分析 (Snapshot Analysis):** (仅当 Overall Threat Score >= {DEFAULT_SCORE_THRESHOLD} 时)  如果总体威胁评分较高，请提供简要的文字分析，解释你判断的依据，指出可能存在的攻击类型、攻击目标、潜在影响等。

    5. **防护建议 (Mitigation Advice):** (仅当 Overall Threat Score >= {DEFAULT_SCORE_THRESHOLD} 时)  如果总体威胁评分较高，请提供简要的防护建议，例如可以采取的防火墙规则、安全配置调整、应急响应措施等。

    **快照数据 (JSON):**
    ```json
    {snapshot_json}
    ```

    请返回 **JSON 格式** 的结果，包含以下字段：

    - "overall_threat_score":  总体威胁评分 (浮点数)
    - "attack_type_score":  JSON 对象，包含各攻击类型评分，例如:  `{{ "tcp_flood": 8.5 }}`
    - "ip_scores": JSON 对象，包含 Top 3 风险 IP 地址及其评分，例如: `{{ "192.168.1.100": 7.0, "192.168.1.101": 6.5, "192.168.1.102": 6.0 }}`
    - "snapshot_analysis":  (可选) 攻击分析 (字符串)
    - "mitigation_advice":  (可选) 防护建议 (字符串)

    请严格按照 JSON 格式返回结果，**只返回 JSON 对象，不要包含任何其他文本**。
    """
    return prompt

def call_gemini_api_snapshot(prompt_content):
    """调用 Gemini API for Snapshot Analysis (使用 response_schema 请求结构化 JSON 输出)"""
    headers = {
        'Content-Type': 'application/json',
    }
    params = {
        'key': GEMINI_API_KEY
    }

    ip_score_properties = {}
    for i in range(1, 4): # Top 3 IP scores
        ip_score_properties[f"top_ip_{i}"] = {"type": "NUMBER", "format": "float"} # 动态生成 IP score 字段名

    data = {
        "contents": [{
            "parts": [{"text": prompt_content}]
        }],
        "generationConfig": {
            "response_mime_type": "application/json", # 明确指定 JSON 输出
            "response_schema": {  # 定义 JSON Schema
                "type": "OBJECT",
                "properties": {
                    "overall_threat_score": {"type": "NUMBER", "format": "float"},
                    "attack_type_score": {
                        "type": "OBJECT",
                        "properties": {
                            "tcp_flood": {"type": "NUMBER", "format": "float"},
                            # 可以根据需要添加更多攻击类型
                        },
                        "required": ["tcp_flood"], #  TCP Flood 评分是必需的
                        "propertyOrdering": ["tcp_flood"]
                    },
                    "ip_scores": {
                        "type": "OBJECT",
                        "properties": {
                            "top_ip_1": {"type": "NUMBER", "format": "float"},
                            "top_ip_2": {"type": "NUMBER", "format": "float"},
                            "top_ip_3": {"type": "NUMBER", "format": "float"}
                        },
                        "required": ["top_ip_1", "top_ip_2", "top_ip_3"], # Top 3 IP scores 都是必需的
                        "propertyOrdering": ["top_ip_1", "top_ip_2", "top_ip_3"]
                    },
                    "snapshot_analysis": {"type": "STRING"}, # 可选
                    "mitigation_advice": {"type": "STRING"}  # 可选
                },
                "required": ["overall_threat_score", "attack_type_score", "ip_scores"], # 标记为必需字段
                "propertyOrdering": ["overall_threat_score", "attack_type_score", "ip_scores", "snapshot_analysis", "mitigation_advice"]
            }
        }
    }
    try:
        response = requests.post(GEMINI_API_ENDPOINT, headers=headers, params=params, json=data)
        response.raise_for_status() # 检查 HTTP 错误
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Gemini API 调用失败 (Snapshot Analysis): {e}")
        return None


def parse_llm_response_snapshot(llm_response_json):
    """解析 LLM 返回的 JSON 结果 for Snapshot Analysis"""
    try:
        response_text = llm_response_json["candidates"][0]["content"]["parts"][0]["text"]
        response_data = json.loads(response_text)

        if all(key in response_data for key in ["overall_threat_score", "attack_type_score", "ip_scores"]):
            return {
                "overall_threat_score": float(response_data["overall_threat_score"]),
                "attack_type_score": response_data["attack_type_score"],
                "ip_scores": response_data["ip_scores"],
                "snapshot_analysis": response_data.get("snapshot_analysis"),
                "mitigation_advice": response_data.get("mitigation_advice")
            }
        else:
            print(f"LLM Snapshot 响应 JSON 格式不符合预期，缺少字段: {response_text}")
            return None

    except json.JSONDecodeError as e:
        print(f"解析 LLM Snapshot 响应 JSON 失败 (JSONDecodeError): {e}, 响应文本: {response_text}")
        return None
    except Exception as e:
        print(f"解析 LLM Snapshot 响应 JSON 失败 (其他错误): {e}")
        return None

def generate_json_response_snapshot(overall_threat_score, tcp_flood_score, ip_scores, analysis=None, mitigation_advice=None):
    """生成默认 JSON 响应 for Snapshot Analysis"""
    response_json = {
        "overall_threat_score": overall_threat_score,
        "attack_type_score": {"tcp_flood": tcp_flood_score},
        "ip_scores": ip_scores
    }
    if analysis:
        response_json["snapshot_analysis"] = analysis
    if mitigation_advice:
        response_json["mitigation_advice"] = mitigation_advice
    return json.dumps(response_json, indent=2)
