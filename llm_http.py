# llm_http.py
import requests
import json
from config import GEMINI_API_ENDPOINT, GEMINI_API_KEY, PREDEFINED_ATTACK_TYPES, DEFAULT_SCORE_THRESHOLD

def analyze_http_batch_with_llm(http_request_batch, batch_index, event_handling_module):
    """使用 LLM 分析 HTTP 请求批次 (**包含分析和建议处理** )"""
    prompt_content = generate_llm_prompt_http(http_request_batch) # Pass the whole batch to prompt
    llm_response = call_gemini_api_http(prompt_content)
    if llm_response:
        attack_detection_result = parse_llm_response_http(llm_response)
        if attack_detection_result and attack_detection_result["overall_threat_score"] is not None: # 确保 overall_threat_score 存在
            overall_threat_score = attack_detection_result["overall_threat_score"]
            attack_analysis = attack_detection_result.get("attack_analysis") # 获取 analysis 和 advice
            mitigation_advice = attack_detection_result.get("mitigation_advice")

            detected_attack_type = "Normal" # 默认值
            max_attack_score = 0.0
            detected_attack_scores = {}

            for attack_type in PREDEFINED_ATTACK_TYPES:
                if attack_type != "Normal":
                    score_key = attack_type.lower().replace(" ", "_").replace("(", "").replace(")", "") # 转换为 JSON 字段名
                    attack_score = attack_detection_result["attack_type_score"].get(score_key, 0.0)
                    detected_attack_scores[score_key] = attack_score
                    if attack_score > max_attack_score:
                        max_attack_score = attack_score
                        detected_attack_type = attack_type # 更新检测到的攻击类型为最高评分的类型

            if overall_threat_score >= DEFAULT_SCORE_THRESHOLD and detected_attack_type != "Normal":
                event_handling_module.record_http_event(http_request_batch, detected_attack_type, detected_attack_scores, overall_threat_score, batch_index, attack_analysis, mitigation_advice) # 记录 analysis 和 advice
                json_response = generate_json_response_http(detected_attack_type, detected_attack_scores, overall_threat_score, attack_analysis, mitigation_advice) # 传递 analysis 和 advice
                print("--- Batch 攻击检测结果 (JSON) ---") # Batch result output
                print(json_response)
            else:
                json_response = generate_json_response_http("Normal", detected_attack_scores, overall_threat_score) #  Normal Batch 也输出所有 scores
                print("--- Batch 请求分析结果 (JSON) ---") # Batch analysis output
                print(json_response)


def generate_llm_prompt_http(http_request_batch):
    """生成 LLM Prompt (请求结构化 JSON 输出和细化评分，针对批量请求, **包含分析和建议**)"""
    request_details_str = ""
    for i, req in enumerate(http_request_batch):
        request_details_str += f"Request {i+1}:\n"
        request_details_str += f"Method: {req['method']}\n"
        request_details_str += f"Path: {req['path']}\n"
        request_details_str += f"Headers: {json.dumps(req['headers'])}\n"
        request_details_str += f"Body: {req['body']}\n\n"


    prompt = f"""
    你是一个 Web 应用防火墙 (firewall) 和安全分析专家。你的任务是分析 **一批** HTTP 请求，判断是否存在 Web 攻击。
    预定义的攻击类型包括: {', '.join([at for at in PREDEFINED_ATTACK_TYPES if at != 'Normal'])}.
    如果判断为正常请求，则主要攻击类型为 "Normal"。

    请返回 **JSON 格式** 的结果，包含以下字段，**针对整个请求批次进行评估**:
    - "attack_type_score": 一个 JSON 对象，包含预定义攻击类型 (除了 "Normal") 的评分。每个攻击类型作为一个字段名，评分为 0.0-10.0 (1 位小数)，**针对整个请求批次中该类型攻击的风险进行评估**。
    - "overall_threat_score": 总体威胁评分，范围 0.0-10.0 (1 位小数)，综合评估 **整个请求批次的** 潜在风险。即使是 "Normal" 批次，也应根据请求特征给出 0.0 或接近 0.0 的评分。
    - "attack_analysis": **(仅当 overall_threat_score >= {DEFAULT_SCORE_THRESHOLD} 时)** 针对检测到的攻击的简要分析，说明可能存在的攻击类型、攻击目的、以及潜在影响。(字符串，可选)
    - "mitigation_advice": **(仅当 overall_threat_score >= {DEFAULT_SCORE_THRESHOLD} 时)**  针对检测到的攻击，提供简要的防护建议，例如可以采取的 firewall 规则、安全配置等。(字符串，可选)

    评分标准 (0-10):
    - 0-3:  低风险或正常请求批次
    - 4-6:  中等风险，可能存在潜在风险或可疑模式
    - 7-10: 高风险，很可能是恶意攻击批次

    HTTP 请求批次详情:
    {request_details_str}

    请严格按照以下 JSON 示例格式返回结果，**只返回 JSON 对象，不要包含任何其他文本**。
    例如 (高风险攻击请求批次):
    {{
      "attack_type_score": {{ ... }},
      "overall_threat_score": 9.0,
      "attack_analysis": "该批次请求疑似包含 SQL 注入和 XSS 攻击...",
      "mitigation_advice": "建议部署 SQL 注入和 XSS 防护规则..."
    }}
    例如 (正常或低风险请求批次):
    {{
      "attack_type_score": {{ ... }},
      "overall_threat_score": 1.5
    }}
    """
    return prompt

def call_gemini_api_http(prompt_content):
    """调用 Gemini API (使用 response_schema 请求结构化 JSON 输出, **包含分析和建议**)"""
    headers = {
        'Content-Type': 'application/json',
    }
    params = {
        'key': GEMINI_API_KEY
    }
    attack_score_properties = {}
    attack_type_names = [at for at in PREDEFINED_ATTACK_TYPES if at != "Normal"]
    for attack_type in attack_type_names:
        score_key = attack_type.lower().replace(" ", "_").replace("(", "").replace(")", "") # JSON 字段名转换
        attack_score_properties[score_key] = {"type": "NUMBER", "format": "float"}

    required_attack_scores = list(attack_score_properties.keys()) # 所有 attack_type_score 下的 properties 都是 required

    data = {
        "contents": [{
            "parts": [{"text": prompt_content}]
        }],
        "generationConfig": {
            "response_mime_type": "application/json", # 明确指定 JSON 输出
            "response_schema": {  # 定义 JSON Schema
                "type": "OBJECT",
                "properties": {
                    "attack_type_score": {
                        "type": "OBJECT",
                        "properties": attack_score_properties,
                        "required": required_attack_scores,
                        "propertyOrdering": required_attack_scores
                    },
                    "overall_threat_score": {"type": "NUMBER", "format": "float"},
                    "attack_analysis": {"type": "STRING"}, # 新增 attack_analysis，可选
                    "mitigation_advice": {"type": "STRING"}  # 新增 mitigation_advice，可选
                },
                "required": ["attack_type_score", "overall_threat_score"], # 标记为必需字段
                "propertyOrdering": ["attack_type_score", "overall_threat_score", "attack_analysis", "mitigation_advice"] # 可以添加 ordering，但不是必须
            }
        }
    }
    try:
        response = requests.post(GEMINI_API_ENDPOINT, headers=headers, params=params, json=data)
        response.raise_for_status() # 检查 HTTP 错误
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Gemini API 调用失败 (HTTP Analysis): {e}")
        return None

def parse_llm_response_http(llm_response_json):
    """解析 LLM 返回的 JSON 结果 (包含细化评分, **以及分析和建议** )"""
    try:
        # 假设 Gemini 返回的 JSON 结构类似:
        # { "candidates": [{ "content": { "parts": [{"text": '{"attack_type_score": {...}, "overall_threat_score": 9.0, "attack_analysis": ..., "mitigation_advice": ...}'}] } }] }
        response_text = llm_response_json["candidates"][0]["content"]["parts"][0]["text"]
        # 尝试解析 JSON 字符串
        response_data = json.loads(response_text)

        # 检查是否包含所有必需字段
        if "attack_type_score" in response_data and "overall_threat_score" in response_data:
            return {
                "attack_type_score": response_data["attack_type_score"],
                "overall_threat_score": float(response_data["overall_threat_score"]), # 确保是浮点数
                "attack_analysis": response_data.get("attack_analysis"), # 使用 .get() 获取可选字段，不存在时返回 None
                "mitigation_advice": response_data.get("mitigation_advice")  # 使用 .get() 获取可选字段，不存在时返回 None
            }
        else:
            print(f"LLM HTTP 响应 JSON 格式不符合预期，缺少字段: {response_text}")
            return None

    except json.JSONDecodeError as e:
        print(f"解析 LLM HTTP 响应 JSON 失败 (JSONDecodeError): {e}, 响应文本: {response_text}")
        return None
    except Exception as e:
        print(f"解析 LLM HTTP 响应 JSON 失败 (其他错误): {e}")
        return None


def generate_json_response_http(attack_type, attack_type_score, overall_threat_score, attack_analysis=None, mitigation_advice=None):
    """生成默认 JSON 响应 (包含细化评分, **以及分析和建议**)"""
    response_json = {
        "attack_type_score": attack_type_score,
        "overall_threat_score": overall_threat_score
    }
    if attack_analysis:
        response_json["attack_analysis"] = attack_analysis
    if mitigation_advice:
        response_json["mitigation_advice"] = mitigation_advice
    return json.dumps(response_json)
