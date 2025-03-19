# data_processing.py
import datetime
import random
import json

demo_requests = [
    [ # 批次 1
        {
            "method": "GET",
            "path": "/",
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "*/*"},
            "body": ""
        },
        {
            "method": "POST",
            "path": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=test&password=password123"
        }
    ],
    [ # 批次 2
        {
            "method": "GET",
            "path": "/search?q=';alert(1);'",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": ""
        },
        {
            "method": "POST",
            "path": "/api/user",
            "headers": {"Content-Type": "application/json"},
            "body": '{"name": "test", "email": "test@example.com", "role": "admin\'--"}'
        },
        {
            "method": "GET",
            "path": "/../../etc/passwd",
            "headers": {"User-Agent": "Malicious User"},
            "body": ""
        }
    ],
    [ # 批次 3 - 新增批次，包含更多攻击类型示例
        {
            "method": "GET",
            "path": "/admin",
            "headers": {"User-Agent": "BruteForceBot"},
            "body": "" # 模拟 Brute Force 尝试访问管理后台
        },
        {
            "method": "POST",
            "path": "/api/upload",
            "headers": {"Content-Type": "multipart/form-data"},
            "body": 'Content-Disposition: form-data; name="file"; filename="../../../../../tmp/evil.sh"\r\nContent-Type: application/octet-stream\r\n\r\n#!/bin/bash\necho "Evil script executed!"\n' # 模拟 Directory Traversal 上传恶意文件
        },
         {
            "method": "GET",
            "path": "/redirect?url=http://evil.com",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "" # 模拟 Open Redirect
        }
    ]
]

def generate_demo_snapshot_data(scenario="normal"):
    """生成快照 Demo 数据"""
    now = datetime.datetime.now()
    start_time = now - datetime.timedelta(minutes=5)

    snapshot_data = {
        "Timestamp": now.isoformat(),
        "Basic": {
            "StartTime": start_time.isoformat(),
            "EndTime": now.isoformat(),
            "TotalPackets": random.randint(1000, 5000),
            "TotalBytes": random.randint(100000, 500000)
        },
        "MAC": {
            "UniqueSourceCount": random.randint(50, 200),
            "TopSources": [{"Address": f"MAC-{i}", "Count": random.randint(10, 50)} for i in range(5)]
        },
        "IP": {
            "UniqueSourceCount": random.randint(30, 150),
            "TopPairs": [{"SourceIP": f"192.168.1.{i}", "DestinationIP": "8.8.8.8", "Count": random.randint(20, 80)} for i in range(5)]
        },
        "Port": {
            "UniqueDestCount": random.randint(20, 80),
            "TopPairs": [{"SourcePort": random.randint(1024, 65535), "DestinationPort": 80, "Count": random.randint(30, 100)} for i in range(5)]
        },
        "Protocol": {
            "Protocols": [
                {"Name": "TCP", "Count": random.randint(600, 3000), "Percentage": random.uniform(50.0, 70.0)},
                {"Name": "UDP", "Count": random.randint(200, 1500), "Percentage": random.uniform(20.0, 40.0)},
                {"Name": "ICMP", "Count": random.randint(50, 500), "Percentage": random.uniform(5.0, 15.0)},
            ]
        },
        "TCPFlags": {
            "Flags": [
                {"Flag": "SYN", "Count": random.randint(300, 1500)},
                {"Flag": "ACK", "Count": random.randint(500, 2500)},
                {"Flag": "FIN", "Count": random.randint(10, 100)},
                {"Flag": "RST", "Count": random.randint(5, 50)},
            ]
        },
        "Application": {
            "Apps": [
                {"Name": "HTTP", "Count": random.randint(400, 2000), "Percentage": random.uniform(40.0, 60.0)},
                {"Name": "DNS", "Count": random.randint(100, 800), "Percentage": random.uniform(10.0, 25.0)},
                {"Name": "SSH", "Count": random.randint(20, 150), "Percentage": random.uniform(2.0, 5.0)},
            ]
        }
    }

    if scenario == "tcp_flood":
        snapshot_data["Basic"]["TotalPackets"] = random.randint(10000, 50000) # 大量数据包
        snapshot_data["Basic"]["TotalBytes"] = random.randint(500000, 2000000) # 大量字节
        snapshot_data["TCPFlags"]["Flags"] = [
                {"Flag": "SYN", "Count": random.randint(8000, 40000)}, # 大量 SYN 包
                {"Flag": "ACK", "Count": random.randint(1000, 5000)}, # 少量 ACK 包
                {"Flag": "FIN", "Count": random.randint(10, 50)},
                {"Flag": "RST", "Count": random.randint(5, 20)},
            ]
        snapshot_data["Protocol"]["Protocols"][0]["Count"] = random.randint(9000, 45000) # TCP 协议占比更高
        snapshot_data["Protocol"]["Protocols"][0]["Percentage"] = random.uniform(80.0, 95.0)
    return snapshot_data

def process_demo_requests(llm_http_module, llm_snapshot_module, event_handling_module):
    """处理 Demo 数据，包括 HTTP 请求和快照"""
    print("使用 Demo 数据进行分析...")

    # 处理 HTTP 请求批次 (保持不变)
    for batch_index, request_batch in enumerate(demo_requests):
        print(f"\n--- Processing HTTP Batch {batch_index + 1} ---") #  更明确的输出
        llm_http_module.analyze_http_batch_with_llm(request_batch, batch_index + 1, event_handling_module)

    # 处理快照数据
    print("\n--- Processing Demo Snapshots ---") #  更明确的输出
    process_demo_snapshots(llm_snapshot_module, event_handling_module) #  调用快照处理函数

def process_demo_snapshots(llm_snapshot_module, event_handling_module):
    """处理 Demo 快照数据"""
    print("使用 Demo 快照数据进行分析...")
    normal_snapshot = generate_demo_snapshot_data("normal")
    print("\n--- Processing Normal Snapshot ---")
    llm_snapshot_module.analyze_snapshot_with_llm(normal_snapshot, event_handling_module)

    tcp_flood_snapshot = generate_demo_snapshot_data("tcp_flood")
    print("\n--- Processing TCP Flood Snapshot ---")
    llm_snapshot_module.analyze_snapshot_with_llm(tcp_flood_snapshot, event_handling_module)
