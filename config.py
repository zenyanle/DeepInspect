# config.py
PREDEFINED_ATTACK_TYPES = [
    "XSS (Cross-Site Scripting)",
    "SQL Injection",
    "CSRF (Cross-Site Request Forgery)",
    "Command Injection",
    "File Inclusion",
    "Directory Traversal",
    "Brute Force",
    "DDoS (Distributed Denial of Service)",
    "SSRF (Server-Side Request Forgery)",
    "Open Redirect",
    "Path Traversal",
    "LDAP Injection",
    "XPath Injection",
    "Header Injection",
    "Email Injection",
    "XML External Entity (XXE)",
    "Normal"
]
DEFAULT_SCORE_THRESHOLD = 7.0
GEMINI_API_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent" # 更新 Gemini API Endpoint
GEMINI_API_KEY = "" # 替换为你的 Gemini API Key
