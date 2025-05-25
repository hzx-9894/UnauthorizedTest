from mitmproxy import ctx, http
import json
from urllib.parse import parse_qs, unquote
import re


class AuthInspector:
    AUTH_PATTERNS = {
        'headers': [
            ('authorization', r'Bearer\s+(\S+)', 'Bearer Token'),
            ('authorization', r'Basic\s+(\S+)', 'Basic Auth'),
            ('x-api-key', None, 'API Key'),
            ('x-auth-token', None, 'Custom Auth Token')
        ],
        'cookies': [
            ('session', None, 'Session Cookie'),
            ('token', None, 'Access Token'),
            ('auth', None, 'Authentication Cookie')
        ],
        'params': [
            ('access_token', None, 'URL Token'),
            ('api_key', None, 'API Key'),
            ('auth_token', None, 'Auth Token')
        ]
    }

    def __init__(self):
        self.auth_counter = 0

    def request(self, flow: http.HTTPFlow):
        if flow.request.method != "POST":
            return

        auth_findings = self.detect_auth(flow)
        content_type = flow.request.headers.get("Content-Type", "").lower()
        post_data = flow.request.content

        parsed_content = self.parse_content(content_type, post_data)
        auth_in_body = self.scan_body_auth(parsed_content)

        all_findings = auth_findings + auth_in_body

        # 输出报告
        self.generate_report(flow, content_type, parsed_content, all_findings)

    def detect_auth(self, flow):
        findings = []

        # 检查请求头
        for header in flow.request.headers:
            lower_header = header.lower()
            for pattern in self.AUTH_PATTERNS['headers']:
                if lower_header == pattern[0].lower():
                    value = flow.request.headers[header]
                    findings.append((
                        pattern[2],
                        self.mask_sensitive(value, pattern[1])
                    ))

        # 检查Cookies
        cookie_header = flow.request.headers.get('Cookie', '')
        for name, pattern, label in self.AUTH_PATTERNS['cookies']:
            match = re.search(fr'{name}=([^;]+)', cookie_header, re.I)
            if match:
                findings.append((
                    label,
                    self.mask_sensitive(unquote(match.group(1)))
                ))

        # 检查URL参数
        for param in flow.request.query:
            for pattern in self.AUTH_PATTERNS['params']:
                if param.lower() == pattern[0].lower():
                    findings.append((
                        pattern[2],
                        self.mask_sensitive(flow.request.query[param])
                    ))

        return findings

    def scan_body_auth(self, parsed_content):
        findings = []
        sensitive_keys = {'password', 'pwd', 'secret', 'token'}

        def recursive_scan(data, path=''):
            if isinstance(data, dict):
                for k, v in data.items():
                    current_path = f"{path}.{k}" if path else k
                    if k.lower() in sensitive_keys:
                        findings.append((
                            f"敏感字段: {current_path}",
                            self.mask_sensitive(str(v))
                        ))
                    recursive_scan(v, current_path)
            elif isinstance(data, list):
                for i, item in enumerate(data):
                    recursive_scan(item, f"{path}[{i}]")

        recursive_scan(parsed_content)
        return findings

    def mask_sensitive(self, value, regex=None):
        if not value:
            return ""

        if regex:
            match = re.search(regex, value)
            if match:
                token = match.group(1)
                return value.replace(token, f"{token[:4]}******")

        if len(value) > 8:
            return f"{value[:4]}******{value[-2:]}"
        return "******"

    def generate_report(self, flow, content_type, parsed_content, findings):
        self.auth_counter += 1

        report = [
            "\n" + "=" * 60,
            f"🔍 授权请求 #{self.auth_counter}",
            f"🌐 URL: {flow.request.url}",
            f"📦 Content-Type: {content_type}",
        ]

        if findings:
            report.append("🚨 检测到授权凭证:")
            for label, value in findings:
                report.append(f"   ▸ {label}: {value}")
        else:
            report.append("✅ 未检测到明显授权凭证")

        report.append("📝 请求内容预览:")
        report.append(self.pretty_format(parsed_content))
        report.append("=" * 60)

        ctx.log.info("\n".join(report))

    # 保留之前的 parse_content 和 pretty_format 方法
    # ... (同之前版本的实现)


addons = [AuthInspector()]