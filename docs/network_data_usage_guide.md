# CAPEv2 网络分析数据使用指南

## 概述

本指南详细说明如何在 CAPEv2 中访问和使用 NetworkAnalysis 和 Pcap 解析后的网络数据。

## 1. 数据结构概览

### 1.1 完整的网络数据结构

```json
{
  "network": {
    "pcap_sha256": "d8b6c7e2f1a3...",
    "sorted_pcap_sha256": "a1b2c3d4e5f6...",
    "hosts": [
      {
        "ip": "93.184.216.34",
        "country_name": "United States", 
        "hostname": "example.com",
        "inaddrarpa": "34.216.184.93.in-addr.arpa",
        "ports": [80, 443]
      }
    ],
    "domains": [
      {
        "domain": "example.com",
        "ip": "93.184.216.34"
      }
    ],
    "http": [
      {
        "method": "GET",
        "host": "example.com",
        "port": 80,
        "uri": "/index.html",
        "user-agent": "Mozilla/5.0 ...",
        "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\n...",
        "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n..."
      }
    ],
    "irc": [
      {
        "server": "irc.freenode.net",
        "port": 6667,
        "command": "JOIN",
        "params": "#channel"
      }
    ],
    "icmp": [
      {
        "src": "192.168.1.100",
        "dst": "8.8.8.8", 
        "type": "echo-request",
        "data": "ping data"
      }
    ],
    "tcp": [...],
    "udp": [...]
  }
}
```

## 2. 在不同模块中访问网络数据

### 2.1 在 Web 界面中访问

#### 2.1.1 Django 视图中获取数据

```python
# web/analysis/views.py
def analysis_network(request, task_id):
    """网络分析页面"""
    
    # 从数据库获取分析结果
    if repconf.mongodb.enabled:
        # MongoDB 方式
        analysis = mongo_find_one(
            {"info.id": int(task_id)},
            {"network": 1, "info": 1},
            sort=[("_id", -1)]
        )
        network_data = analysis.get("network", {}) if analysis else {}
    else:
        # 文件系统方式
        results_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "reports", "report.json")
        if os.path.exists(results_path):
            with open(results_path) as f:
                data = json.load(f)
                network_data = data.get("network", {})
        else:
            network_data = {}
    
    # 处理网络数据
    context = {
        "network_summary": {
            "pcap_available": bool(network_data),
            "total_hosts": len(network_data.get("hosts", [])),
            "total_domains": len(network_data.get("domains", [])),
            "total_http_requests": len(network_data.get("http", [])),
            "has_irc": bool(network_data.get("irc", [])),
            "has_icmp": bool(network_data.get("icmp", []))
        },
        "network_details": network_data
    }
    
    return render(request, "analysis/network.html", context)
```

#### 2.1.2 在模板中显示数据

```html
<!-- templates/analysis/network.html -->
<div class="network-analysis">
    <h3>网络分析概要</h3>
    <div class="summary-stats">
        <div class="stat-item">
            <span class="label">外部主机通信:</span>
            <span class="value">{{ network_summary.total_hosts }}</span>
        </div>
        <div class="stat-item">
            <span class="label">DNS 解析:</span>
            <span class="value">{{ network_summary.total_domains }}</span>
        </div>
        <div class="stat-item">
            <span class="label">HTTP 请求:</span>
            <span class="value">{{ network_summary.total_http_requests }}</span>
        </div>
    </div>

    {% if network_details.hosts %}
    <h4>通信主机列表</h4>
    <table class="hosts-table">
        <thead>
            <tr>
                <th>IP 地址</th>
                <th>主机名</th>
                <th>国家</th>
                <th>通信端口</th>
            </tr>
        </thead>
        <tbody>
            {% for host in network_details.hosts %}
            <tr>
                <td>{{ host.ip }}</td>
                <td>{{ host.hostname|default:"未知" }}</td>
                <td>{{ host.country_name|default:"未知" }}</td>
                <td>{{ host.ports|join:", " }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    {% if network_details.http %}
    <h4>HTTP 请求详情</h4>
    <div class="http-requests">
        {% for request in network_details.http %}
        <div class="http-request">
            <div class="request-line">
                <span class="method">{{ request.method }}</span>
                <span class="url">{{ request.host }}{{ request.uri }}</span>
            </div>
            <div class="request-details">
                <strong>User-Agent:</strong> {{ request.user-agent|default:"未知" }}<br>
                <strong>端口:</strong> {{ request.port }}
            </div>
        </div>
        {% endfor %}
    </div>
    {% endif %}
</div>
```

### 2.2 在 API 中提供网络数据

```python
# web/apiv2/views.py
@api_view(['GET'])
def task_network_info(request, task_id):
    """获取任务的网络分析信息"""
    
    try:
        # 验证任务存在
        task = Task.objects.get(id=task_id)
        
        # 获取网络分析数据
        network_data = get_network_analysis_data(task_id)
        
        if not network_data:
            return Response({
                "error": False,
                "data": {
                    "message": "网络分析数据不可用",
                    "pcap_available": False
                }
            })
        
        # 构建响应数据
        response_data = {
            "task_id": task_id,
            "pcap_info": {
                "pcap_sha256": network_data.get("pcap_sha256"),
                "sorted_pcap_sha256": network_data.get("sorted_pcap_sha256"),
                "pcap_available": True
            },
            "communication_summary": {
                "unique_hosts": len(network_data.get("hosts", [])),
                "dns_resolutions": len(network_data.get("domains", [])),
                "http_requests": len(network_data.get("http", [])),
                "irc_messages": len(network_data.get("irc", [])),
                "icmp_packets": len(network_data.get("icmp", []))
            },
            "external_communications": [
                {
                    "ip": host["ip"],
                    "hostname": host.get("hostname"),
                    "country": host.get("country_name"),
                    "ports": host.get("ports", [])
                }
                for host in network_data.get("hosts", [])
                if not _is_internal_ip(host["ip"])
            ],
            "suspicious_indicators": _analyze_suspicious_activity(network_data)
        }
        
        return Response({
            "error": False,
            "data": response_data
        })
        
    except Task.DoesNotExist:
        return Response({
            "error": True,
            "message": f"任务 {task_id} 不存在"
        })

def _analyze_suspicious_activity(network_data):
    """分析可疑网络活动"""
    indicators = []
    
    # 检查 IRC 通信
    if network_data.get("irc"):
        indicators.append({
            "type": "irc_communication",
            "description": f"检测到 {len(network_data['irc'])} 条 IRC 消息",
            "severity": "medium"
        })
    
    # 检查可疑端口
    suspicious_ports = [6667, 6697, 8080, 1337, 31337, 4444, 5555]
    for host in network_data.get("hosts", []):
        for port in host.get("ports", []):
            if port in suspicious_ports:
                indicators.append({
                    "type": "suspicious_port",
                    "description": f"与 {host['ip']} 的 {port} 端口通信",
                    "severity": "high" if port in [1337, 31337, 4444] else "medium"
                })
    
    # 检查大量 HTTP 请求
    http_requests = network_data.get("http", [])
    if len(http_requests) > 50:
        indicators.append({
            "type": "high_http_volume",
            "description": f"检测到 {len(http_requests)} 个 HTTP 请求",
            "severity": "low"
        })
    
    return indicators

def _is_internal_ip(ip):
    """检查是否为内网 IP"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False
```

### 2.3 在报告模块中使用网络数据

```python
# modules/reporting/network_report.py
class NetworkReport(Report):
    """生成专门的网络分析报告"""
    
    def run(self, results):
        """生成网络分析报告"""
        
        network_data = results.get("network", {})
        if not network_data:
            log.info("没有网络分析数据可用")
            return
        
        # 创建网络报告目录
        network_report_dir = os.path.join(self.reports_path, "network")
        os.makedirs(network_report_dir, exist_ok=True)
        
        # 生成各种网络分析报告
        self._generate_hosts_report(network_data, network_report_dir)
        self._generate_http_report(network_data, network_report_dir)
        self._generate_dns_report(network_data, network_report_dir)
        self._generate_suspicious_activity_report(network_data, network_report_dir)
    
    def _generate_hosts_report(self, network_data, output_dir):
        """生成主机通信报告"""
        hosts = network_data.get("hosts", [])
        if not hosts:
            return
        
        report_path = os.path.join(output_dir, "hosts_communication.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("网络主机通信分析报告\n")
            f.write("=" * 50 + "\n\n")
            
            # 分类显示内外网通信
            internal_hosts = []
            external_hosts = []
            
            for host in hosts:
                if self._is_internal_ip(host["ip"]):
                    internal_hosts.append(host)
                else:
                    external_hosts.append(host)
            
            if external_hosts:
                f.write(f"外部网络通信 ({len(external_hosts)} 个主机):\n")
                f.write("-" * 30 + "\n")
                for host in external_hosts:
                    f.write(f"IP: {host['ip']}\n")
                    f.write(f"主机名: {host.get('hostname', '未知')}\n")
                    f.write(f"国家: {host.get('country_name', '未知')}\n")
                    f.write(f"通信端口: {', '.join(map(str, host.get('ports', [])))}\n")
                    f.write("\n")
            
            if internal_hosts:
                f.write(f"\n内部网络通信 ({len(internal_hosts)} 个主机):\n")
                f.write("-" * 30 + "\n")
                for host in internal_hosts:
                    f.write(f"IP: {host['ip']}\n")
                    f.write(f"通信端口: {', '.join(map(str, host.get('ports', [])))}\n")
                    f.write("\n")
    
    def _generate_http_report(self, network_data, output_dir):
        """生成 HTTP 通信报告"""
        http_requests = network_data.get("http", [])
        if not http_requests:
            return
        
        report_path = os.path.join(output_dir, "http_communications.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("HTTP 通信分析报告\n")
            f.write("=" * 50 + "\n\n")
            
            # 按域名分组
            domain_requests = {}
            for req in http_requests:
                host = req.get("host", "未知")
                if host not in domain_requests:
                    domain_requests[host] = []
                domain_requests[host].append(req)
            
            for domain, requests in domain_requests.items():
                f.write(f"域名: {domain} ({len(requests)} 个请求)\n")
                f.write("-" * 40 + "\n")
                
                for req in requests:
                    f.write(f"  {req.get('method', 'GET')} {req.get('uri', '/')}\n")
                    user_agent = req.get('user-agent', '')
                    if user_agent:
                        f.write(f"  User-Agent: {user_agent[:100]}...\n" if len(user_agent) > 100 else f"  User-Agent: {user_agent}\n")
                    f.write("\n")
                f.write("\n")
    
    def _generate_dns_report(self, network_data, output_dir):
        """生成 DNS 解析报告"""
        domains = network_data.get("domains", [])
        if not domains:
            return
        
        report_path = os.path.join(output_dir, "dns_resolutions.txt")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("DNS 解析分析报告\n")
            f.write("=" * 50 + "\n\n")
            
            for domain in domains:
                f.write(f"{domain['domain']} -> {domain['ip']}\n")
    
    def _generate_suspicious_activity_report(self, network_data, output_dir):
        """生成可疑活动报告"""
        report_path = os.path.join(output_dir, "suspicious_activity.txt")
        
        suspicious_items = []
        
        # 检查 IRC 活动
        irc_data = network_data.get("irc", [])
        if irc_data:
            suspicious_items.append(f"检测到 IRC 通信: {len(irc_data)} 条消息")
        
        # 检查可疑端口
        suspicious_ports = [6667, 6697, 8080, 1337, 31337, 4444, 5555]
        for host in network_data.get("hosts", []):
            for port in host.get("ports", []):
                if port in suspicious_ports:
                    suspicious_items.append(f"可疑端口通信: {host['ip']}:{port}")
        
        # 检查异常 HTTP 活动
        http_requests = network_data.get("http", [])
        if len(http_requests) > 100:
            suspicious_items.append(f"大量 HTTP 请求: {len(http_requests)} 个")
        
        # 写入报告
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("可疑网络活动分析报告\n")
            f.write("=" * 50 + "\n\n")
            
            if suspicious_items:
                for item in suspicious_items:
                    f.write(f"⚠️  {item}\n")
            else:
                f.write("未检测到明显的可疑网络活动。\n")
```

## 3. 数据查询和分析工具

### 3.1 命令行工具

```python
#!/usr/bin/env python3
# tools/network_analyzer.py
"""
CAPEv2 网络数据分析命令行工具
"""

import argparse
import json
import os
import sys
from collections import Counter

def load_network_data(task_id):
    """加载网络分析数据"""
    report_path = f"/opt/cape/storage/analyses/{task_id}/reports/report.json"
    
    if not os.path.exists(report_path):
        print(f"报告文件不存在: {report_path}")
        return None
    
    with open(report_path) as f:
        data = json.load(f)
        return data.get("network", {})

def analyze_hosts(network_data):
    """分析主机通信"""
    hosts = network_data.get("hosts", [])
    
    print(f"\n主机通信分析 (共 {len(hosts)} 个主机):")
    print("-" * 50)
    
    external_hosts = [h for h in hosts if not is_internal_ip(h["ip"])]
    internal_hosts = [h for h in hosts if is_internal_ip(h["ip"])]
    
    print(f"外部主机: {len(external_hosts)}")
    print(f"内部主机: {len(internal_hosts)}")
    
    # 统计国家分布
    countries = Counter(h.get("country_name", "未知") for h in external_hosts)
    if countries:
        print("\n外部主机国家分布:")
        for country, count in countries.most_common():
            print(f"  {country}: {count}")
    
    # 统计端口使用
    all_ports = []
    for host in hosts:
        all_ports.extend(host.get("ports", []))
    
    if all_ports:
        port_stats = Counter(all_ports)
        print(f"\n最常用端口:")
        for port, count in port_stats.most_common(10):
            print(f"  {port}: {count} 次")

def analyze_http(network_data):
    """分析 HTTP 通信"""
    http_requests = network_data.get("http", [])
    
    print(f"\nHTTP 通信分析 (共 {len(http_requests)} 个请求):")
    print("-" * 50)
    
    if not http_requests:
        print("无 HTTP 通信数据")
        return
    
    # 统计方法
    methods = Counter(req.get("method", "GET") for req in http_requests)
    print("HTTP 方法分布:")
    for method, count in methods.items():
        print(f"  {method}: {count}")
    
    # 统计域名
    hosts = Counter(req.get("host", "未知") for req in http_requests)
    print(f"\n访问的域名 (前10):")
    for host, count in hosts.most_common(10):
        print(f"  {host}: {count} 次")
    
    # 统计 User-Agent
    user_agents = Counter(req.get("user-agent", "未知") for req in http_requests)
    print(f"\nUser-Agent 分布:")
    for ua, count in user_agents.most_common(5):
        ua_short = ua[:80] + "..." if len(ua) > 80 else ua
        print(f"  {ua_short}: {count} 次")

def analyze_dns(network_data):
    """分析 DNS 解析"""
    domains = network_data.get("domains", [])
    
    print(f"\nDNS 解析分析 (共 {len(domains)} 个解析):")
    print("-" * 50)
    
    if not domains:
        print("无 DNS 解析数据")
        return
    
    # 统计顶级域名
    tlds = Counter()
    for domain in domains:
        domain_name = domain.get("domain", "")
        if "." in domain_name:
            tld = domain_name.split(".")[-1]
            tlds[tld] += 1
    
    print("顶级域名分布:")
    for tld, count in tlds.most_common(10):
        print(f"  .{tld}: {count}")
    
    print(f"\n解析详情:")
    for domain in domains[:10]:  # 显示前10个
        print(f"  {domain.get('domain', '未知')} -> {domain.get('ip', '未知')}")

def check_suspicious(network_data):
    """检查可疑活动"""
    print(f"\n可疑活动检查:")
    print("-" * 50)
    
    suspicious_count = 0
    
    # 检查 IRC
    irc_data = network_data.get("irc", [])
    if irc_data:
        print(f"⚠️  检测到 IRC 通信: {len(irc_data)} 条消息")
        suspicious_count += 1
    
    # 检查可疑端口
    suspicious_ports = [6667, 6697, 8080, 1337, 31337, 4444, 5555]
    for host in network_data.get("hosts", []):
        for port in host.get("ports", []):
            if port in suspicious_ports:
                print(f"⚠️  可疑端口通信: {host['ip']}:{port}")
                suspicious_count += 1
    
    # 检查大量请求
    http_count = len(network_data.get("http", []))
    if http_count > 100:
        print(f"⚠️  大量 HTTP 请求: {http_count} 个")
        suspicious_count += 1
    
    if suspicious_count == 0:
        print("✅ 未发现明显的可疑网络活动")

def is_internal_ip(ip):
    """检查是否为内网 IP"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def main():
    parser = argparse.ArgumentParser(description="CAPEv2 网络分析工具")
    parser.add_argument("task_id", help="任务 ID")
    parser.add_argument("--hosts", action="store_true", help="分析主机通信")
    parser.add_argument("--http", action="store_true", help="分析 HTTP 通信")
    parser.add_argument("--dns", action="store_true", help="分析 DNS 解析")
    parser.add_argument("--suspicious", action="store_true", help="检查可疑活动")
    parser.add_argument("--all", action="store_true", help="执行所有分析")
    
    args = parser.parse_args()
    
    # 加载数据
    network_data = load_network_data(args.task_id)
    if not network_data:
        sys.exit(1)
    
    print(f"分析任务 {args.task_id} 的网络数据")
    print(f"PCAP SHA256: {network_data.get('pcap_sha256', '未知')}")
    
    # 执行分析
    if args.all or args.hosts:
        analyze_hosts(network_data)
    
    if args.all or args.http:
        analyze_http(network_data)
    
    if args.all or args.dns:
        analyze_dns(network_data)
    
    if args.all or args.suspicious:
        check_suspicious(network_data)

if __name__ == "__main__":
    main()
```

### 3.2 使用示例

```bash
# 分析任务 123 的所有网络数据
python tools/network_analyzer.py 123 --all

# 只分析主机通信
python tools/network_analyzer.py 123 --hosts

# 检查可疑活动
python tools/network_analyzer.py 123 --suspicious

# 分析 HTTP 和 DNS 
python tools/network_analyzer.py 123 --http --dns
```

## 4. 高级用法和集成

### 4.1 与外部威胁情报集成

```python
# modules/reporting/threat_intel_network.py
class ThreatIntelNetworkReport(Report):
    """集成威胁情报的网络分析报告"""
    
    def run(self, results):
        network_data = results.get("network", {})
        if not network_data:
            return
        
        # 检查 IP 和域名
        self._check_threat_intel(network_data)
    
    def _check_threat_intel(self, network_data):
        """检查威胁情报"""
        
        # 检查主机 IP
        for host in network_data.get("hosts", []):
            ip = host["ip"]
            threat_info = self._query_threat_intel_ip(ip)
            if threat_info:
                log.warning(f"发现恶意 IP: {ip} - {threat_info}")
        
        # 检查域名
        for domain in network_data.get("domains", []):
            domain_name = domain["domain"]
            threat_info = self._query_threat_intel_domain(domain_name)
            if threat_info:
                log.warning(f"发现恶意域名: {domain_name} - {threat_info}")
    
    def _query_threat_intel_ip(self, ip):
        """查询 IP 威胁情报（示例）"""
        # 这里可以集成 VirusTotal, Shodan 等 API
        pass
    
    def _query_threat_intel_domain(self, domain):
        """查询域名威胁情报（示例）"""
        # 这里可以集成域名黑名单、威胁情报源等
        pass
```

### 4.2 网络行为模式匹配

```python
# modules/signatures/network_patterns.py
class SuspiciousNetworkPattern(Signature):
    """检测可疑网络模式"""
    name = "suspicious_network_pattern"
    description = "检测到可疑的网络通信模式"
    severity = 3
    categories = ["network"]
    
    def run(self):
        network_data = self.results.get("network", {})
        if not network_data:
            return False
        
        suspicious_indicators = 0
        
        # 检查 IRC 通信
        if network_data.get("irc"):
            self.data.append({"type": "irc", "description": "检测到 IRC 通信"})
            suspicious_indicators += 1
        
        # 检查可疑端口
        suspicious_ports = [1337, 31337, 4444, 5555]
        for host in network_data.get("hosts", []):
            for port in host.get("ports", []):
                if port in suspicious_ports:
                    self.data.append({
                        "type": "suspicious_port",
                        "description": f"与 {host['ip']}:{port} 通信"
                    })
                    suspicious_indicators += 1
        
        # 检查 DGA 域名模式
        domains = network_data.get("domains", [])
        for domain in domains:
            if self._is_dga_domain(domain["domain"]):
                self.data.append({
                    "type": "dga_domain", 
                    "description": f"可能的 DGA 域名: {domain['domain']}"
                })
                suspicious_indicators += 1
        
        return suspicious_indicators > 0
    
    def _is_dga_domain(self, domain):
        """检测可能的 DGA 生成域名"""
        # 简单的 DGA 检测逻辑
        if len(domain) > 20:  # 异常长的域名
            return True
        
        # 检查随机字符串模式
        import re
        if re.match(r'^[a-z]{10,}\.com$', domain):  # 长随机字符串
            return True
        
        return False
```

这个使用指南提供了在 CAPEv2 中访问和使用网络分析数据的完整方法，从基本的数据获取到高级的威胁情报集成。