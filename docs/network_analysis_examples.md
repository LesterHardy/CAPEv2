# NetworkAnalysis 和 Pcap 调用示例代码

## 1. 实际调用代码示例

### 1.1 插件加载和发现过程

```python
# 在 lib/cuckoo/core/plugins.py 中
def load_plugins(module):
    """自动发现和注册处理插件"""
    for _, value in inspect.getmembers(module):
        if inspect.isclass(value):
            # NetworkAnalysis 类会被自动发现，因为它继承自 Processing
            if issubclass(value, Processing) and value is not Processing:
                register_plugin("processing", value)
                print(f"Registered processing plugin: {value.__name__}")

# 示例输出：
# Registered processing plugin: NetworkAnalysis
# Registered processing plugin: BehaviorAnalysis
# Registered processing plugin: AnalysisInfo
# ...
```

### 1.2 处理模块执行示例

```python
# 在 lib/cuckoo/core/plugins.py - RunProcessing 类中
class RunProcessing:
    def run(self):
        """运行所有处理模块"""
        processing_list = list_plugins(group="processing")
        # processing_list 包含: [NetworkAnalysis, BehaviorAnalysis, AnalysisInfo, ...]
        
        if processing_list:
            # 按 order 属性排序（NetworkAnalysis.order = 1）
            processing_list.sort(key=lambda module: module.order)
            
            for module in processing_list:
                print(f"Processing with module: {module.__name__}")
                result = self.process(module)
                if result:
                    self.results.update(result)
                    print(f"Updated results with key: {list(result.keys())}")

    def process(self, module):
        """处理单个模块 - 以 NetworkAnalysis 为例"""
        # 实例化 NetworkAnalysis
        current = module(self.results)  # NetworkAnalysis(self.results)
        
        # 设置分析路径（例如: /opt/cape/storage/analyses/123/）
        current.set_path(self.analysis_path)
        
        # 设置任务信息
        current.set_task(self.task)
        
        # 从 processing.conf 的 [network] 部分加载配置
        current.set_options(options)
        
        print(f"Executing {current.__class__.__name__}.run()")
        
        # 调用 NetworkAnalysis.run() 方法
        data = current.run()
        
        # 返回格式: {"network": {...network_analysis_data...}}
        return {current.key: data}
```

### 1.3 NetworkAnalysis.run() 具体执行

```python
# 在 modules/processing/network.py 中
class NetworkAnalysis(Processing):
    key = "network"
    
    def run(self):
        print(f"Starting network analysis for PCAP: {self.pcap_path}")
        
        # 检查 PCAP 文件是否存在
        if not path_exists(self.pcap_path):
            print(f"PCAP file not found: {self.pcap_path}")
            return {}
        
        # 加载 JA3 指纹数据
        ja3_fprints = self._import_ja3_fprints()
        print(f"Loaded {len(ja3_fprints)} JA3 fingerprints")
        
        # 初始化结果字典
        results = {"pcap_sha256": File(self.pcap_path).get_sha256()}
        
        # 核心：调用 Pcap 类解析网络数据
        print("Calling Pcap.run() for main analysis")
        pcap_results = Pcap(self.pcap_path, ja3_fprints, self.options).run()
        results.update(pcap_results)
        
        # 如果启用了 PCAP 排序
        if proc_cfg.network.sort_pcap:
            sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
            sort_pcap(self.pcap_path, sorted_path)
            if path_exists(sorted_path):
                print("Calling Pcap.run() for sorted PCAP")
                sorted_results = Pcap(sorted_path, ja3_fprints, self.options).run()
                results.update(sorted_results)
        
        # 如果有 httpreplay 支持，进行 TLS 解密
        if HAVE_HTTPREPLAY:
            try:
                tls_master = self.get_tlsmaster()
                if tls_master:
                    print("Calling Pcap2.run() for TLS decryption")
                    p2_results = Pcap2(self.pcap_path, tls_master, self.network_path).run()
                    if p2_results:
                        results.update(p2_results)
            except Exception as e:
                print(f"Error in TLS decryption: {e}")
        
        print(f"Network analysis completed. Found {len(results.get('hosts', []))} hosts")
        return results
```

## 2. Pcap 类详细解析过程

```python
# 在 modules/processing/network.py 中
class Pcap:
    def __init__(self, pcap_path, ja3_fprints=None, options=None):
        self.pcap_path = pcap_path
        self.ja3_fprints = ja3_fprints or {}
        self.options = options or {}
        
        # 初始化各种协议解析器
        self.connections = {}
        self.dns_requests = {}
        self.http_requests = []
        self.irc_requests = []
        self.icmp_requests = []
    
    def run(self):
        """主要的 PCAP 解析方法"""
        print(f"Parsing PCAP file: {self.pcap_path}")
        
        try:
            # 使用 dpkt 打开 PCAP 文件
            with open(self.pcap_path, "rb") as pcap_file:
                pcap_reader = dpkt.pcap.Reader(pcap_file)
                
                packet_count = 0
                for timestamp, packet in pcap_reader:
                    packet_count += 1
                    
                    # 解析以太网帧
                    try:
                        eth = dpkt.ethernet.Ethernet(packet)
                        if isinstance(eth.data, dpkt.ip.IP):
                            self._parse_ip_packet(eth.data, timestamp)
                    except Exception as e:
                        print(f"Error parsing packet {packet_count}: {e}")
                        continue
                
                print(f"Processed {packet_count} packets")
        
        except Exception as e:
            print(f"Error opening PCAP file: {e}")
            return {}
        
        # 生成最终结果
        results = {
            "hosts": self._generate_hosts_list(),
            "domains": self._generate_domains_list(),
            "http": self.http_requests,
            "irc": self.irc_requests,
            "icmp": self.icmp_requests,
            "tcp": self._generate_tcp_streams(),
            "udp": self._generate_udp_streams(),
        }
        
        print(f"Generated network analysis results:")
        print(f"  - {len(results['hosts'])} unique hosts")
        print(f"  - {len(results['domains'])} domain resolutions")
        print(f"  - {len(results['http'])} HTTP requests")
        print(f"  - {len(results['irc'])} IRC messages")
        print(f"  - {len(results['icmp'])} ICMP packets")
        
        return results
    
    def _parse_ip_packet(self, ip_packet, timestamp):
        """解析 IP 数据包"""
        src_ip = socket.inet_ntoa(ip_packet.src)
        dst_ip = socket.inet_ntoa(ip_packet.dst)
        
        # 记录主机信息
        self._record_host(src_ip)
        self._record_host(dst_ip)
        
        # 根据协议类型进行具体解析
        if isinstance(ip_packet.data, dpkt.tcp.TCP):
            self._parse_tcp_packet(ip_packet, timestamp)
        elif isinstance(ip_packet.data, dpkt.udp.UDP):
            self._parse_udp_packet(ip_packet, timestamp)
        elif isinstance(ip_packet.data, dpkt.icmp.ICMP):
            self._parse_icmp_packet(ip_packet, timestamp)
```

## 3. 数据访问示例

### 3.1 在 Web 界面中访问网络数据

```python
# 在 web/analysis/views.py 中
def analysis_full(request, task_id):
    """分析详情页面"""
    
    # 从数据库或文件系统获取分析结果
    analysis = get_analysis_results(task_id)
    
    # 访问网络分析数据
    network_data = analysis.get("network", {})
    
    if network_data:
        print("Network analysis available:")
        print(f"  PCAP SHA256: {network_data.get('pcap_sha256')}")
        print(f"  Hosts contacted: {len(network_data.get('hosts', []))}")
        print(f"  DNS resolutions: {len(network_data.get('domains', []))}")
        print(f"  HTTP requests: {len(network_data.get('http', []))}")
        
        # 获取具体的网络活动
        for host in network_data.get('hosts', []):
            print(f"  Host: {host['ip']} ({host.get('country_name', 'Unknown')})")
        
        for domain in network_data.get('domains', []):
            print(f"  DNS: {domain['domain']} -> {domain['ip']}")
        
        for http_req in network_data.get('http', []):
            print(f"  HTTP: {http_req['method']} {http_req.get('host', '')}{http_req.get('uri', '')}")
    
    return render(request, 'analysis/report.html', {
        'network': network_data,
        # ... 其他数据
    })
```

### 3.2 在报告模块中访问网络数据

```python
# 在 modules/reporting/custom_network_report.py 中
class CustomNetworkReport(Report):
    def run(self, results):
        """生成自定义网络报告"""
        
        # 获取网络分析数据
        network_data = results.get("network", {})
        
        if not network_data:
            print("No network data available")
            return
        
        # 分析网络活动模式
        hosts = network_data.get("hosts", [])
        external_hosts = [host for host in hosts if not self._is_internal_ip(host["ip"])]
        
        print(f"External communications:")
        for host in external_hosts:
            ports = host.get("ports", [])
            print(f"  {host['ip']} (ports: {', '.join(map(str, ports))})")
        
        # 分析 HTTP 流量
        http_requests = network_data.get("http", [])
        unique_domains = set()
        for req in http_requests:
            if "host" in req:
                unique_domains.add(req["host"])
        
        print(f"HTTP communications to {len(unique_domains)} unique domains:")
        for domain in sorted(unique_domains):
            print(f"  {domain}")
        
        # 检查可疑网络活动
        suspicious_activity = []
        
        # 检查 IRC 通信
        irc_data = network_data.get("irc", [])
        if irc_data:
            suspicious_activity.append(f"IRC communication detected: {len(irc_data)} messages")
        
        # 检查异常端口
        for host in hosts:
            for port in host.get("ports", []):
                if port in [6667, 6697, 8080, 1337, 31337]:  # 常见恶意软件端口
                    suspicious_activity.append(f"Communication on suspicious port {port} to {host['ip']}")
        
        if suspicious_activity:
            print("Suspicious network activity detected:")
            for activity in suspicious_activity:
                print(f"  - {activity}")
    
    def _is_internal_ip(self, ip):
        """检查是否为内网 IP"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
```

### 3.3 通过 API 访问网络数据

```python
# API 端点示例
@api_view(['GET'])
def get_network_analysis(request, task_id):
    """获取网络分析 API"""
    
    try:
        # 从数据库获取任务结果
        task = Task.objects.get(id=task_id)
        results = get_task_results(task_id)
        
        network_data = results.get("network", {})
        
        # 构建 API 响应
        response_data = {
            "task_id": task_id,
            "pcap_available": bool(network_data),
            "summary": {
                "total_hosts": len(network_data.get("hosts", [])),
                "total_domains": len(network_data.get("domains", [])),
                "total_http_requests": len(network_data.get("http", [])),
                "pcap_sha256": network_data.get("pcap_sha256"),
            },
            "details": {
                "hosts": network_data.get("hosts", []),
                "domains": network_data.get("domains", []),
                "http": network_data.get("http", []),
                "irc": network_data.get("irc", []),
                "icmp": network_data.get("icmp", []),
            }
        }
        
        return JsonResponse({
            "error": False,
            "data": response_data
        })
        
    except Task.DoesNotExist:
        return JsonResponse({
            "error": True,
            "message": f"Task {task_id} not found"
        })
    except Exception as e:
        return JsonResponse({
            "error": True,
            "message": str(e)
        })
```

## 4. 配置示例

### 4.1 processing.conf 配置示例

```ini
[network]
# 启用网络分析
enabled = yes

# 是否对 PCAP 进行时间排序（有助于分析时序）
sort_pcap = yes

# DNS 白名单功能
dnswhitelist = yes
dnswhitelist_file = extra/whitelist_domains.txt

# IP 白名单功能
ipwhitelist = yes
ipwhitelist_file = extra/whitelist_ips.txt

# 地理位置查询
country_lookup = yes
maxmind_database = data/GeoLite2-Country.mmdb

# JA3 指纹识别
ja3_file = data/ja3/ja3fingerprint.json
```

### 4.2 白名单文件示例

```text
# extra/whitelist_domains.txt
microsoft.com
windows.com
google.com
github.com

# extra/whitelist_ips.txt
8.8.8.8
8.8.4.4
1.1.1.1
```

## 5. 调试和监控

### 5.1 启用详细日志

```python
# 在 NetworkAnalysis 中添加调试信息
import logging

log = logging.getLogger(__name__)

class NetworkAnalysis(Processing):
    def run(self):
        log.debug(f"Starting network analysis for task {self.task['id']}")
        log.debug(f"PCAP file: {self.pcap_path}")
        log.debug(f"PCAP size: {os.path.getsize(self.pcap_path)} bytes")
        
        # ... 解析过程 ...
        
        log.debug(f"Network analysis completed in {time.time() - start_time:.2f} seconds")
        return results
```

### 5.2 性能监控

```python
# 在 lib/cuckoo/core/plugins.py 中
def process(self, module):
    import timeit
    
    current = module(self.results)
    current.set_path(self.analysis_path)
    current.set_task(self.task)
    current.set_options(options)
    
    # 记录执行时间
    pretime = timeit.default_timer()
    data = current.run()
    timediff = timeit.default_timer() - pretime
    
    # 添加到统计信息
    self.results["statistics"]["processing"].append({
        "name": current.__class__.__name__,
        "time": round(timediff, 3)
    })
    
    log.debug(f"Module {current.__class__.__name__} completed in {timediff:.3f} seconds")
    
    return {current.key: data}
```

这些代码示例展示了 NetworkAnalysis 和 Pcap 类在 CAPEv2 中的完整调用链路和数据使用方式。