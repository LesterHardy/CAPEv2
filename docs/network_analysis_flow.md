# CAPEv2 网络分析模块调用流程和数据存储分析

## 概述

本文档详细分析了 CAPEv2 中 `NetworkAnalysis` 和 `Pcap` 类的调用位置以及解析后的数据存储位置。

## 1. 核心网络处理模块

### 1.1 主要类定义
- **文件位置**: `modules/processing/network.py`
- **主要类**:
  - `NetworkAnalysis`: 网络分析的主要协调器，继承自 `Processing` 基类
  - `Pcap`: PCAP 文件读取和解析的核心类
  - `Pcap2`: 基于 httpreplay 库的高级 PCAP 解析类（用于 TLS 解密）

### 1.2 NetworkAnalysis 类结构
```python
class NetworkAnalysis(Processing):
    """Network analysis."""
    key = "network"  # 结果字典中的键名
    
    def run(self):
        # 1. 检查 PCAP 文件是否存在
        # 2. 导入 JA3 指纹数据
        # 3. 调用 Pcap 类解析网络数据
        # 4. 如果启用排序，处理排序后的 PCAP
        # 5. 如果有 httpreplay，使用 Pcap2 进行 TLS 解密
```

## 2. 插件发现和加载机制

### 2.1 插件系统核心文件
**文件位置**: `lib/cuckoo/core/plugins.py`

### 2.2 插件发现流程
```python
def load_plugins(module):
    """扫描模块并注册处理插件"""
    for _, value in inspect.getmembers(module):
        if inspect.isclass(value):
            # NetworkAnalysis 继承自 Processing，所以会被自动注册
            elif issubclass(value, Processing) and value is not Processing:
                register_plugin("processing", value)

def list_plugins(group=None):
    """获取指定类型的所有插件"""
    if group:
        return _modules[group]  # 返回所有 processing 插件
    return _modules
```

### 2.3 处理模块执行
**文件位置**: `lib/cuckoo/core/plugins.py` - `RunProcessing` 类

```python
class RunProcessing:
    def run(self):
        # 获取所有处理模块
        processing_list = list_plugins(group="processing")
        
        if processing_list:
            # 按 order 属性排序
            processing_list.sort(key=lambda module: module.order)
            
            # 依次运行每个处理模块
            for module in processing_list:
                result = self.process(module)  # 这里会调用 NetworkAnalysis
                if result:
                    self.results.update(result)  # 合并结果到主结果字典

    def process(self, module):
        """运行单个处理模块"""
        # 实例化模块（例如 NetworkAnalysis）
        current = module(self.results)
        
        # 设置配置和路径
        current.set_path(self.analysis_path)
        current.set_task(self.task)
        current.set_options(options)
        
        # 执行模块的 run() 方法
        data = current.run()
        
        # 返回 {module.key: data} 格式的结果
        return {current.key: data}  # 对于 NetworkAnalysis，key = "network"
```

## 3. 具体调用位置

### 3.1 主要调用入口
**文件位置**: `utils/process.py`

```python
def process_task(task_id, ...):
    """处理单个分析任务"""
    results = {"statistics": {"processing": [], "signatures": [], "reporting": []}}
    
    # 运行所有处理模块，包括 NetworkAnalysis
    with db.session.begin():
        RunProcessing(task=task_dict, results=results).run()
    
    # 运行签名检测
    RunSignatures(task=task_dict, results=results).run()
    
    # 运行报告生成
    if report:
        RunReporting(task=task.to_dict(), results=results, reprocess=reprocess).run()
```

### 3.2 NetworkAnalysis 执行流程
当 `RunProcessing` 执行到 `NetworkAnalysis` 时：

1. **实例化**: `current = NetworkAnalysis(self.results)`
2. **配置设置**: 从 `processing.conf` 的 `[network]` 部分加载配置
3. **路径设置**: `self.pcap_path` 指向 `dump.pcap` 文件
4. **执行解析**: `NetworkAnalysis.run()` 方法被调用

### 3.3 Pcap 类调用
在 `NetworkAnalysis.run()` 方法中：

```python
def run(self):
    # ... 前置检查 ...
    
    # 主要的 PCAP 解析
    results.update(Pcap(self.pcap_path, ja3_fprints, self.options).run())
    
    # 如果启用排序 PCAP
    if proc_cfg.network.sort_pcap:
        sorted_path = self.pcap_path.replace("dump.", "dump_sorted.")
        sort_pcap(self.pcap_path, sorted_path)
        if path_exists(sorted_path):
            results.update(Pcap(sorted_path, ja3_fprints, self.options).run())
    
    # 如果有 httpreplay 支持
    if HAVE_HTTPREPLAY:
        p2 = Pcap2(self.pcap_path, tls_master, self.network_path).run()
        if p2:
            results.update(p2)
    
    return results
```

## 4. 配置和启用

### 4.1 配置文件
**文件位置**: `conf/default/processing.conf.default`

```ini
[network]
enabled = yes           # 启用网络分析
sort_pcap = no         # 是否对 PCAP 进行排序
dnswhitelist = yes     # DNS 白名单
country_lookup = no    # 地理位置查询
```

### 4.2 模块启用条件
- `enabled = yes` 在配置文件中
- PCAP 文件存在于分析目录（通常是 `dump.pcap`）
- 安装了 `dpkt` 库（`IS_DPKT = True`）

## 5. 解析后数据存储位置

### 5.1 内存中的数据流
```
NetworkAnalysis.run() 
    ↓ 
返回解析结果 
    ↓ 
RunProcessing.process() 
    ↓ 
结果合并到 results["network"] 
    ↓ 
传递给报告模块
```

### 5.2 持久化存储

#### 5.2.1 JSON 报告
**文件位置**: `modules/reporting/jsondump.py`
- **存储路径**: `storage/analyses/{task_id}/reports/report.json`
- **数据位置**: `results["network"]` 部分
- **内容**: 完整的网络分析结果，包括：
  - `hosts`: 涉及的主机信息
  - `domains`: DNS 查询结果
  - `http`: HTTP 请求和响应
  - `irc`: IRC 通信
  - `icmp`: ICMP 请求
  - `pcap_sha256`: PCAP 文件哈希

#### 5.2.2 MongoDB 存储
**文件位置**: `modules/reporting/mongodb.py`
```python
def run(self, results):
    # 确保 network 字段存在
    if "network" not in report:
        report["network"] = {}
    
    # 存储到 MongoDB 集合中
```

#### 5.2.3 Elasticsearch 存储
**文件位置**: `modules/reporting/elasticsearchdb.py`
- 网络数据作为分析结果的一部分被索引
- 支持复杂的网络数据搜索和分析

### 5.3 Web 界面显示

#### 5.3.1 后端数据获取
**文件位置**: `web/analysis/views.py`
```python
import modules.processing.network as network

def analysis_full(request, task_id):
    # 从数据库或文件系统获取分析结果
    # results["network"] 包含所有网络分析数据
```

#### 5.3.2 前端展示
**文件位置**: `data/html/sections/network.html`
- **显示内容**:
  - 涉及的主机列表
  - DNS 解析结果
  - HTTP 请求和响应详情
  - IRC 通信记录
  - ICMP 请求信息

## 6. 数据结构示例

### 6.1 网络分析结果结构
```json
{
  "network": {
    "pcap_sha256": "abc123...",
    "hosts": [
      {
        "ip": "192.168.1.100",
        "country_name": "Unknown",
        "hostname": "example.com",
        "ports": [80, 443]
      }
    ],
    "domains": [
      {
        "domain": "example.com",
        "ip": "192.168.1.100"
      }
    ],
    "http": [
      {
        "method": "GET",
        "uri": "/path",
        "host": "example.com",
        "request": "...",
        "response": "..."
      }
    ],
    "irc": [...],
    "icmp": [...]
  }
}
```

## 7. 总结

### 7.1 调用链路总结
1. **启动**: `utils/process.py` → `RunProcessing.run()`
2. **发现**: `list_plugins("processing")` → 获取包括 `NetworkAnalysis` 在内的所有处理模块
3. **执行**: `RunProcessing.process(NetworkAnalysis)` → 实例化并调用 `NetworkAnalysis.run()`
4. **解析**: `NetworkAnalysis.run()` → 调用 `Pcap(pcap_path).run()` 解析网络数据
5. **存储**: 结果返回并合并到 `results["network"]`

### 7.2 数据存储总结
- **临时存储**: 内存中的 `results` 字典
- **JSON 文件**: `storage/analyses/{task_id}/reports/report.json`
- **数据库**: MongoDB 或 Elasticsearch（如果配置）
- **Web 展示**: 通过 Django 视图和 HTML 模板展示

### 7.3 关键文件列表
- **核心解析**: `modules/processing/network.py`
- **插件系统**: `lib/cuckoo/core/plugins.py`
- **执行入口**: `utils/process.py`
- **配置文件**: `conf/default/processing.conf.default`
- **Web 界面**: `web/analysis/views.py`, `data/html/sections/network.html`
- **报告模块**: `modules/reporting/jsondump.py`, `modules/reporting/mongodb.py`

这个分析流程展示了 CAPEv2 中网络分析模块的完整生命周期，从 PCAP 文件捕获到最终的数据展示。