# CAPEv2 NetworkAnalysis 和 Pcap 调用与数据存储完整分析

## 文档概述

本文档集合回答了关于 CAPEv2 中 `NetworkAnalysis` 和 `Pcap` 类调用位置以及解析后数据存储的核心问题。

## 📋 问题解答总结

### 🔍 **项目中哪里调用了 NetworkAnalysis 或者 Pcap 进行网络数据包的解析？**

#### 1. **自动插件发现机制**
- **位置**: `lib/cuckoo/core/plugins.py`
- **过程**: CAPEv2 使用插件系统自动发现继承自 `Processing` 基类的所有处理模块
- **触发**: `NetworkAnalysis` 类因继承 `Processing` 而被自动注册到 `processing` 插件组

#### 2. **主要调用入口**
- **位置**: `utils/process.py` → `process_task()` 函数
- **调用链**:
  ```
  process_task() 
    → RunProcessing(task, results).run()
    → list_plugins("processing") 
    → NetworkAnalysis 实例化和执行
  ```

#### 3. **NetworkAnalysis 执行流程**
- **位置**: `modules/processing/network.py` → `NetworkAnalysis.run()`
- **具体调用**:
  ```python
  # 主要 PCAP 解析
  results.update(Pcap(self.pcap_path, ja3_fprints, self.options).run())
  
  # 排序 PCAP 解析（可选）
  if proc_cfg.network.sort_pcap:
      results.update(Pcap(sorted_path, ja3_fprints, self.options).run())
  
  # TLS 解密解析（可选）
  if HAVE_HTTPREPLAY:
      p2_results = Pcap2(self.pcap_path, tls_master, self.network_path).run()
  ```

#### 4. **配置控制**
- **配置文件**: `conf/default/processing.conf.default`
- **关键配置**: `[network]` 部分的 `enabled = yes`

### 📊 **解析后的数据具体又在哪里？**

#### 1. **内存中的数据流转**
```
Pcap.run() 解析结果 
  ↓
NetworkAnalysis.run() 返回 
  ↓  
RunProcessing.process() 
  ↓
合并到 results["network"]
  ↓
传递给报告模块
```

#### 2. **持久化存储位置**

##### **文件系统存储**
- **JSON 报告**: `storage/analyses/{task_id}/reports/report.json`
  - 数据位置: `results["network"]` 部分
  - 负责模块: `modules/reporting/jsondump.py`

##### **数据库存储**
- **MongoDB**: 由 `modules/reporting/mongodb.py` 存储
  - 集合: `analysis`
  - 字段: `network` 对象
  
- **Elasticsearch**: 由 `modules/reporting/elasticsearchdb.py` 索引
  - 索引: 分析结果索引
  - 支持复杂查询

#### 3. **Web 界面展示**
- **后端**: `web/analysis/views.py` 
  - 导入: `import modules.processing.network as network`
  - 数据获取: 从 MongoDB 或文件系统读取 `results["network"]`

- **前端**: `data/html/sections/network.html`
  - 显示: 主机列表、DNS 解析、HTTP 请求、IRC 通信、ICMP 数据

#### 4. **API 接口**
- **REST API**: `web/apiv2/views.py`
- **数据格式**: JSON 格式的网络分析结果
- **访问方式**: 通过任务 ID 获取网络数据

## 📁 相关文档文件

### 1. **主要分析文档**
- [`network_analysis_flow.md`](./network_analysis_flow.md) - 完整的调用流程和数据存储分析
- [`network_analysis_diagram.md`](./network_analysis_diagram.md) - 可视化数据流程图
- [`network_analysis_examples.md`](./network_analysis_examples.md) - 详细的代码示例
- [`network_data_usage_guide.md`](./network_data_usage_guide.md) - 实用的数据访问指南

### 2. **核心源码文件**
- `modules/processing/network.py` - NetworkAnalysis 和 Pcap 核心实现
- `lib/cuckoo/core/plugins.py` - 插件发现和执行机制
- `utils/process.py` - 任务处理入口
- `web/analysis/views.py` - Web 界面数据获取
- `modules/reporting/jsondump.py` - JSON 报告生成

## 🔧 数据结构概览

### 网络分析结果完整结构
```json
{
  "network": {
    "pcap_sha256": "文件哈希值",
    "sorted_pcap_sha256": "排序后文件哈希值（可选）",
    "hosts": [
      {
        "ip": "IP地址",
        "country_name": "国家名称",
        "hostname": "主机名",
        "ports": [端口列表]
      }
    ],
    "domains": [
      {
        "domain": "域名",
        "ip": "解析IP"
      }
    ],
    "http": [
      {
        "method": "HTTP方法",
        "host": "主机",
        "uri": "请求路径",
        "user-agent": "用户代理",
        "request": "完整请求",
        "response": "完整响应"
      }
    ],
    "irc": [IRC通信数据],
    "icmp": [ICMP数据包],
    "tcp": [TCP流数据],
    "udp": [UDP数据包]
  }
}
```

## 🚀 快速开始

### 1. **查看网络分析配置**
```bash
cat conf/processing.conf | grep -A 10 "\[network\]"
```

### 2. **检查任务的网络数据**
```bash
# 查看 JSON 报告中的网络部分
cat storage/analyses/{TASK_ID}/reports/report.json | jq '.network'
```

### 3. **通过 API 获取网络数据**
```bash
curl -X GET "http://cape-server/apiv2/tasks/{TASK_ID}/network"
```

### 4. **在 Python 中访问**
```python
# 从文件读取
import json
with open(f"storage/analyses/{task_id}/reports/report.json") as f:
    data = json.load(f)
    network_data = data.get("network", {})

# 从 MongoDB 读取（如果启用）
from dev_utils.mongodb import mongo_find_one
analysis = mongo_find_one({"info.id": task_id}, {"network": 1})
network_data = analysis.get("network", {}) if analysis else {}
```

## 📈 使用场景

### 1. **威胁分析**
- 识别外部通信的恶意 IP 和域名
- 检测异常端口通信
- 分析 HTTP 流量模式

### 2. **取证调查**
- 重构网络通信时间线
- 分析数据泄露路径
- 追踪 C&C 通信

### 3. **自动化检测**
- 集成 IOC 匹配
- 网络行为签名检测
- 威胁情报关联

### 4. **报告生成**
- 自定义网络分析报告
- 图表和可视化
- 导出和分享

## ⚙️ 扩展和定制

### 1. **自定义 Pcap 解析器**
- 继承 `Pcap` 类
- 添加新的协议解析器
- 扩展数据提取逻辑

### 2. **增强报告模块**
- 创建专门的网络报告模块
- 集成外部威胁情报 API
- 添加自定义分析逻辑

### 3. **API 扩展**
- 添加网络数据过滤接口
- 实现实时网络监控
- 提供批量分析功能

## 🔗 相关链接

- [CAPEv2 官方文档](https://github.com/kevoreilly/CAPEv2)
- [处理模块开发指南](docs/book/src/customization/processing.rst)
- [API 文档](docs/book/src/usage/api.rst)

---

**注意**: 本文档基于 CAPEv2 当前版本编写，具体实现可能随版本更新而变化。建议结合源码进行深入理解。