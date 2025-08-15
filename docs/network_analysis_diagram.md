# CAPEv2 网络分析数据流图

## 数据流程图

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   分析开始       │    │  PCAP 文件捕获   │    │   处理模块发现   │
│   Task Start    │ -> │   dump.pcap     │ -> │  Plugin Loading │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                                                        v
┌─────────────────────────────────────────────────────────────────┐
│                    RunProcessing.run()                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ BehaviorAnalysis│  │ NetworkAnalysis │  │  AnalysisInfo   │ │
│  │      (order=1)  │  │     (order=1)   │  │    (order=2)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────┐
│                NetworkAnalysis.run()                           │
│                                                                 │
│  1. 检查 PCAP 文件存在性                                        │
│  2. 加载 JA3 指纹数据                                           │
│  3. ┌─────────────────┐                                        │
│     │  Pcap.run()     │ <- 主要解析入口                        │
│     │  解析网络包     │                                        │
│     └─────────────────┘                                        │
│  4. ┌─────────────────┐ (如果启用排序)                          │
│     │  Pcap.run()     │                                        │
│     │ (sorted PCAP)   │                                        │
│     └─────────────────┘                                        │
│  5. ┌─────────────────┐ (如果有 httpreplay)                    │
│     │  Pcap2.run()    │                                        │
│     │  (TLS 解密)     │                                        │
│     └─────────────────┘                                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────┐
│                    Pcap 解析过程                                │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Ethernet    │  │ IP Packet   │  │ Protocol    │             │
│  │ Frame       │->│ Parsing     │->│ Analysis    │             │
│  │ Analysis    │  │             │  │ (TCP/UDP)   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                           │                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────v─────┐  ┌──────────┐ │
│  │ HTTP        │  │ DNS         │  │ IRC       │  │ ICMP     │ │
│  │ Requests    │  │ Queries     │  │ Messages  │  │ Packets  │ │
│  └─────────────┘  └─────────────┘  └───────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────┐
│                   解析结果汇总                                  │
│                                                                 │
│  network = {                                                    │
│    "pcap_sha256": "abc123...",                                  │
│    "hosts": [...],                                              │
│    "domains": [...],                                            │
│    "http": [...],                                               │
│    "irc": [...],                                                │
│    "icmp": [...],                                               │
│    "tcp": [...],                                                │
│    "udp": [...]                                                 │
│  }                                                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────┐
│                    结果存储和分发                               │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ 内存存储     │  │ JSON 报告    │  │ 数据库存储   │             │
│  │ results     │->│ report.json │  │ MongoDB/    │             │
│  │ ["network"] │  │             │  │ Elasticsearch│             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────┐
│                       数据展示                                  │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Web 界面     │  │ API 接口     │  │ 报告模块     │             │
│  │ HTML 模板    │  │ JSON API    │  │ 自定义报告   │             │
│  │ 交互式展示   │  │ 程序化访问   │  │ 导出功能     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 详细调用时序图

```
时间线    │
         │
启动     │ utils/process.py: process_task()
         │   │
         │   └─> RunProcessing(task, results).run()
         │         │
发现     │         └─> list_plugins("processing")
         │               │
         │               └─> [NetworkAnalysis, BehaviorAnalysis, ...]
         │
排序     │         ┌─> processing_list.sort(key=lambda m: m.order)
         │         │
执行循环 │         └─> for module in processing_list:
         │               │
实例化   │               └─> current = NetworkAnalysis(results)
         │                    │
配置     │                    ├─> current.set_path(analysis_path)
         │                    ├─> current.set_task(task)
         │                    └─> current.set_options(options)
         │
开始解析 │                    ┌─> data = current.run()  # NetworkAnalysis.run()
         │                    │     │
PCAP检查 │                    │     ├─> 检查 self.pcap_path 存在性
         │                    │     ├─> 加载 JA3 指纹数据
         │                    │     │
主解析   │                    │     └─> Pcap(pcap_path, ja3, options).run()
         │                    │           │
包解析   │                    │           ├─> 打开 PCAP 文件
         │                    │           ├─> for 每个数据包:
         │                    │           │     ├─> 解析以太网帧
         │                    │           │     ├─> 解析 IP 包
         │                    │           │     ├─> 解析 TCP/UDP
         │                    │           │     └─> 识别应用层协议
         │                    │           │
结果生成 │                    │           └─> 生成 hosts, domains, http 等
         │                    │
排序解析 │                    │     ┌─> if sort_pcap:
(可选)   │                    │     │     └─> Pcap(sorted_path, ...).run()
         │                    │     │
TLS解析  │                    │     └─> if HAVE_HTTPREPLAY:
(可选)   │                    │           └─> Pcap2(pcap_path, tls_master).run()
         │                    │
返回     │                    └─> return {"network": data}
         │
合并     │         └─> results.update({"network": data})
         │
报告     │ RunReporting(task, results).run()
         │   │
JSON     │   ├─> JsonDump: 写入 report.json
         │   ├─> MongoDB: 存入数据库
         │   └─> 其他报告模块
         │
完成     │ 分析完成，数据可供查询
```

## 文件系统结构

```
storage/analyses/{task_id}/
├── dump.pcap              # 网络数据包捕获
├── dump_sorted.pcap       # 排序后的 PCAP (可选)
├── network/               # 网络相关文件目录
│   └── tlsmaster.txt     # TLS 主密钥 (可选)
├── reports/
│   ├── report.json       # 包含 network 字段的完整报告
│   └── report.html       # 网页报告
└── logs/                 # 行为日志
```

## 数据库存储结构

```
MongoDB Collection: analysis
{
  "_id": ObjectId("..."),
  "info": {
    "id": 123,
    "started": "2023-...",
    ...
  },
  "network": {              # NetworkAnalysis 输出
    "pcap_sha256": "...",
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
    "http": [...],
    "irc": [...],
    "icmp": [...]
  },
  "behavior": {...},        # BehaviorAnalysis 输出
  "static": {...},          # 静态分析输出
  ...
}
```

## 配置影响流程

```
processing.conf
├── [network]
│   ├── enabled = yes      -> NetworkAnalysis 被执行
│   ├── sort_pcap = yes    -> 额外的排序 PCAP 解析
│   ├── country_lookup     -> 地理位置信息添加
│   └── dnswhitelist       -> DNS 白名单过滤
│
├── [behavior]
│   └── enabled = yes      -> BehaviorAnalysis 被执行
│
└── [static]
    └── enabled = yes      -> StaticAnalysis 被执行
```

这个流程图清晰地展示了从 PCAP 文件捕获到最终数据展示的整个过程，以及各个组件之间的关系。