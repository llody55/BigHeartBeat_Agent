# BigHeartBeat_Agent

## 简介

> 客户端主要用于将局域网**exporter**相关组件指标聚合并推送到**BigHeartBeat**后转发到**VictoriaMetrics**

## 客户端配置文件

```yaml
# VictoriaMetrics 的上报地址
#victoria_metrics_url: "http://192.168.1.160:5001/report"
# nginx代理+token认证
victoria_metrics_url: "http://192.168.1.225:31037/report"

# 任务名称，用于标识监控任务
job_name: "system_monitoring"

# 数据上报间隔（单位：秒）
report_interval: 5

# 数据压缩方式,默认不压缩，可选值：none, gzip, zstd
compression: none

# 抓取目标配置，类似于 vmagent 的 scrape_configs
scrape_configs:
  - job_name: "node_exporter"
    static_configs:
      - targets: ["192.168.1.217:9100","192.168.1.218:9100","192.168.1.243:9100"]
  - job_name: "cadvisor"
    static_configs:
      - targets: ["192.168.1.217:8386","192.168.1.218:8386","192.168.1.243:8386"]

# 可选：认证令牌
auth_token: "t7HXW3jVgfD74VDw="

# 项目名称
project: "system_monitor"
labels:
  project: "system_monitor"  # 必须与 project 字段一致
  account: "技术部"
  env: "dev"
  region: "cd-1"

```

## 客户端环境变量

| 环境变量名        | 数值类型 | 说明                                       | 示例                                     |
| ----------------- | -------- | ------------------------------------------ | ---------------------------------------- |
| HOST_ID           |          | 指定主机唯一标识符，覆盖本地存储的 host_id | export HOST_ID="123e4567-e89b-12d3-a456" |
| HOST_ID_FILE_PATH |          | 指定存储 host_id 的文件路径                | export HOST_ID_FILE_PATH="/etc/host_id"  |
| PUBLIC_IP         |          | 手动指定公网 IP 地址，覆盖自动获取逻辑     | export PUBLIC_IP="203.0.113.1"           |

## 部署示例

### 创建持久化目录

```bash
[root@consul BigHeartBeatMaxPro_agent]# mkdir -p /data/bigheartbeat_agent/{data,conf}
[root@consul BigHeartBeatMaxPro_agent]# chown -R 1000:1000 /data/bigheartbeat_agent/*
```

### docker启动命令

```bash
[root@consul BigHeartBeatMaxPro_agent]# docker run -itd --network host -v /data/bigheartbeat_agent/data:/app/data -v /data/bigheartbeat_agent/conf:/app/conf -v /proc:/proc -v /sys:/sys  swr.cn-southwest-2.myhuaweicloud.com/llody/bigheartbeat_agent:v0.1.2-amd64
2025-09-19 03:24:45 - INFO - 成功获取公网IP: 
2025-09-19 03:24:45 - INFO - 主机信息: {'system': 'Linux', 'release': '3.10.0-1160.66.1.el7.x86_64', 'version': '#1 SMP Wed May 18 16:02:34 UTC 2022', 'machine': 'x86_64', 'processor': '', 'python_version': '3.10.2', 'cpu_count': 4, 'memory_total': 17.156105041503906, 'disk_total': 455.9881782531738, 'boot_time': '2025-07-29T14:40:17'}
```
