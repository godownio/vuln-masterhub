---
id: web-generic-ssrf-grafana-datasource-iam-credentials
title: Grafana 数据源配置 SSRF：admin/弱口令下用 grafana-ssrf 添加数据源，读取云 IAM 临时凭据
type: scenario
domain: web
path: web/generic/ssrf
technique: grafana-datasource-config-ssrf-iam-credentials
tags:
- web
- ssrf
- grafana
- cloud
- iam
- datasource
- weak-password
- internal-network
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T17:02:26+08:00'
  notes: 已对照原文全文与6张图核对。原文 Grafana 段：数据源配置可实现 SSRF、工具 github RandomRobbieBF/grafana-ssrf；图01 显示 python3.8 grafana-ssrf.py -H https://... -U admin -P admin -u http://.../latest/iam/security_credentials，输出 Source Created→Refreshed Sources→SSRF Source Updated、Status code 200、Response body 可见 RoleForECS 字样，与卡片命令/前置条件/回显描述一致。卡片未虚构原文没有的数据源类型，仅以 Prometheus/Elasticsearch 举例说明数据源机制。dedup=new，top 候选 web-generic-ssrf-cloud-metadata 为通用概览卡、web-generic-file-inclusion-grafana-cve-2021-43798-* 为目录穿越 CVE，均非同链。原文未标 Grafana/工具版本，affected_versions 留空正确。未对任何目标发起请求。
url: /docs/web/generic/ssrf/web-generic-ssrf-grafana-datasource-iam-credentials/
draft: false
kb_aliases:
- grafana-ssrf
- Grafana 数据源 SSRF
- Grafana admin admin
- Grafana 读取 IAM
- Grafana 内网探测
---

## 一句话结论

Grafana 允许管理员配置数据源并由服务端发起连接；当 Grafana 暴露在公网且使用 admin/admin 等弱口令时，攻击者可用 grafana-ssrf 工具创建/更新一个指向云元数据 IAM 凭据接口的数据源并触发查询，服务端返回的 AccessKeyId/SecretAccessKey/SessionToken 直接回显在工具输出中。

## 原理

- 数据源是 Grafana 的服务端能力：Prometheus/Elasticsearch 等数据源 URL 由服务端填写并连接，管理员保存后可通过“Save & test”或查询面板让 Grafana 后端向该 URL 发起请求。
- 把数据源 URL 指向 `http://<metadata>/latest/iam/security_credentials` 或内网服务，Grafana 服务器（常在云主机上、可访问元数据）就会代攻击者请求，响应回到数据源查询结果/错误信息中，形成回显 SSRF。
- 该功能本身需要管理员权限，所以前置条件通常是弱口令/默认口令（原文工具命令使用 `-U admin -P admin`）、未授权管理接口或已拿到的管理员会话；一旦满足，SSRF 的“回显”让云凭据泄露非常直接。
- 原文截图中工具依次执行 Source Created → Refreshed Sources → SSRF Source Updated，HTTP 200，响应体包含云 IAM 凭据（可见 `RoleForECS` 等字样）。

## 触发条件

- Grafana 可从攻击者网络访问，管理界面可登录（弱口令/默认口令/已获取会话）；
- 当前账号可创建或修改数据源；
- Grafana 所在主机可访问云元数据服务或目标内网；
- 云元数据未强制 IMDSv2/自定义 Header 等限制（否则需能配置请求头或换目标）。

## 利用步骤

1. 尝试 Grafana 默认/弱口令（admin/admin 等），或使用已获取的管理员会话；
2. 使用 grafana-ssrf 工具（或手工调用 `/api/datasources`）：`python3 grafana-ssrf.py -H https://target -U admin -P admin -u http://<metadata>/latest/iam/security_credentials`；
3. 工具创建数据源并刷新/查询，触发 Grafana 后端向目标 URL 发请求；
4. 在工具输出或数据源查询结果中读取响应（原文 Status code 200，响应体含 IAM 临时凭据）；
5. 用泄露的 AccessKey/SecretKey/SessionToken 调用云 API，横向到 OSS/RDS/ECS 等资源；也可把 URL 换成内网 admin 面板、K8s API、其他元数据路径继续探测。

## PoC

```bash
# 原文工具用法（目标、凭据、URL 均为示意）
python3 grafana-ssrf.py -H https://grafana.example.com -U admin -P admin \
  -u http://100.100.100.200/latest/iam/security_credentials
# 输出：Source Created / SSRF Source Updated / Status code: 200 / Response body: {...,"RoleForECS"...}
```

## 变体与关联

- 除 IAM 凭据外，可指向 `latest/meta-data/`、`latest/user-data/`、内网 K8s apiserver/etcd/Docker API 等；
- Grafana 的告警 webhook、快照、插件安装等功能也可能产生服务端请求，可作为同类 SSRF 面；
- 与库内其他“未授权运维组件回显 SSRF”卡（Consul/Selenium/Cerebro/ClickHouse）属同一云攻防主题，但入口与前置条件不同（本卡需要 Grafana 管理员/弱口令）。

## 检测与防御

- 修改默认口令、启用强认证与最小权限；禁止将 Grafana 管理端口直接暴露公网；
- 限制数据源创建权限，并对数据源 URL 做协议/网段白名单（禁止元数据与内网地址）；
- 网络侧禁止 Grafana 主机访问 169.254.169.254/100.100.100.200 等元数据地址，启用 IMDSv2 或等效 Header 校验；
- 审计 `/api/datasources` 的创建/更新与异常查询行为，监控 Grafana 出站连接。
