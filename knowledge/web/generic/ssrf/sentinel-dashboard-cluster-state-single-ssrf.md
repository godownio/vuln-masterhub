---
id: sentinel-dashboard-cluster-state-single-ssrf
title: Alibaba Sentinel Dashboard 集群状态接口 /cluster/state_single 未限制内网地址导致有回显 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: 利用集群状态查询接口可控 ip/port 参数构造服务端 HTTP 请求探测内网
aliases:
- Sentinel SSRF
- Sentinel Dashboard state_single SSRF
tags:
- ssrf
- sentinel
- alibaba
- java
- dashboard
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-29
  verified_at: '2026-11-08T15:47:00+08:00'
  notes: 已对照原文核对：img04/12 调用链与校验代码逐条吻合（isIPv4/IPv6 仅校验格式、app 为空时跳过 isValidMachineOfApp、urlBuilder 拼 http://ip:port），img14/17 回显 phpstudy 404 页，img16 http.server 收到 GET /getClusterMode，有回显 SSRF 成立。affected_versions 1.8.8 为原文明确分析并复现的版本（img02/03 下载 Sentinel-1.8.8.zip 审计），非附带环境版本，保留；原文未给受影响区间。CVE-2021-44139 为另一处 SSRF，卡中仅作关联，正确。
---

# Alibaba Sentinel Dashboard 集群状态接口 /cluster/state_single 未限制内网地址导致有回显 SSRF

## 一句话结论

Alibaba Sentinel Dashboard 的 `/cluster/state_single` 接口将用户可控的 ip/port 直接拼入 `http://ip:port/getClusterMode` 发起服务端 HTTP 请求，仅校验 IP 格式而未限制回环与内网地址，登录用户可借此对任意内网主机与端口发起有回显的 SSRF 探测。

## 原理

调用链：`ClusterConfigController.apiGetClusterState`（`/cluster/state_single`，接收 app/ip/port 三个参数）→ `ClusterConfigService.getClusterUniversalState` → `SentinelApiClient.fetchClusterMode(ip, port)` → `executeCommand`。`executeCommand` 中虽有两道校验：`InetAddressUtils.isIPv4Address/isIPv6Address` 校验 IP 必须是合法的 IPv4/IPv6 字面量，`isValidMachineOfApp` 校验 ip 属于 app——但这些校验只防「格式错误」和「ip 与 app 不匹配」，完全不限制回环地址（127.0.0.1）、私网段或云元数据地址。校验通过后直接 `urlBuilder.append("http://").append(ip).append(':').append(port).append('/').append(api)` 构造 URL，用 Apache HttpClient 的 `HttpGet` 发起 GET 请求（api 固定为 `FETCH_CLUSTER_MODE_PATH`，即 `/getClusterMode`）。请求失败时异常消息被包装进 `CommandFailedException` 返回给前端，目标响应（如 404 页面 HTML）会回显在 `msg` 字段中，因此是有回显的 SSRF；即使无响应内容，差异化的错误与响应时长也支持端口存活探测。

## 触发条件

- 拥有 Sentinel Dashboard 的有效登录会话（接口需登录后访问）。
- Dashboard 版本为 1.8.8（文章分析时最新 Release）且未限制该接口对内网地址的访问。

## 利用步骤

1. 登录 Sentinel Dashboard，携带会话 Cookie 访问：
   `GET /cluster/state_single?app=<任意应用名>&ip=<目标IP>&port=<目标端口>`
2. 服务器会向 `http://<目标IP>:<目标端口>/getClusterMode` 发起 GET 请求。
3. 观察响应 JSON：请求失败时 `msg` 中带 `CommandFailedException` 与目标返回的响应体（如目标 Web 服务的 404 HTML 页面），可据此识别内网服务指纹；文章复现中 ip=127.0.0.1&port=80 时回显了 phpstudy 的 404 页面。
4. 在受控服务器上起 `python3 -m http.server 8000` 并传入 ip=<受控机>/port=8000，可从访问日志收到 `GET /getClusterMode` 请求，证明 SSRF 出网可达。
5. 遍历内网 IP 与端口即可做内网存活/端口探测，结合回显可读取内网 HTTP 服务返回内容；若部署在云上，可进一步尝试访问云元数据地址。

## PoC

```http
GET /cluster/state_single?app=SSRF-TEST&ip=127.0.0.1&port=80 HTTP/1.1
Host: localhost:8080
Cookie: <登录会话>
```

响应 `{"success":false,"code":-1,"msg":"com.alibaba.csp.sentinel.dashboard.client.CommandFailedException, \n<!DOCTYPE html>...<title>404 错误 - phpstudy</title>..."}`，回显了本机 80 端口服务的页面内容。

## 变体与关联

- 同组件早前已有 CVE-2021-44139（另一处 SSRF），本漏洞位于集群状态查询链路，是独立的新触发点，修复 44139 的补丁不覆盖此路径。
- `fetchClusterClientInfoAndConfig`、`fetchClusterServerBasicInfo` 等同样以可控 ip/port 调用 `executeCommand` 的方法共用同一 sink，理论上同样可达。
- `isValidMachineOfApp` 校验在 app 为空时跳过；controller 层 app 虽必填，但复现中填入不存在的应用名 `SSRF-TEST` 仍成功触发，说明该校验对未注册应用不构成阻碍。

## 检测与防御

- 在 `executeCommand` 入口处对解析后的 IP 做私网/回环/链路本地地址黑名单（或仅允许已注册机器列表），拒绝 127.0.0.0/8、10.0.0.0/8、172.16.0.0/12、192.168.0.0/16、169.254.0.0/16、::1 等。
- Dashboard 不应暴露给非信任网络；限制登录来源并按需收敛 `/cluster/**` 接口权限。
- 检测：审计访问日志中 `/cluster/state_single` 的 ip 参数是否出现内网段地址；对异常的出站 HTTP 请求（路径固定为 /getClusterMode）告警。
