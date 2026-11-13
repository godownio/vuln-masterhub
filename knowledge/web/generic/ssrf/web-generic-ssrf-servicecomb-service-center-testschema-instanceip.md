---
id: web-generic-ssrf-servicecomb-service-center-testschema-instanceip
title: Apache ServiceComb Service-Center /testSchema/ SSRF：X-InstanceIP 拼接目标地址并回显响应（CVE-2023-44313）
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-header-host-join-response-read
aliases:
- CVE-2023-44313
- ServiceComb Service-Center SSRF
- X-InstanceIP SSRF
- /testSchema SSRF
- 契约测试代理 SSRF
tags:
- ssrf
- apache
- servicecomb
- service-center
- golang
- echo
- header-injection
- cve-2023-44313
cve: CVE-2023-44313
affected_versions: < 2.2.0
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:39:07+08:00'
  notes: 已对照原文与5张截图核对：受影响版本<2.2.0、安全版本2.2.0、CVE-2023-44313均与原文一致；X-InstanceIP拼接http://<instanceIP>+去掉testSchema/的RequestURI、响应回显、SCHEMA_DISABLE开关与img02/03一致；修复diff(img01)与checkInstanceHost/img05一致；PoC路径/testSchema/sc+dnslog与img03/04一致；未实际复现
---

## 一句话结论

Apache ServiceComb Service-Center（< 2.2.0）frontend 的 `/testSchema/*` 路由把请求头 `X-InstanceIP` 与去掉 `testSchema/` 的 RequestURI 直接拼成 `http://<instanceIP><path>`，未做任何 IP/主机校验就发起请求并把响应体原样回显；攻击者设置 `X-InstanceIP: <内网IP:端口或 dnslog 域名>` 即可让 Service-Center 服务器发起任意 HTTP 请求并读到响应（支持 GET/POST/PUT/DELETE 及请求头/请求体转发），CVE-2023-44313，2.2.0 修复。

## 原理

- **漏洞代码路径**：`server.go` 中 `e.Any("/testSchema/*", m.SchemaHandleFunc)` 注册契约测试代理；`SchemaHandleFunc` 里：
  ```go
  instanceIP = r.Header.Get("X-InstanceIP")
  requestUrl = strings.Replace(r.RequestURI, "testSchema/", "", 1)
  url        = "http://" + instanceIP + requestUrl
  ```
  随后按原请求方法 `http.NewRequest`，把原请求头（排除 Accept-Encoding/Connection/Cookie/UA/Referer 等少量黑名单）复制到新请求，`client.Do(req)` 发出，`ioutil.ReadAll(response.Body)` 后 `c.String(200, string(respBody))` 返回给攻击者。
- **为什么是 SSRF**：目标主机完全由 `X-InstanceIP` 控制（可带端口），请求路径由 URL 剩余部分控制，协议固定为 http；服务端以自身网络位置发起请求，响应内容会被带回，属于"可读响应"的完整 SSRF，而非盲打。
- **为什么能读内网**：Service-Center 通常部署在内网/与业务微服务同网段，可访问注册中心后端、管理接口、云元数据（http://169.254.169.254/）等原本外部不可达的服务；方法、头和 body 的转发还能构造 POST/PUT/DELETE 请求。
- **开关**：路由默认开启，仅当环境变量 `SCHEMA_DISABLE=true` 时返回 403 "schema is disabled"。
- **修复方式**：2.2.0 在 Mux 中新增 `SchemaTestCIDR *net.IPNet`，调用 `checkInstanceHost(instanceIP)`：`net.SplitHostPort` 解析主机后要求落在配置的 CIDR 内，否则返回 `ErrInvalidInstanceIP` 403。

## 触发条件

- 目标 Service-Center frontend 端口可从攻击者网络访问，版本 < 2.2.0；
- 未设置 `SCHEMA_DISABLE=true`（默认未设置）；
- 目标服务器出网或能访问攻击者指定的内网地址（用于探测/读取）。

## 利用步骤

1. 识别目标：访问 Service-Center frontend，确认存在 `/testSchema/` 路由（返回非 404）且版本 < 2.2.0。
2. 用 dnslog 验证：发送 `GET /testSchema/sc`，请求头带 `X-InstanceIP: <随机>.dnslog.cn`，观察 dnslog 是否收到解析记录。
3. 读取内网服务：把 `X-InstanceIP` 换成 `内网IP:端口`，路径改成目标接口（如 `/actuator/env`、`/v2/...`），从响应体读取内容。
4. 需要 POST/PUT/DELETE 时，用相同方法发送并携带 body，代理会按原方法转发。
5. 也可探测云元数据 `X-InstanceIP: 169.254.169.254`（仅 http）。

## PoC

```http
GET /testSchema/sc HTTP/1.1
Host: 127.0.0.1:30103
X-InstanceIP: 7dwu5i.dnslog.cn
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

dnslog 收到 `7dwu5i.dnslog.cn` 的解析记录即证明 SSRF；响应体为 Service-Center 代替攻击者请求 `http://7dwu5i.dnslog.cn/sc` 的结果。读取内网示例（把主机换成目标内网地址）：

```http
GET /testSchema/actuator/health HTTP/1.1
Host: frontend:30103
X-InstanceIP: 10.0.0.12:8080
Connection: close
```

## 变体与关联

- 固定 `http://` 前缀限制了 file/gopher 等协议，但仍可打内网 HTTP 服务与云元数据（http）；
- `X-InstanceIP` 可携带端口，等同任意内网端口探测；路径可控可命中带副作用的 GET 接口；
- 同类"请求头决定目标地址 + 回显响应"的 SSRF 见 [[web-generic-ssrf]] 目录下其他代理/回调类卡片；
- 服务注册中心/配置中心类组件（Nacos、Eureka 等）的 SSRF/未授权面可对照排查。

## 检测与防御

- 升级 Apache ServiceComb Service-Center 至 2.2.0 及以上；
- 不需要契约测试时设置 `SCHEMA_DISABLE=true` 关闭 `/testSchema/*` 路由；
- frontend 管理端口只在内网/运维网段暴露，不允许公网访问；
- 对出站请求做目标白名单/CIDR 限制（2.2.0 的 SchemaTestCIDR 即此思路），并禁止访问云元数据地址；
- 监控 `/testSchema/` 请求中异常的 `X-InstanceIP`（dnslog 域名、内网 IP、169.254.169.254）及由此产生的出站连接。
