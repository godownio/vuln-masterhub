---
id: ctf-forensics-http-unauth-api-audit
title: HTTP 流量未授权 API 审计：无认证头 + 200 + 业务数据，GET 405/POST 200 也算
type: scenario
domain: ctf
path: ctf/forensics
technique: http-unauth-api-traffic-audit
tags:
- ctf
- forensics
- pcap
- http
- api
- unauthorized
- audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:28+08:00'
  notes: 已对照原文 接口未授权 1 核对：目标 172.16.5.139:50000、无 Authorization/Cookie/Token/Bearer + 200 + 业务数据、GET 405/POST 200 计入、排除 /、/robots.txt、/cryptodemo 均一致；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-http-unauth-api-audit/
draft: false
kb_aliases:
- 未授权接口流量审计
- 无认证头 API
- 200 业务数据
- 405 变 POST 200
- 接口字符串长度排序
---

## 一句话结论

从 pcap 中按目标 host:port 过滤 HTTP，枚举 `/api/*` 路径，按“请求无 `Authorization`/`Cookie`/`Token`/`Bearer` + 响应 `200 OK` + 响应体含真实业务数据”判定未授权访问；GET 返回 405 但 POST 返回 200 且同样无认证的接口也应计入。

## 原理

- **认证缺失 + 服务端不校验**：请求里没有任何会话/令牌字段，服务端仍返回 200 和业务 JSON，说明接口未做身份校验或把鉴权交给了前端。
- **方法限制不是授权控制**：`GET /api/lottery/result` 返回 405 只说明该方法不允许，不代表接口受保护；换 POST 后 200 且无认证，仍是未授权可访问。
- **业务数据判定**：200 响应可能只是空壳/静态页；要看响应体是否包含用户、订单、名单、身份证等真实业务字段。`/`、`/robots.txt`、`/cryptodemo` 这类页面即使 200 也不算 API。
- **审计口径**：按 URL 去重、按路径长度排序，便于批量核对与提交。

## 触发条件

- 有 HTTP pcap/pcapng，目标服务地址与端口明确。
- 接口路径可枚举，响应体未加密或可读。
- 题目/审计要求找出“无认证即可返回业务数据”的 API。

## 利用步骤

1. 用 `tshark -r capture.pcapng -Y 'http && ip.addr==<target> && tcp.port==<port>'` 过滤目标流量。
2. 提取请求方法、Host、URI、请求头与响应状态码、响应体；按 URI 聚合。
3. 检查每个请求是否含 `Authorization`、`Cookie`、`Token`、`Bearer` 等认证字段。
4. 检查响应是否 200 且 body 含真实业务字段（username/password/phone/id_card 等）。
5. 对 GET 405 的路径继续看同路径的其他方法（POST/PUT），确认是否无认证 200。
6. 排除静态页/首页/robots.txt 等非 API 路径，按题目要求排序输出。

## PoC

```python
import re
from collections import defaultdict

# 以 tshark 导出的 http.request/response 字段为例
reqs = defaultdict(list)
for line in open("http_fields.txt", encoding="utf-8", errors="ignore"):
    method, host, uri, hdrs, status, body = line.rstrip("\n").split("\t")
    reqs[(host, uri)].append((method, hdrs, status, body))

AUTH = re.compile(r"(?i)(authorization|cookie|token|bearer)\s*:")
for (host, uri), items in reqs.items():
    if not uri.startswith("/api/"):
        continue
    for method, hdrs, status, body in items:
        if not AUTH.search(hdrs) and status.startswith("200") and body.strip():
            print(method, host, uri, status, body[:80])
```

## 变体与关联

- **认证位置变体**：token 可能在 query、body、自定义头（`X-Token`）、签名参数；要逐项检查而不是只看 `Authorization`。
- **响应变体**：200 但 body 为空/仅 `{"code":0}` 不算；可能返回 302 到登录页；可能 gzip/chunked，需要先解压。
- **接口类型变体**：GraphQL 单端点、WebSocket、gRPC-Web；按消息/操作名而不是路径枚举。
- **关联卡片**：[[ctf-forensics-http-beacon-gate-php-dns-c2-extraction]]（HTTP 流量提取）、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（未授权接口的后续利用）、[[ctf-forensics-multi-api-masked-pii-correlation]]（多个未授权接口的关联）。
- **边界**：公开接口（登录、注册、健康检查）本来就不需要认证，不应误报；需要结合业务语义判断。

## 检测与防御

- **CTF/审计验证**：先确认请求头确实无认证字段，再确认响应体含真实业务数据；对 405 路径补测其他方法。
- **防御**：网关/框架统一默认拒绝，所有 `/api/*` 走认证中间件；不要依赖前端隐藏入口；对方法限制与授权做区分；定期做接口清单与未授权扫描。
- **检测信号**：无 Cookie/Authorization 的 API 请求返回 200 且响应体较大；同一路径不同方法的状态码差异；异常 UA/来源集中访问业务接口。
