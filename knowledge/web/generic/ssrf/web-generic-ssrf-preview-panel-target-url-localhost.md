---
id: web-generic-ssrf-preview-panel-target-url-localhost
title: 后台预览面板 target_url 任意抓取：SSRF 访问 127.0.0.1 内部诊断路由回显 flag
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-preview-url-localhost-internal-route
aliases:
- 诊断地址 SSRF
- target_url
- 127.0.0.1/internal
- 预览面板 SSRF
- 回显 SSRF
- 本机内部路由
tags:
- web
- ssrf
- localhost
- preview
- internal-route
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:16:10+08:00'
  notes: 已对照原文与图01-03核对：mail_user/mail_role=admin 进入后台预览面板，target_url 提交 http://127.0.0.1/internal/report?view=flag&slot=last 后回显 flag（图03），路由索引 final 别名与说明文档一致；卡片已注明 &slot 被工具拆参的问题。未验证点：PoC 未本机复跑；原文无受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

后台“预览面板”把用户提交的 `target_url` 交给服务端抓取并回显响应，虽然说明文档声称“只查看本机内部诊断结果、不支持外部地址”，但实现未做地址限制；攻击者可用 `http://127.0.0.1/internal/report?view=flag&slot=last` 让服务端访问只监听本机的内部诊断路由，从而绕过网络边界拿到 flag。

## 原理

- 预览/诊断类功能通常由服务端代用户发起 HTTP 请求（`curl`、`requests`、`URLConnection`、`fetch`），再把响应正文返回页面；如果 `target_url` 未做协议/主机/端口白名单，就是 SSRF。
- 本题内部诊断路由只绑定在 `127.0.0.1`（或只允许本机访问），外部直接请求不可达；服务端进程自己请求 `127.0.0.1` 则被视为本机流量，访问控制被绕过。
- 联调说明与路由索引泄露了内部别名：`final -> /internal/report?view=flag&slot=last`；`health`、`mailq` 也可用于探测。说明文档中的“不支持外部地址”只是文字承诺，代码未校验。
- 前置条件：先通过客户端 Cookie 信任进入后台（`mail_user=admin; mail_role=admin`），再通过任意文件读取拿到说明与路由索引，最后用双人复核的 0e 魔术哈希通过校验并提交 `target_url`。
- 一个实用细节：`target_url` 的值本身包含 `&slot=last`，如果把它当作普通表单/查询参数提交，代理工具会把 `&slot=last` 拆成新的顶层参数，导致服务端收到的 URL 被截断；应把整个 URL 作为一个参数值 URL 编码，或直接在页面表单中提交。
- 根因是“服务端请求用户可控 URL + 响应回显 + 未限制回环/内网地址”，属于完整可用的 SSRF 原语（能读内部 HTTP 响应）。

## 触发条件

- 应用存在服务端 URL 抓取功能（预览、诊断、图片代理、webhook 测试、远程配置拉取）。
- `target_url`/`url`/`endpoint` 等参数可由低权限用户控制，且没有协议、主机、端口、IP 段白名单。
- 服务端能访问回环地址或内网，且内部服务只依赖网络位置做访问控制。
- 响应正文（或状态码/长度/错误信息）会返回给攻击者，形成有回显 SSRF。
- 前置认证可通过弱 Cookie、默认口令或其它漏洞绕过。

## 利用步骤

1. 进入后台预览面板，确认 `target_url` 参数会被服务端抓取并回显。
2. 读取联调说明与路由索引，找到内部诊断别名，例如 `final -> /internal/report?view=flag&slot=last`。
3. 先提交 `http://127.0.0.1/internal/health` 或 `http://127.0.0.1/internal/queue` 验证 SSRF 可达。
4. 提交完整目标 URL；若使用代理工具，注意把 `?view=flag&slot=last` 全部编码进 `target_url` 的值，避免 `&` 被拆成新参数。
5. 读取回显中的 flag；若被拦截，尝试 `localhost`、`127.1`、`0.0.0.0`、十进制 IP、DNS 重绑定、302 跳转等变体。
6. 继续探测内网其他端口/路由，或尝试 `file://`、`gopher://` 等协议（取决于服务端 HTTP 客户端）。

## PoC

```http
POST /admin.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

token_a=240610708&token_b=QNKCDZO&target_url=http%3A%2F%2F127.0.0.1%2Finternal%2Freport%3Fview%3Dflag%26slot%3Dlast
```

页面表单等价输入：

```text
预览凭据 A: 240610708
预览凭据 B: QNKCDZO
诊断地址:   http://127.0.0.1/internal/report?view=flag&slot=last
```

回显示意：

```text
ISCC{...}
```

## 变体与关联

- **地址变体**：`127.0.0.1`、`localhost`、`127.1`、`0.0.0.0`、`[::1]`、十进制/八进制 IP、DNS 重绑定、302 跳转到内网。
- **协议变体**：`http/https`、`file://` 读本地文件、`gopher://` 构造原始 TCP 报文、`dict://` 探测服务。
- **回显变体**：直接回显正文、仅回显状态码/长度、错误信息回显、盲 SSRF 需 OOB/DNSLog。
- **关联**：[[web-generic-auth-php-md5-magic-hash-pair-double-verify]]（本题进入诊断功能的校验绕过）；[[web-generic-file-inclusion-download-param-source-disclosure]]（本题泄露内部路由的入口）；[[web-generic-ssrf-redirect-gopher-localhost-portscan-omi]]（回环 SSRF 的协议升级利用）。
- **边界**：服务端限制目标为公网、禁止回环/私网、只允许固定域名、或响应不回显且无 OOB 信道时，本路径失效。

## 检测与防御

- **检测**：`target_url`/`url` 参数出现 `127.0.0.1`、`localhost`、私网段、非 HTTP 协议、十进制 IP；服务端向本机/内网发起异常请求；预览接口响应包含内部服务页面或错误堆栈。
- **防御**：对目标 URL 做协议白名单（仅 http/https）与主机/IP 白名单；解析后校验 IP 不属于回环、私网、链路本地、云元数据段；禁止跟随重定向或对重定向目标再次校验。
- **加固**：预览/诊断功能只允许访问固定的内部服务列表；不要把内部路由索引放在可下载文件中；服务端 HTTP 客户端使用独立网络策略与最小权限。
