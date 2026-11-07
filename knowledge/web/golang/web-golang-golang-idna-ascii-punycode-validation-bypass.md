---
id: web-golang-golang-idna-ascii-punycode-validation-bypass
title: Go idna 纯 ASCII Punycode 标签解码漏判绕过域名校验
type: scenario
domain: web
path: web/golang
technique: idna-ascii-punycode-label-validation-bypass
aliases:
- CVE-2026-39821
- GO-2026-5026
- xn-- 尾分隔符绕过
- IDN 解析差异
- 国际化域名黑名单绕过
- idna.ToUnicode 绕过
tags:
- go
- idna
- punycode
- idn
- unicode
- normalization
- validation-bypass
- blacklist
- cve-2026-39821
- go-2026-5026
cve:
- CVE-2026-39821
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: golang.org/x/net < v0.57.0（v0.54.0–v0.56.0 实测受影响），且工具链 unicode.Version < 16.0.0；标准库侧修复于 go1.25.13、go1.26.6、go1.27.0-rc.3
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:51:00+08:00'
  notes: 已对照原文与22张图核对；Punycode 尾分隔符路径、unicode16 短路、v0.54-v0.59 逐版本结果、标准库 ascii.Is 短路、修复 diff 与检测逻辑均一致；受影响版本按原文实测设置；未本地复现
---

## 一句话结论

在 `unicode.Version` 低于 16.0.0 的 Go 工具链下，`golang.org/x/net/idna` 会把 `xn--<任意 ASCII 标签>-` 解码成 `<标签>` 且不返回错误；调用方若用这个规范化结果做黑名单、白名单、回调域名或特权域判断，攻击者无需注册任何国际化域名，只要拼一个字符串就能让目标域名通过校验。

## 原理

- IDNA 的 A-label 形如 `xn--` 加 Punycode。Punycode（RFC 3492）的编码结果由 `<basic 段> '-' <delta 增量>` 组成：basic 段是原输入里的 ASCII 字符，尾分隔符之后的 delta 编码非 ASCII 码位。
- 对 `xn--example-`，`decode` 在末尾找到 `-`，判定整个余下部分都是 basic 段、delta 为空，于是直接返回 `example` 且 `err=nil`。这一步本身符合 RFC 3492。
- 问题出在解码后的语义检查：A-label 存在的意义是承载非 ASCII 内容，解码结果若是纯 ASCII，说明这是一个多余/畸形的 ACE 标签。UTS #46 早期修订（pre-revision 33）没有把这种情况定义为错误，`idna` 因此在 `process` 中补了一条检查。
- 但该检查写成 `if unicode16 && err == nil && len(u) > 0 && isASCII(u)`。`unicode16` 是编译期常量 `unicode.Version >= "16.0.0"`，直接取自工具链标准库 `unicode` 数据表，与 `x/net`、`x/text` 版本无关。
- 当工具链标准库仍是 Unicode 15.0.0（如 go1.26.x 常见环境）时，`unicode16` 编译为 `false`，整个 `&&` 条件短路，`isASCII(u)` 永远不执行，`xn--example-.com` 被当作普通 ASCII 域名接受，错误为空。
- 于是 `ToASCII`/`ToUnicode` 同时返回“目标 ASCII 域名 + nil 错误”。安全代码若只看返回值或忽略 `err`，就会把一个完全由攻击者构造的字符串当成可信的规范化结果。
- 危险来自表示层与决策层的错位：校验端看到原始字符串 `xn--example-.com`，它与黑名单里的 `example.com` 不相等；后续规范化或网络动作却把它还原成 `example.com`。白名单方向同理：先规范化再比对，外部输入会被当成可信目标。
- 注意边界：Go 标准库 `net/http` 的拨号和请求行序列化都会先做 `ascii.Is` 短路，纯 ASCII 的 `xn--example-.com` 不会进入 `idna`，DNS 直接解析失败。因此这条构造的入口是**应用层直接调用 `idna` 并拿结果做安全决策**的代码，不是标准库裸拨号。

## 触发条件

- 应用把用户可控的 hostname 交给 `idna.ToASCII`、`idna.ToUnicode` 或 `idna.Lookup.ToASCII` 做规范化，再把结果用于黑名单、白名单、回调地址比对、特权域名判断或后续请求。
- 依赖 `golang.org/x/net` 低于 v0.57.0（v0.54.0、v0.55.0、v0.56.0 实测均受影响；v0.55.0/v0.56.0 的“修复”只保留了 `unicode16` 门槛，没有真正生效）。
- 工具链标准库 `unicode.Version` 低于 16.0.0（可用 `go run` 打印验证；go1.26.x 常见为 15.0.0）。
- 调用方丢弃 `err`（`_, _ =`、单值接收），或只对返回值做字符串比较，不检查错误。

## 利用步骤

1. 找到接收 hostname/URL 并调用 `idna` 的入口，确认返回值会进入安全判断或网络请求。
2. 用探针确认环境：`idna.ToUnicode("xn--example-.com")` 若返回 `example.com` 且 `err=nil`，处于漏洞状态。
3. 对任意想伪装的目标 ASCII 标签 `s` 构造 `xn--s-`；多标签域名只改需要伪装的那一段，例如 `xn--admin-.example.com` 解码为 `admin.example.com`。
4. 若校验在规范化之前，字符串黑名单不命中而放行；若校验先规范化再比对，外部输入会命中白名单，被当成可信目标。
5. 落到具体业务：SSRF 黑名单绕过（见 `[[web-generic-ssrf-golang-idna-ascii-punycode-blacklist-bypass]]`）、OAuth `redirect_uri`/Webhook 域名校验、特权域名判断等。后两类是否成立取决于业务是否真的调用 `idna` 且丢弃错误，属于待验证方向。

## PoC

```go
package main

import (
	"fmt"

	"golang.org/x/net/idna"
)

func main() {
	for _, s := range []string{
		"xn--example-.com",
		"xn--admin-.example.com",
		"xn--localhost-",
	} {
		uni, errU := idna.ToUnicode(s)
		ascii, errA := idna.ToASCII(s)
		fmt.Printf("in=%q uni=%q errU=%v ascii=%q errA=%v\n", s, uni, errU, ascii, errA)
	}
}
```

go1.26.8（标准库 unicode 15.0.0）+ `golang.org/x/net@v0.54.0` 实测：

```text
in="xn--example-.com"          uni="example.com"   errU=<nil>  ascii="example.com"   errA=<nil>
in="xn--admin-.example.com"    uni="admin.example.com" errU=<nil> ascii="admin.example.com" errA=<nil>
in="xn--localhost-"            uni="localhost"     errU=<nil>  ascii="localhost"     errA=<nil>
```

切到 `v0.57.0` 后返回值仍是目标域名，但错误变为 `idna: invalid label "example-"`；调用方必须检查 `err` 才算拦截。

最小检测探针：

```go
func vulnerable() bool {
	s, err := idna.ToUnicode("xn--example-.com")
	return err == nil && s == "example.com"
}
```

## 变体与关联

- 前缀大小写敏感：`XN--EXAMPLE-` 不被识别为 ACE，原样返回；构造必须用小写 `xn--`。
- 无尾 `-` 的 `xn--example` 会走 delta 解码，实测输出希腊字母 `Ωίθηδ`，不是本漏洞；尾分隔符决定走 basic 段直返路径。
- 空标签 `xn--` 返回空串、无错误；`xn---`、`xn--a--` 等畸形串的行为需按版本实测，不能只按直觉判断。
- IP 字面量不可行：`xn--169.254.169.254-` 被点号切成多个标签后，`169` 触发 `invalid label "169"`，目标限定为域名形态。
- 版本差异：v0.55.0/v0.56.0 在 Unicode 15 工具链下仍漏；v0.57.0 把条件改为无条件检查才修复。审计时必须同时看 `go.mod` 的 `x/net` 版本和 `go version`，只看其中一个会误判。
- 关联：`[[web-generic-ssrf-golang-idna-ascii-punycode-blacklist-bypass]]` 是同一原语在 SSRF 黑名单上的完整落地；`[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]` 是另一类“校验与执行使用不同解析器”的同族问题。
- 权限提升：通告把“规范化结果作为特权域判断依据”列为提权方向，但公开材料未见独立利用链，本卡按 low 置信方向记录，不单独成卡。

## 检测与防御

- 代码审计：检索 `idna.ToASCII`、`idna.ToUnicode`、`idna.Lookup.ToASCII` 的调用点，重点看返回值是否以 `_` 接收或单值接收；修复版本下错误仍在 `err` 里，丢弃 `err` 等于没修。
- 代码审计：找出“先对 hostname 做字符串匹配，再交给 `idna` 或网络库”的两段式代码；凡是“先放行、后规范化”的顺序都值得把 `xn--` 前缀输入纳入测试。
- 运行时探针：对已知黑名单域名构造 `xn--<label>-`，断言 `ToUnicode` 返回错误；返回目标域名且 `err` 为空即仍处于漏洞状态。
- 依赖处置：`x/net` 升级到 v0.57.0 及以上；标准库侧升级到 go1.25.13、go1.26.6、go1.27.0-rc.3 或更新版本（1.24 及更早没有修复版本）。
- 修复写法：任何 `idna` 调用都必须检查 `err`，出错立即拒绝，不能回退使用返回字符串；不要把规范化返回值当作唯一可信依据。
- 结构加固：安全判断不要建立在字符串上。先按同一套规范化规则得到唯一的最终形式，再用这个最终形式同时做校验和实际动作；对网络请求则在连接前解析出 IP，拒绝回环、私网、链路本地地址。
- 回归测试：把 `xn--example-.com`、`xn--localhost-`、`xn--admin-.example.com` 写成“必须报错/必须拒绝”的用例，而不是只断言返回值。
