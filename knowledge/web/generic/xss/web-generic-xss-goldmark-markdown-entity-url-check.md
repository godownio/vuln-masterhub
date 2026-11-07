---
id: web-generic-xss-goldmark-markdown-entity-url-check
title: Goldmark 先查危险协议后做 HTML 实体还原：javascript&colon; 绕过 Markdown 链接过滤（CVE-2026-5160）
type: scenario
domain: web
path: web/generic/xss
technique: dangerously-check-before-html-entity-decode
aliases:
- Goldmark XSS
- CVE-2026-5160
- javascript&colon;
- Markdown 链接 XSS
- IsDangerousURL 绕过
- URLEscape 实体还原
- 校验时序倒置
tags:
- xss
- markdown
- goldmark
- go
- html-entity
- url-scheme
- sanitizer-bypass
- cve-2026-5160
cve:
- CVE-2026-5160
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: goldmark <= 1.11.0
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:32:25+08:00'
  notes: '已对照原文与图01-14、11核对：IsDangerousURL 只对原始字节做 javascript:/vbscript:/file:/data: 前缀比较，javascript&colon; 第11字节为&导致不匹配；检查通过后 URLEscape(...,true)→ResolveEntityNames→LookUpHTML5EntityByName 将 &colon;还原为:；PoC服务输出 <a href="javascript:alert(document.domain)"> 且图11实测弹窗。原文正文称修复v1.12.0、流程图写v1.17.6+，存在不一致，卡按正文<=1.11.0与v1.12.0修复标注，未改；affected_versions保留。PoC未在本机执行。frontmatter 无 sources/source_url。'
---

## 一句话结论

Goldmark 在 `<1.12.0` 的链接渲染中先用原始字节判断 `IsDangerousURL`，之后才在 `URLEscape(..., true)` 里还原 HTML 字符实体；把 `javascript:` 写成 `javascript&colon;` 即可让检查器看到“普通字符串”、让浏览器最终看到并执行 `javascript:`，在服务端渲染的 Markdown 链接处形成 XSS。

## 原理

- 浏览器处理一个链接至少经过三层：HTML 解析阶段还原实体（`&colon;`→`:`、`&#x6a;`→`j`），URL 解析阶段识别并归一化协议（忽略前导控制字符、大小写不敏感），若协议为 `javascript:` 再由 JS 引擎解码负载并执行。
- Goldmark 的 `renderLink` 在写入 `href` 前调用 `IsDangerousURL(n.Destination)`。该函数只对原始字节做大小写不敏感的前缀比较（`javascript:`、`vbscript:`、`file:`、`data:`），此时 `javascript&colon;` 的第 11 个字节是 `&` 而不是 `:`，比较失败，返回“安全”。
- 检查通过后，同一分支调用 `util.URLEscape(n.Destination, true)`；`resolveReference=true` 会依次执行 `UnescapePunctuations`、`ResolveNumericReferences`、`ResolveEntityNames`，其中 `ResolveEntityNames` 查 HTML5 实体表把 `&colon;` 还原成 `:`。
- 因此“检查时的字符串”是 `javascript&colon;...`，“输出给浏览器的字符串”已经变成 `javascript:...`。检查发生在中间态，执行发生在最终态，两者之间存在一次实体解码，安全判断被语义变化绕过。
- 这与单纯的编码混淆不同：问题不在浏览器容错，而在组件自己主动做了一次“检查之后、输出之前”的解码。

## 触发条件

- 使用 Goldmark `<= 1.11.0`，并由服务端把用户可控 Markdown 渲染为 HTML（默认配置即可；`Unsafe=false` 不影响此链）。
- 攻击者能控制 Markdown 链接目标，例如 `[text](...)`。
- 渲染结果被原样插入页面，且页面未对最终 HTML 再做可信 sanitizer 处理。
- 浏览器支持 `javascript:` 协议链接（常规浏览器均支持）。

## 利用步骤

1. 在可提交 Markdown 的位置写入实体化的伪协议链接：`[View Detail](javascript&colon;alert(document.domain))`。
2. Goldmark 渲染时 `IsDangerousURL` 对原始字节判为安全，随后 `URLEscape(..., true)` 把 `&colon;` 还原为 `:`。
3. 输出 HTML 的 `href` 已变成 `javascript:alert(document.domain)`。
4. 诱导用户点击链接，浏览器按 `javascript:` 协议交给 JS 引擎执行。

## PoC

最小 Go 服务：

```go
package main

import (
    "bytes"
    "fmt"
    "net/http"

    "github.com/yuin/goldmark"
)

func handler(w http.ResponseWriter, r *http.Request) {
    md := "# Article\n\n[View Detail](javascript&colon;alert(document.domain))\n"
    var buf bytes.Buffer
    _ = goldmark.Convert([]byte(md), &buf)
    fmt.Fprintf(w, "<html><body>%s</body></html>", buf.String())
}

func main() { http.HandleFunc("/", handler); http.ListenAndServe(":8080", nil) }
```

渲染结果中的关键部分：

```html
<a href="javascript:alert(document.domain)">View Detail</a>
```

点击后弹出当前域，证明实体在检查之后被还原成了危险协议。

## 变体与关联

- 其它 HTML5 命名实体：只要能在 `ResolveEntityNames` 阶段还原出协议中的关键字符，就可能构造同类载荷；数值实体则可能在 `ResolveNumericReferences` 阶段被还原。
- 同类时序问题不限于 Goldmark：任何“先按原始字符串做黑名单/白名单，再做实体解码、URL 解码、Unicode 反转义”的实现，都存在同一语义错位。
- 与浏览器三阶段解析的通用关系：详见 [[web-generic-xss-filter-bypass-encoding-obfuscation]]（编码混淆绕过）与 [[web-generic-xss-scriptless-execution-vectors]]（伪协议载体）。
- 修复方式是把检查移到解码之后：先对 `n.URL(source)` 做 `URLEscape`，再对结果调用 `IsDangerousURL`，最后输出。

## 检测与防御

- 升级 Goldmark 到包含修复的版本；不要仅依赖黑名单前缀判断。
- 代码审计：搜索 `IsDangerousURL` 一类检查与其后的 `URLEscape`/实体解码调用，确认检查对象与最终输出对象是同一份规范化字符串。
- 对所有用户可控链接执行“先完整解码/归一化、后判断协议”的顺序；白名单只允许 `http`、`https`、`mailto` 等明确协议。
- 服务端 Markdown 渲染结果在进入页面前再经过 DOMPurify 一类 allowlist sanitizer 兜底；对 `a[href]` 再校验协议。
- 运行时检测：输出中出现 `javascript:`、`data:text/html`、`vbscript:` 等伪协议，或 Markdown 源中出现 `&colon;`、`&#x3a;` 等被用于拆分协议关键字的实体。
