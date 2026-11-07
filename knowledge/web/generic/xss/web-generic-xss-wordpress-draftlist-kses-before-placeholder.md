---
id: web-generic-xss-wordpress-draftlist-kses-before-placeholder
title: Draft List 短代码先 kses 过滤后替换占位符，草稿标题逃逸属性触发存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: sanitize-order-placeholder-injection
aliases:
- CVE-2026-9104
- Draft List XSS
- WordPress 短代码占位符 XSS
- wp_kses 过滤顺序缺陷
- 先过滤后拼接
tags:
- web
- xss
- stored-xss
- wordpress
- plugin
- shortcode
- wp_kses
- attribute-escape
cve:
- CVE-2026-9104
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: 所有 2.6.3 及更早版本
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T00:43:08+08:00'
  notes: 已对照原文与截图核对 wp_kses 先过滤后 str_replace、can_edit 分支不转义、日期字符串比较坑点与 SVG 弹窗结果；未验证点：未在本机复现，依赖原文弹窗/源码截图
---

## 一句话结论

Draft List 插件把 `[drafts template='...']` 的模板先交给 `wp_kses()` 过滤、之后才用未转义的草稿标题替换 `{{draft}}` 占位符；拥有作者权限的用户把标题写成属性逃逸 payload，任何无编辑权限的访客浏览该页面时即触发存储型 XSS。

## 原理

- 短代码模板来自页面内容，插件先 `html_entity_decode()` 再 `wp_kses($template, $allowed_list)` 过滤，随后才在生成列表时执行 `str_replace('{{draft}}', $draft, $this_line)`。
- 过滤与拼接的顺序颠倒：`wp_kses()` 只审查当时模板里已有的标签和属性，占位符位置此时是纯文本 `{{draft}}`；真正的高风险数据（草稿标题）在过滤之后才进入 HTML，因此完全不受白名单约束。
- 替换时 `$draft = $draft_title` 没有任何转义；只有 `$can_edit` 为真（当前用户能编辑该草稿）才包一层 `<a>` 并调用 `esc_html()`。普通访客、订阅者等无编辑权限用户走的是不转义分支。
- 模板中 `<div title="{{draft}}">` 的 `title` 属性处于双引号上下文，标题里的 `"` 提前闭合属性，再接 `>` 闭合标签，即可注入任意标签（如 `<svg onload=...>`）。
- 之所以成立：安全过滤被当作一次性关卡，而实际输出是“已过滤模板 + 未过滤变量”的二次拼接；变量可在过滤后改变文档结构。

## 触发条件

- 安装并启用 Draft List 2.6.3 或更早版本；
- 攻击者拥有 Author 或更高权限，能创建草稿并设置标题；
- 站点某公开页面使用了 `[drafts]` 短代码，且模板中包含带引号属性的 `{{draft}}` 占位符（如 `title="{{draft}}"`）；
- 草稿能通过插件的日期判断：从未发布过的草稿 `post_date` 为 `0000-00-00 00:00:00`，与 `1970-01-02` 做字符串比较时为 false，不会被渲染；需先发布再立即改回草稿，使其拥有真实时间；
- 受害者以无编辑权限身份（未登录访客或订阅者）访问该页面。

## 利用步骤

1. 确认插件版本 ≤ 2.6.3，并找到渲染 `[drafts]` 短代码的公开页面。
2. 在页面/文章中插入实体编码后的模板，避免区块编辑器重写短代码属性：
   `[drafts template='&lt;div title=&quot;{{draft}}&quot;&gt;Hover Me&lt;/div&gt;']`
3. 以 Author 身份新建草稿，标题填属性逃逸 payload：
   `"><svg onload="alert('XSS')"></svg>`
4. 发布该草稿后立刻改回“草稿”状态，使 `post_date`/`post_modified` 变为真实时间，从而通过日期检查。
5. 退出登录（或使用订阅者账号）访问短代码所在页面，`{{draft}}` 被替换为恶意标题，SVG 的 `onload` 执行。

## PoC

```text
短代码（放在已发布页面中）：
[drafts template='&lt;div title=&quot;{{draft}}&quot;&gt;Hover Me&lt;/div&gt;']

草稿标题：
"><svg onload="alert('XSS')"></svg>
```

渲染结果（过滤后拼接，payload 已不在 kses 审查范围内）：

```html
<div title=""><svg onload="alert('XSS')"></svg>">Hover Me</div>
```

访问页面即弹窗。

## 变体与关联

- 变体：把 payload 放进 `style`、`class` 等同样被白名单允许的属性；用 `onmouseover` 等事件属性替代 `onload`；标题内容还可注入 `<a href=javascript:...>`。
- 同类根因：任何“先对模板/容器做净化，再替换占位符或拼接变量”的实现，包括模板引擎的 `safe` 过滤器在变量插入前执行、富文本先过滤后做变量插值、缓存/片段拼接先过滤后附加用户数据。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（`<svg onload>` 属于 script 标签被过滤时的替代载体）；[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（属性上下文转义不完整的另一条路径）。
- 权限边界：需要 Author 及以上账号才能写入标题，因此不是未授权 XSS；若站点开放作者注册或存在账号接管，利用门槛会降低。

## 检测与防御

- 检测：页面 HTML 中出现未转义的 `on*` 事件属性或异常 `<svg>`；作者账号创建标题含引号加标签的草稿；短代码模板中出现属性内的 `{{draft}}` 占位符。
- 防御：在最终输出点按上下文转义，属性内使用 `esc_attr()`，文本节点使用 `esc_html()`；对替换后的完整结果再做一次白名单过滤，而不是只过滤模板；不要用 `$can_edit` 决定是否转义，转义应对所有查看者一致；升级插件到修复版本。
- 代码审计关注点：搜索 `str_replace`/`sprintf` 拼接模板、`wp_kses`/净化函数调用位置、`esc_*` 被包在权限分支内的写法。
