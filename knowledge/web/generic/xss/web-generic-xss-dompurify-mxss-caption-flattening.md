---
id: web-generic-xss-dompurify-mxss-caption-flattening
title: DOMPurify 3.1.0 mXSS 绕过：506 层扁平化 + caption 突变把 onerror 弹入 HTML 命名空间
type: scenario
domain: web
path: web/generic/xss
technique: dompurify-mxss-caption-flattening
aliases:
- DOMPurify 3.1.0 绕过
- DOMPurify mXSS
- caption 突变
- 节点扁平化绕过
- 命名空间混淆
- 512 层扁平化
- XSS 过滤器绕过
tags:
- web
- xss
- mxss
- dompurify
- html-sanitizer
- namespace-confusion
- caption
- dom-parsing
cve: []
severity: high
confidence: high
affected_versions: DOMPurify 3.1.0（原文测试）；3.1.1 增加 MAX_NESTING_DEPTH 深度检测作为修复
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:41:23+08:00'
  notes: 已对照原文并逐张核对15张图：图06-10确认509/510层扁平化与a标签弹出行为，图11/12展示3.1.0 payload首次解析样式文本、二次解析img进入HTML并带onerror，图13为3.1.1 deep-nesting修复提交，payload与原文<div*506>结构一致，绕过成立。未验证点：未在本机浏览器复跑；原文未标CVE；frontmatter无sources/source_url。
---

## 一句话结论

在 DOMPurify 3.1.0 中，用约 506 层嵌套 `div` 触发浏览器 512 层节点扁平化，再借 `<table><caption>` 的插入模式弹出和 `<svg><title>` 的 HTML 集成点制造命名空间切换，可让一段 `<img src=x onerror=alert()>` 在 DOMPurify 第一次解析时被当作 `<style>` 文本放过、在浏览器第二次解析时被弹回 HTML 命名空间执行，从而绕过净化器触发 XSS。

## 原理

- HTML 解析存在 HTML、SVG、MathML 三种命名空间。`<svg><title>`、`<svg><desc>`、MathML 的 `<annotation-xml>`/`<foreignObject>` 是“HTML 集成点”，可以把内容重新按 HTML 解析；`<style>` 在 SVG 命名空间中的内容按文本处理，不会当成标签。
- `<caption>` 的插入模式规定：解析器遇到 `<caption>` 开始标记时，会从“打开元素堆栈”中不断弹出元素，直到弹出 `<caption>`；后续内容可能被直接弹到 `<table>` 之外。这个过程只看开放元素堆栈，不考虑命名空间，因此会把原本位于 SVG 里的 `<style>` 内容弹入 HTML 上下文。
- 浏览器对嵌套深度有上限：约 512 层时不再继续建树，而是执行 node flattening（扁平化），把第 513 层之后的内容提升出来。被扁平化的节点命名空间保持不变，但位置发生变化。
- mXSS（mutation XSS）的本质是：同一段 HTML 被同一个解析器连续解析两次，第一次与第二次的结果不同。DOMPurify 的清理结果本身不是稳定 DOM，浏览器把净化后的 HTML 再 `innerHTML` 回去时会进行第二次解析，第二次才发生真正的突变。
- 本 payload 的组合：506 层 `div` 把 `table>caption>svg>title>table>caption` 推到扁平化边界；第一次解析时 `<style><a id="</style><img src=x onerror=alert()>">` 整体被当作 SVG `<style>` 的文本（DOMPurify 不把其中的 `</style><img ...>` 识别为标签，所以不过滤）；扁平化把外层 `<caption>` 弹出后，第二次解析时这段文本回到 HTML 命名空间，`</style>` 闭合 style，`<img>` 成为真实元素并触发 `onerror`。

## 触发条件

- 目标使用 DOMPurify 3.1.0（尚未加入 deep-nesting 深度检测的版本）。
- 存在 HTML 注入点（评论、富文本、资料等），后端/前端用 DOMPurify 净化后把结果插入 DOM（`innerHTML`、`insertAdjacentHTML`、框架的 `dangerouslySetInnerHTML` 等）。
- DOMPurify 使用默认配置或允许 `table`、`caption`、`svg`、`title`、`style`、`div` 等标签；若配置了 `FORBID_TAGS` 排除其中任一关键节点，链条会断。
- 浏览器遵循 WHATWG 的 512 层扁平化与 caption 插入模式（Chrome/Firefox/Safari 均需按目标版本验证；不同解析器实现可能存在差异）。

## 利用步骤

1. 确认净化器版本为 DOMPurify 3.1.0，且输出会被二次写入 DOM。
2. 构造 506 层嵌套 `<div>`（用脚本生成，避免手工计数误差），在其内部放置 `table > caption > svg > title > table > caption` 结构。
3. 在 `svg` 下放 `<style><a id="</style><img src=x onerror=alert()>"></a></style>`，让 `</style><img ...>` 处于 style 文本中。
4. 提交 payload，观察 DOMPurify 输出：`<img>` 仍以文本形式藏在 style 里。
5. 页面把净化结果插入 DOM 后，第二次解析触发扁平化与 caption 弹出，`img` 进入 HTML 命名空间并执行 `onerror`。
6. 若未触发，按目标浏览器微调 div 层数（在 500–510 间尝试）和 `title`/`desc` 集成点。

## PoC

以下 `<!-- div×506 -->` 表示连续 506 个 `<div>`，实际使用时用脚本拼接：

```html
<!-- div×506 -->
<table>
  <caption>
    <svg>
      <title>
        <table><caption></caption></table>
      </title>
      <style><a id="</style><img src=x onerror=alert()>"></a></style>
    </svg>
  </caption>
</table>
```

生成骨架：

```javascript
const payload = '<div>'.repeat(506) +
  '<table><caption><svg><title><table><caption></caption></table></title>' +
  '<style><a id="</style><img src=x onerror=alert()>"></a></style>' +
  '</svg></caption></table>';
```

第一次解析：`<style>` 内出现文本 `<a id="`，`img` 不被视为标签；第二次解析：`<img src="x" onerror="alert()">` 出现在 `<div>×506` 之下并执行。

## 变体与关联

- 变体：把 `<title>` 换成 `<desc>`（第二个 DOMPurify 绕过即使用 `<desc>`）；把 `alert()` 换成任意事件处理器或 `fetch` 外带。
- 变体：调整 506 层为其他接近 512 的数值，或叠加多层 caption/表格结构，适配不同浏览器的扁平化阈值。
- 变体：同一思路可用于其他“净化后二次解析”的 sanitizer（sanitize-html、自定义正则过滤器），只要其解析结果与浏览器二次解析不一致。
- 关联卡片：[[web-generic-xss-dompurify-parentnode-clobbering-depth-bypass]]（DOMPurify 3.1.1 针对本卡的修复被 DOM clobbering 绕过）、[[web-generic-xss-dom-clobbering-window-name-collision]]（同类解析期全局变量劫持）。
- 边界：DOMPurify 3.1.1 起增加 `MAX_NESTING_DEPTH` 深度检测，本 payload 会被 `_forceRemove`；更高版本还增加了正则与 DOM clobbering 防护，需按版本重新评估。

## 检测与防御

- 检测：净化前后做“二次解析一致性”测试，把 DOMPurify 输出再交给同一 HTML 解析器，比较两次 DOM 树；对深层嵌套（>500 层）、`table/caption` 与 `svg/title|desc` 组合、`style` 内出现 `</style>` 文本的输入告警。
- 防御：升级到最新 DOMPurify，不要停留在 3.1.0；按业务收紧 `ALLOWED_TAGS`/`ALLOWED_ATTR`，禁止 `style`、`svg`、`math` 等高风险标签；对用户 HTML 先转义再按白名单重建，而不是“先净化后原样插回”。
- 加固：启用 CSP 与 Trusted Types，降低 XSS 执行面；但 CSP 不能修复 mXSS 本身，只能减轻后果。
