---
id: web-generic-xss-operator-expression-injection
title: 运算符充当 JS 表达式注入载体：乘号/加减/in/instanceof 在双输出点与符号黑名单下构造 XSS
type: scenario
domain: web
path: web/generic/xss
technique: xss-operator-expression-injection
aliases:
- 运算符 XSS
- 乘号绕过 XSS
- in instanceof XSS
- 双输出点 XSS
- 引号过滤 XSS 构造
- alert(1) 表达式
tags:
- xss
- javascript
- expression-injection
- operator
- bypass
- filter
- dom
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V443
  verified_at: '2026-11-09T22:52:52+08:00'
  notes: 对照原文图10-12、18：xsstest3 双输出点（var px / $('#xss').val）与 *、+、- 三种运算符载荷 ?px=xxxxx'*alert(1)*'、'+alert(1)+'、'-alert(1)-' 均与原文一致；in/instanceof 载荷出自 xsstest4 变体，原文明确属运算符族且未被过滤，描述成立。dedup 候选 javascript-context-injection 为通用 JS 上下文卡，非同一条链（本卡为双输出点引号自平衡+符号/关键字运算符绕过）。未本机复跑。
---

## 一句话结论

当输入被同步拼进两个 JS 输出点、单纯闭合引号会让其中一个点语法出错时，不必依赖分号/注释，用二元运算符把 `alert(1)` 包成表达式即可：`'x'*alert(1)*''`、`'x'+alert(1)+'x'`、`'x'-alert(1)-'x'` 都能在两侧保持语法合法并触发执行；若符号被黑名单过滤，还可用关键字运算符 `in` / `instanceof` 绕过。

## 原理

- **JS 表达式求值顺序**：二元运算符会对两侧操作数求值；`alert(1)` 作为操作数之一，无论最终结果是 NaN、字符串拼接还是抛错，都会先执行。`'x' * alert(1) * ''` 中 `alert(1)` 返回 undefined，后续得到 NaN，但弹窗已发生。
- **为什么适合双输出点**：同一输入被 echo 到两处（如 `var px = 'INPUT';` 与 `$('xss').val('INPUT')`）。用 `"` 或 `'` 闭合会在第一处结束字符串，但第二处会因多出引号而语法错误；把 payload 设计成 `'*alert(1)*'` 这种"引号数量自平衡"的表达式，则在两处都保持合法。
- **可用运算符族**：
  - 乘号：`'x'*alert(1)*''`（数值强制转换）；
  - 加号：`'x'+alert(1)+'x'`（字符串拼接，求值 alert）；
  - 减号：`'x'-alert(1)-'x'`（数值转换）；
  - 关键字：`'x' in alert(1) in 'x'`、`'x' instanceof alert(1) instanceof 'x'`（RHS 先求值再类型检查，alert 执行后可能抛 TypeError，但已达成执行）。
- **为什么关键字运算符有价值**：很多过滤器只黑名单 `+ - * / | & ^ ~ ! ? : ;` 等符号，不会屏蔽 `in`/`instanceof` 这类字母运算符；它们同样能把输入变成表达式并求值 `alert(1)`。
- **代价与边界**：表达式求值后可能抛异常（如 `in`/`instanceof` 的 TypeError），但异常发生前 alert 已执行，XSS 目的已达到；同一 script 块后续代码可能不再执行。

## 触发条件

- 用户输入被拼进内联脚本的表达式/字符串位置，且至少有两处同步输出（或存在引号平衡约束）。
- 过滤规则禁止引号闭合后的分号/注释，或只过滤符号运算符。
- 页面允许内联脚本执行（无严格 CSP）。

## 利用步骤

1. 观察输入被拼进 JS 的位置与次数（如 `var px = '...'` 与 `.val('...')` 两处）。
2. 若两处都要保持语法，先尝试运算符自平衡 payload：`'*alert(1)*'`，URL 编码后提交。
3. 若 `*` 或 `+`/`-` 被过滤，改用关键字运算符：`' in alert(1) in '`、`' instanceof alert(1) instanceof '`。
4. 在浏览器 Console/页面验证 alert；若有异常，确认异常发生前 payload 已执行。
5. 按上下文补充注释或分号处理尾部多余代码。

## PoC

```javascript
// 双输出点示例
var px = 'xxxxx';
$('xss').val('xxxxx');

// 乘号：两侧都变成 'xxxxx'*alert(1)*''
// URL: ?px=xxxxx'*alert(1)*'

// 加号/减号同理
// ?px=xxxxx'+alert(1)+'
// ?px=xxxxx'-alert(1)-'

// 符号被过滤时用关键字运算符
// ?px=xxxxx' in alert(1) in '
// ?px=xxxxx' instanceof alert(1) instanceof '
```

## 变体与关联

- 变体：逗号运算符 `'x',alert(1),'x'`、三元 `cond?alert(1):0`、逻辑 `0&&alert(1)`、`||` 短路等同样可作为表达式载体（前提是符号未被过滤）。
- 变体：`in`/`instanceof` 被过滤时可用 `delete`、`typeof`、`void`、模板字符串插槽等。
- 关联：[[web-generic-xss-javascript-context-injection]]（字符串闭合与表达式位置的通用原理）；[[web-generic-xss-dom-hash-settimeout-debug-construction]]（无回显时如何定位 JS 拼接点）；[[web-generic-xss-template-literal-absorbs-unclosed-quote]]（符号全被过滤后的模板字符串吸收路线）。

## 检测与防御

- 检测：请求参数中出现 `*alert(`、`+alert(`、`-alert(`、` in alert(`、` instanceof alert(` 等模式；同一参数在页面出现两次且落入 JS。
- 防御：不要拼接生成 JS，使用 `JSON.stringify`/`json_encode` 输出数据；对输入做 JS 语法安全编码而非符号黑名单；CSP 禁止 inline/unsafe-eval。
- 局限：运算符 payload 依赖目标上下文可构造出合法表达式；严格转义（引号与反斜杠都处理）后不成立。
