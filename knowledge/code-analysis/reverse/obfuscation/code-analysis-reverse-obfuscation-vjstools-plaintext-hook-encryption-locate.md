---
id: code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate
title: v_jstools 挂钩定位前端加密明文点：从 JSON.stringify/atob 钩子回溯请求拦截器并锁定加密与签名函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: vjstools-plaintext-hook-locate-encryption
aliases:
- v_jstools 找加密函数
- 明文点定位
- JS hook 找加密入口
- hook JSON.stringify
- 前端加密逆向定位
- 拦截器断点找明文
tags:
- js-reverse
- frontend-encryption
- hook
- devtools
- v_jstools
- plaintext-point
- webpack
- signature
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T07:58:08+08:00'
  notes: 已对照原文与43张图核对：v_jstools勾选JSON.stringify等hook、inject start、控制台明文输出、按文件行号断点、步过确认l()为AES-CBC加密函数，均与原文一致；PoC为等价hook示意；原文无受影响版本
---

## 一句话结论

用 v_jstools 对 `JSON.stringify`/`JSON.parse`、`atob`/`btoa`、`escape` 等函数挂钩后，控制台会打印每次调用的参数、返回值与调用位置；顺着包含业务明文字段（如 `password`/`username`/`validCode`）的那次 `JSON.stringify` 调用点打断点，再单步跟踪 `t.data = l(n)` 之类的赋值，就能在 webpack 混淆代码中直接定位加密函数、签名算法、时间戳与 requestId 的生成位置，而无需先读懂混淆后的符号名。

## 原理

- **明文一定在浏览器里出现过**：前端加密只是请求拦截器里的一步，加密函数之前必然存在保存原始用户输入的变量（明文点）。找到这个变量，就绕过了「必须搜索到加解密函数」的思维定式。
- **典型拦截器结构**：请求拦截器中依次执行 `r = Date.parse(new Date())`（时间戳）、`n = JSON.stringify(v(t.data))`（序列化归一化）、`i = p()`（requestId）、`s = MD5(n + i + r)`（签名）、`t.data = l(n)`（加密）。在 `JSON.stringify` 处挂钩就能看到 `n` 的完整明文以及调用它的 JS 文件与行号。
- **v_jstools 的作用**：Chrome 扩展在页面加载前注入 hook，包装常用序列化/编码/函数调用类 API，把参数、返回值和调用栈位置输出到控制台。勾选 `hook-function`/`hook-eval` 还能追踪普通函数与 eval；只勾选与目标相关的项可避免信息过载。
- **为什么比全局搜索可靠**：生产环境 webpack 打包后变量名被压缩、字符串可能被拆分或编码，搜 `AES`/`sign` 常常落在无关代码上；hook 输出的是运行时真实调用点，符号是否混淆不影响定位。
- **越靠前的明文点价值越高**：拦截器入口、`JSON.stringify` 参数、加密函数入参都是明文点；越接近用户输入，后续签名/加密逻辑越完整，改值后越不容易被前置校验覆盖。
- **边界**：hook 输出量大需要筛选；`eval` 封闭上下文可能报错；页面若使用 iframe/worker 或强反调试，需要在对应上下文注入；定位到函数后仍需后续步骤（改值/插桩/RPC）才能自动化。

## 触发条件

- 目标 Web 前端用 JS 对请求体加密或签名，能打开浏览器 DevTools 并安装扩展。
- 已安装 v_jstools（或等价 hook 扩展），页面可刷新重新执行注入。
- 目标是修改/重放被加密或签名的请求，直接改包会导致解密失败或签名不匹配。

## 利用步骤

1. 安装 v_jstools，打开配置页，只勾选与本次需求相关的 hook（`hook-JSON.parse`、`hook-JSON.stringify`、`hook-atob`、`hook-btoa`、`hook-function` 等），打开「是否挂钩总开关」。
2. 打开目标页控制台并刷新，确认出现 `inject start!`。
3. 在页面提交一次表单，观察控制台打印：找到包含业务明文字段的那条 `JSON.stringify` 记录，记录右侧 JS 文件与行号。
4. 点击链接跳到源码对应行并打断点，重新提交，命中断点后在 Scope 面板确认明文变量（如 `n` 或 `t.data`）。
5. 单步/步过执行，观察赋值后变量变为密文（如 `t.data = l(n)`），进入 `l()` 阅读其 key/iv/算法；在同一拦截器中继续找到 requestId、timestamp、sign 的生成函数。
6. 记录这些函数与变量，后续用作用域改值、JS-Forward 或 JS-RPC 接管改包。

## PoC

工具操作流程无独立 PoC；等价的最小 hook 思路如下（注入控制台即可看到明文参数与调用栈，v_jstools 是它的批量实现）：

```js
const _stringify = JSON.stringify;
JSON.stringify = function (v) {
    console.log('[stringify]', v, new Error().stack);
    return _stringify.apply(this, arguments);
};
```

提交表单后控制台会打印 `{"password":"...","username":"...","validCode":"..."}` 及调用位置，据此下断点。

## 变体与关联

- **XHR/fetch 断点**：按 URL 断在请求发送处，再沿 Initiator 调用栈向上找明文点，适合参数名不可搜索的场景（已有前端加密自动化卡）。
- **全局搜索参数名**：未混淆时最快，webpack 混淆后经常失效。
- **v_jstools 其它钩子**：`hook-cookie` 观察会话写入，`hook-eval` 追踪动态执行，`config-hook-random` 固定随机数便于对比两次请求。
- **定位后的三条路**：作用域直接改值（单次）、JS-Forward 注入本地桥（Burp 改包）、JS-RPC 暴露函数（自动化）。

## 检测与防御

- 这是纯客户端调试行为，服务端无法直接检测；根本防御是不把安全建立在客户端加密/签名上：传输用 TLS，授权与会话校验放服务端。
- 前端可加反调试、代码完整性校验与 hook 检测提高成本，但均可被绕过。
- 风控侧关注同一会话短时间内的异常参数、重复提交与畸形请求。
