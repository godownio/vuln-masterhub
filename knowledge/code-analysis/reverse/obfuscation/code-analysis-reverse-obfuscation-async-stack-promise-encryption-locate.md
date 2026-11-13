---
id: code-analysis-reverse-obfuscation-async-stack-promise-encryption-locate
title: DevTools 异步调用栈跟栈定位前端加密点：XHR initiator → send 断点 → Promise.then 链向上回溯到明文
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: async-callstack-promise-encryption-locate
aliases:
- 异步调试找加密
- Promise 跟栈
- axios 拦截器断点
- initiator 跟栈
- 前端加密异步定位
- Promise.then (async) 调用栈
tags:
- js-reverse
- devtools
- callstack
- async
- promise
- axios
- frontend-encryption
- debugging
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V527
  verified_at: '2026-11-11T15:16:10+08:00'
  notes: 已对照原文 content.md 与全部 13 张图核对：图5 Initiator 请求栈含 Promise.then (async)/u.request/r.forEach.<computed>/chunk-vendors.5620f0fe.js；图6/7 XHR send 断点处 l=userName=wqew%40163.com&password=sy9cWiUt%2F5U%3D（已加密）；图8 向上栈帧出现 main.e2f89ef1.js 与 login.46b0271d.js；图9 login.46b0271d.js 中 a["a"].post(t,...) 与 account/login；图10 Scope 对象 {userName:'wqew@163.com', password:'sy9cWiUt/5U='}（password 已是密文，原卡『明文对象』措辞已改为『局部对象，password 可能已加密』）；图11 DesencodeURIObject 加密调用与第二次栈回溯。axios then 链代码、文件名归属技巧、断点跟栈步骤均与原文一致。原文未给产品版本/CVE；dedup 候选均为 related/new 非同链。PoC 未执行。保留。
---

## 一句话结论

前端加密常被包在异步回调 / Promise 链里，直接在请求处下断只能看到已加密数据；正确做法是用 Network 的 Initiator 查看请求的异步调用栈，在 `XMLHttpRequest.send`（或 fetch/axios adapter）下断点，再沿 Call Stack 中的 `Promise.then (async)`、axios 拦截器、`forEach` 等帧逐层向上回溯，直到找到明文对象参与加密调用的那一帧。

## 原理

- 异步回调不在同步调用栈上：事件循环把 Promise 的 then 回调放入微任务队列执行，调用栈在异步边界处断开；DevTools 的 Call Stack 会用 `Promise.then (async)` 之类的帧标注异步跳转，提示上一段调用来自另一个任务。
- 请求最终都由 `XMLHttpRequest.send`/`fetch` 发出；在 send 处下断点时，请求体已经完成序列化与加密（例如 form-urlencoded 的 `userName=...&password=<密文>`），所以这一帧只能看到密文，必须向上找「加密之前」的帧。
- axios 的 `request` 方法把 `Promise.resolve(config)` 与请求/响应拦截器逐个串成 then 链（`while (e.length) n = n.then(e.shift(), e.shift())`），因此调用栈里会出现 `u.request`、`r.forEach.<computed>`、`Promise.then (async)` 等中间帧，真正的业务加密函数往往在更上层的 `login.<hash>.js` 业务文件里。
- DevTools 的 Initiator 面板展示发起该请求的完整异步调用链（含 async 帧与源码位置），Scope 面板则显示每一帧的局部变量；在业务帧上点选即可看到该帧的局部对象（如 `{userName, password}`；password 可能已是加密后的值）与相关加密函数调用。
- 判断代码归属的技巧：看调用栈里的 JS 文件名与 chunk 名——`chunk-vendors.*.js` 是公共库（axios 等），`login.<hash>.js`/`main.<hash>.js` 是业务代码，优先在业务文件的帧上打断点、单步。

## 触发条件

- 前端在提交前对密码/参数做加密或签名，且加密逻辑位于 Promise/async 回调、axios 拦截器或异步请求封装内。
- 浏览器可打开 DevTools 并能重新触发请求（登录页通常无验证码或可反复提交）。
- 已知请求入口（Network 面板能看到目标请求）。

## 利用步骤

1. 触发一次登录，Network 面板找到请求，切到 Initiator → Request call stack，记录异步调用链与涉及的 JS 文件。
2. 在 Sources 中搜索并在 `XMLHttpRequest.prototype.send`（或 axios 的 dispatchRequest/adapter）下断点；重新触发，确认断点处请求体已是密文。
3. 在 Call Stack 中逐帧向上点击，观察 Scope 面板：找到出现用户输入对象（如 `{userName, password}`，此时 password 可能已被加密）或加密函数调用（如 `DesencodeURIObject(...)`）的帧。
4. 在加密调用前再下断点，或在上一帧的局部变量里直接读取明文/中间值。
5. 遇到 `Promise.then (async)` 帧时，表示当前栈来自另一个异步任务：继续向上点到调用该 Promise 的业务帧（如 login.xxx.js 的异步函数），直到明文由用户输入赋值的点。
6. 记录算法与参数（mode、padding、key/iv 来源），用离线工具验证解密结果与抓包密文一致。

## PoC

axios 拦截器 then 链的形态（示意，用于理解为何调用栈里有多层 Promise 帧）：

```js
let p = Promise.resolve(config);
requestInterceptors.forEach(i => { p = p.then(i.fulfilled, i.rejected); });
responseInterceptors.forEach(i => { p = p.then(i.fulfilled, i.rejected); });
return p;
```

断点位置示意：

```js
XMLHttpRequest.prototype.send = function (body) {
  debugger; // 此处 body 通常已是密文，需向上跟栈找明文
  return originalSend.call(this, body);
};
```

## 变体与关联

- 变体：`fetch` + async/await 时调用栈可能显示 `await` 边界；可在 `window.fetch` 或 `Request` 构造函数下断点。
- 变体：webpack 分包后业务代码在 `login.<hash>.js`/`main.<hash>.js`，公共库在 `chunk-vendors.<hash>.js`，可先按文件名缩小范围。
- 关联：[[code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate]]（hook JSON.stringify 找明文点）、[[code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt]]（断点后直接改明文变量）、[[code-analysis-dynamic-debugging-cdp-callframe-scope-local-variables]]（用 CDP 程序化读取异步调用栈与局部变量）。

## 检测与防御

- 前端加密/签名不是安全边界：攻击者可在浏览器内暂停、改值、跟栈，任何下发给客户端的密钥与算法都可被还原。
- 防御：敏感校验与加密放服务端；前端加密仅用于减少明文暴露，不能替代 TLS；关键接口加服务端限速、风控与重放防护。
- 检测（对防守方）：无可靠的客户端检测手段；可关注异常登录频率与自动化特征，而不是依赖前端加密。
