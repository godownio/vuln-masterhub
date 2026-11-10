---
id: code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt
title: DevTools 断点作用域改明文变量：在签名与加密执行前改 Scope 中的请求对象，绕过前端校验并让密文/签名基于篡改值重算
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: devtools-scope-edit-plaintext-before-encrypt
tags:
- js-reverse
- devtools
- debugger
- scope
- frontend-encryption
- signature
- request-tamper
- plaintext-point
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T07:58:10+08:00'
  notes: 已对照原文与图片核对：在签名/加密前断点，于Scope把password 1234改为123后继续执行登录成功（图11/12），原理与前提一致；无独立PoC属调试器交互；与JS-Forward/JS-RPC为不同改包机制非重复
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt/
draft: false
kb_aliases:
- 断点改变量绕过前端加密
- Scope 面板改值
- 作用域修改请求参数
- 加密前改变量
- DevTools 改包
- 前端签名绕过改值
---

## 一句话结论

在前端加密/签名代码执行之前的断点处，直接在 DevTools 的 Scope（作用域）面板修改明文变量或对象属性，再继续执行，后续的 `JSON.stringify`、签名（如 `MD5(n+i+r)`）与加密（如 `t.data = l(n)`）都会基于被改后的值重新计算，于是无需还原算法、无需代理改包，就能让服务端收到「合法加密/签名但内容被篡改」的请求。

## 原理

- **执行时序**：请求拦截器先拿到用户输入对象（如 `t.data`），再做归一化/序列化 `n = JSON.stringify(v(t.data))`、生成 `i = p()` 与 `r = timestamp`、计算 `s = MD5(n+i+r)`、最后加密 `t.data = l(n)`。断点停在序列化或加密语句之前时，`t.data`/`n` 还是普通可编辑的 JS 值。
- **调试器可修改暂停态作用域**：DevTools 暂停时，Scope 面板和 Console 都能读写当前调用栈的局部变量与对象属性，修改立即写入该对象；继续执行后，后续代码读取到的就是攻击者改过的值。
- **为什么能过服务端**：签名与密文由页面自己的函数用改后的明文重新生成，服务端解密、验签都会通过；客户端加密/签名只保证字段完整性，不是授权。真正限制改包的是「密文不可编辑」，而这里篡改发生在加密之前。
- **前提**：断点必须位于签名和加密之前，且被改的变量确实是后续计算的输入；若值已被闭包提前捕获，应改对应对象属性或在更早的明文点修改。
- **边界**：只影响当前这一次请求（刷新即恢复）；无法绕过服务端权限校验；若前端在提交前有其他一致性校验（如二次确认字段），需要同步改全。

## 触发条件

- 浏览器未禁用 DevTools，能在目标 JS 中下断点。
- 已定位加密/签名前的明文点（拦截器入口或 `JSON.stringify` 调用处）。
- 目标操作依赖前端提交的参数（如登录、查询、提交表单），且想改的字段参与了后续签名/加密。

## 利用步骤

1. 用 hook 或 XHR 断点定位请求拦截器，在 `n = JSON.stringify(v(t.data))` 或 `t.data = l(n)` 之前下断点。
2. 提交一次请求命中断点，在 Scope → 本地 展开明文变量：`t.data` 为对象、`n` 为 JSON 字符串（视站点实现而定）。
3. 修改目标字段：双击值直接编辑，或对 `n` 字符串按合法 JSON 修改（如把 `password` 从 `1234` 改成 `123`、`username` 改成目标账号）；也可在 Console 中对当前作用域对象赋值。
4. 继续执行（Resume），观察 Scope 中 `t.data` 变为由新值生成的密文，`sign` 也按新值计算。
5. 放行请求，服务端按正常流程解密验签并处理篡改后的参数；原文演示把错误口令改为正确口令后登录成功。

## PoC

无独立 PoC（调试器交互）。关键操作是在类似下面的语句执行前修改作用域：

```js
// 断点停在此行之前
n = JSON.stringify(v(t.data));   // 此时在 Scope 中把 t.data.password 改为目标值
// 继续执行：签名与加密都基于新的 t.data
s = MD5(n + i + r);
t.data = l(n);
```

## 变体与关联

- **Console 直接调用**：暂停时在 Console 里对当前作用域变量赋值或调用加密函数，效果相同。
- **JS-Forward**：把「改值」挪到本地服务/Burp，适合需要反复、统一修改的场景。
- **JS-RPC**：把加密函数暴露给外部工具，由代理/扫描器自动生成任意明文的密文与签名。
- **注意**：若站点在加密后还对密文做二次签名或绑定 requestId，改明文后由页面重算通常仍一致；若有不一致说明找到的不是最终输入点，需要向前找。

## 检测与防御

- 服务端必须基于会话与权限做授权，不能把前端签名/加密当作安全边界；关键操作应二次验证（原密码、验证码、MFA）。
- 对敏感字段做服务端业务校验（如登录只校验账号口令，不信任客户端预校验结果）。
- 风控关注异常参数变更与短时间重复敏感操作；前端反调试只能提高调试成本。
