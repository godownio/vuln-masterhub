---
id: web-nodejs-gray-matter-js-frontmatter-rce
title: gray-matter 的 JS front-matter 引擎把用户可控字符串当 JavaScript 求值导致 RCE
type: scenario
domain: web
path: web/nodejs
technique: gray-matter-js-engine-code-execution
tags:
- nodejs
- gray-matter
- front-matter
- code-execution
- rce
- dependency
- jwt-forgery
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-10
  verified_at: '2026-11-08T01:09:06+08:00'
  notes: 已对照原文核对；原理/PoC/结论与 content.md 及图 02/03/04/08 一致，JS front-matter 求值 RCE 已打通；5 个 Node.js RCE 候选均属不同 sink，dedup_review 成立；未验证点：未在本地复现 gray-matter 具体版本行为
url: /docs/web/nodejs/web-nodejs-gray-matter-js-frontmatter-rce/
draft: false
kb_aliases:
- gray-matter
- JavaScript front-matter
- '---js 引擎'
- front-matter RCE
- js-yaml !!js/function
---

## 一句话结论

当服务端把用户可控字符串交给 `gray-matter` 解析且未禁用其 JavaScript front-matter 引擎时，以 `---js\n<JS>\n---` 包裹的输入会在解析阶段被当作 JavaScript 执行，配合 Node 进程里的 `require('child_process')` 即构成任意命令执行（RCE）。

## 原理

- gray-matter 把文本头部的 front-matter 按分隔符后缀选择「引擎」：`---js` 表示这一段不是 YAML 而是 JavaScript，库会对其求值并把返回值当作 front-matter 数据对象，这是设计上的「可编程 front-matter」能力。
- 危险点在于求值发生在**服务端 Node 进程**里，且能拿到完整 Node 运行时（`require`），因此 front-matter 内容等同于源码，可访问 `child_process`、文件系统与环境变量。
- 为什么用户可控：本例把鉴权 token 中的自定义声明 `slogon` 直接传给 `gray(decoded.slogon)`，再用 `gray.stringify(...)` 重新拼装后渲染。能控制该声明就控制了被求值的 JS 文本。
- 为什么走到 RCE：调用形如 `gray.stringify(gray(payload).content, {username})`，先求值的 `gray(payload)` 在 payload 以 `---js` 开头时即触发 JS 执行，与后面 `stringify` 是否渲染、是否丢弃 front-matter 数据无关。
- 前置门槛：该管理接口用 JWT 鉴权，而签名密钥硬编码在构建产物/源码里，攻击者可离线签发 `username=admin` 且 `slogon` 任意的 token，从而抵达 `gray()` 调用点。「密钥硬编码可伪造 token」与「把不可信字段交给可编程解析器」两个缺陷叠加才闭环。

## 触发条件

- 服务端用 gray-matter（或同类支持 JS 引擎的 front-matter 库）解析用户可控文本；
- 未把引擎显式锁定为 YAML/JSON，未对分隔符做白名单；
- 用户能控制进入解析器的整段文本（这里通过伪造 token 的自定义声明）；
- 应用以 Node 进程运行，JS 引擎内可 `require('child_process')`；
- 存在离线签发/篡改 token 的途径（硬编码密钥、弱密钥、算法混淆等）。

## 利用步骤

1. 定位把用户字段交给 `gray()` / `matter()` 的调用点（如 `gray(decoded.slogon).content`）。
2. 取得该字段控制权：本例用硬编码 JWT 密钥签发含恶意 `slogon` 的管理员 token。
3. 把 `slogon` 构造成 `---js\n<JS>\n---`，JS 内用 `require('child_process').execSync(...)` 执行命令；输出可写入 Web 目录文件或外带到攻击者控制的地址。
4. 携带伪造 token 请求管理接口，触发解析，JS 在服务端执行。
5. 读取结果（访问生成的文件，或接收带外 HTTP/DNS 请求）；对结果做 Base64 解码以还原特殊字符。

## PoC

```js
// 演示 JS front-matter 在解析阶段即执行；仅在授权环境验证
const gray = require('gray-matter');
const payload = '---js\n((require("child_process")).execSync("id > /tmp/pwned"))\n---x';
const profile = gray.stringify(gray(payload).content, { username: 'admin' });
// gray(payload) 求值时 execSync 已执行，/tmp/pwned 写入命令输出
```

```python
# 前置：用硬编码密钥伪造管理员 token
import jwt, time
tok = jwt.encode(
    {"username": "admin", "slogon": malicious_slogon,
     "iat": int(time.time()), "exp": int(time.time()) + 604800},
    "<HARDCODED_JWT_SECRET>", algorithm="HS256")
```

## 变体与关联

- 变体：YAML 解析器的 `!!js/function`、其他语言 templating/front-matter 的「可编程头」、服务端模板注入，同属「把数据当代码」类；即便应用只取 `.content` 而丢弃 front-matter 数据，执行也发生在取 `.content` 之前，不因丢弃而幸免。
- 关联：JWT 硬编码/弱密钥伪造、Node.js 反序列化 gadget、服务端模板注入（SSTI）。

## 检测与防御

- 防御：不要用 JS 引擎解析任何不可信 front-matter；显式 `engines: { yaml: ... }` 并把分隔符锁死为普通 YAML；对用户字段做白名单校验（只接受普通字符串，拒绝换行与 `---`）；不要把鉴权 token 的自定义声明直接交给富文本/可编程解析器。
- 密钥：JWT 签名密钥由环境变量/密钥管理系统注入，禁止写入前端可见的构建产物与源码；轮换已泄露密钥。
- 检测：WAF/日志中出现以 `---js`/`---javascript` 开头、含 `require(`、`child_process`、`execSync` 的字段值；Node 进程异常派生 `sh -c`、Web 目录出现非预期新文件、异常外联。
