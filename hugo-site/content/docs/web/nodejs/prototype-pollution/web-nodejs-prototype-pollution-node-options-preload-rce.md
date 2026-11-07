---
id: web-nodejs-prototype-pollution-node-options-preload-rce
title: 原型污染到 Node 子进程代码执行：污染 NODE_OPTIONS=-r 让 spawn 的 node 预加载文件
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: prototype-pollution-node-options-preload-rce
tags:
- nodejs
- prototype-pollution
- constructor-prototype
- node-options
- child-process
- spawn
- rce
- file-read
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:11:23+08:00'
  notes: '已对照原文与图01核对：merge 仅过滤字面量 __proto__、constructor.prototype 绕过、payload {"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}、spawn(''node'', [''-e'', ...], {env: customEnv, shell: false}) 均与原文一致；图01 显示 POST /api/config 返回 Configuration updated successfully。未验证点：原文未展示 -r /flag 的最终读取结果，语法错误回显泄 flag 属合理推断；PoC 未运行；原文未给 Node 版本；frontmatter 无 sources/source_url。'
url: /docs/web/nodejs/prototype-pollution/web-nodejs-prototype-pollution-node-options-preload-rce/
draft: false
kb_aliases:
- NODE_OPTIONS 原型污染
- constructor.prototype 绕过 __proto__
- Node 子进程环境变量污染
- --require 预加载
- 原型污染 RCE gadget
---

## 一句话结论

当 merge 只过滤字面量 `__proto__`、却允许 `constructor.prototype` 时，可污染 `Object.prototype.NODE_OPTIONS="-r /flag"`；之后应用用 `spawn('node', ..., {env: customEnv})` 启动子进程，子进程继承该环境变量，Node 启动时以 `--require /flag` 预加载文件，从而执行攻击者指定的模块，或通过语法错误回显把文件内容（flag）带出来。

## 原理

- **绕过 `__proto__` 过滤**：`p.__proto__ === p.constructor.prototype`。merge 过滤 `key === '__proto__'` 后，提交 `{"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}` 仍会沿 `constructor → prototype` 落到共享原型，把属性写到 `Object.prototype`。
- **环境变量继承**：Node 的 `child_process.spawn(cmd, args, {env})` 用传入的 `env` 对象构造子进程环境。若该对象是普通对象、且代码用 `for...in`/`Object.assign`/展开等方式合并环境变量，`Object.prototype` 上的可枚举属性会被带进子进程环境；即使只复制自有属性，上游若先把请求数据 merge 进 `customEnv`，污染也会进入 env。
- **NODE_OPTIONS 的威力**：Node 启动时读取 `NODE_OPTIONS`，支持 `--require <module>`（`-r`）在入口脚本前预加载模块。把值设为 `-r /flag` 后，子进程会 `require('/flag')`：
  - 若 `/flag` 是合法 JS，直接执行其中的代码（RCE）；
  - 若不是 JS，Node 抛出语法错误，错误信息通常包含出错文件的首行/片段，从而泄露 flag 内容。
- **为什么用子进程**：应用可能禁用了 `shell: true`、过滤了命令字符串，但没有限制环境变量；`spawn('node', ['-e', '...'], {env: customEnv})` 是常见的健康检查/沙箱执行点，正好成为 gadget。
- **前提**：`NODE_OPTIONS` 未被父进程清理/覆盖；Node 版本允许 `--require`（大多数版本默认允许）；`/flag` 对子进程可读。

## 触发条件

- 存在递归 merge/深拷贝 sink，过滤了 `__proto__` 但没有过滤 `constructor`/`prototype`。
- 应用会 `spawn`/`execFile` 启动 `node` 子进程，并把用户可控/可污染的对象作为 `env`。
- `NODE_OPTIONS` 未被显式删除，且子进程继承环境。
- 目标文件（如 `/flag`）对子进程可读；或可通过 `--require` 加载攻击者可控的模块。

## 利用步骤

1. 确认 merge 过滤规则：提交 `{"__proto__":{"x":1}}` 观察是否被拦；再提交 `{"constructor":{"prototype":{"x":1}}}`，检查新对象是否继承 `x`。
2. 找到 `spawn('node', ...)` 的调用点，确认 `env` 来源与是否继承原型属性。
3. 提交 payload 污染 `NODE_OPTIONS`：
   ```json
   {"constructor":{"prototype":{"NODE_OPTIONS":"-r /flag"}}}
   ```
4. 触发一次 `spawn`（如健康检查、代码运行、沙箱执行接口），观察子进程输出/错误。
5. 若 `-r /flag` 只报语法错误，读取错误信息中的文件片段；若能上传 JS 模块，可改为 `-r /app/uploads/evil.js` 执行任意代码。
6. 清理/重复污染视进程生命周期而定；多进程/多实例需分别打。

## PoC

```json
{
  "constructor": {
    "prototype": {
      "NODE_OPTIONS": "-r /flag"
    }
  }
}
```

对应的脆弱 Node 代码形态：

```javascript
function merge(target, source) {
  for (let key in source) {
    if (key === '__proto__') continue;      // 只拦字面量
    if (source[key] instanceof Object && key in target) {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}

const customEnv = {};                        // 普通对象
merge(customEnv, req.body);                  // 污染进入 env/原型
spawn('node', ['-e', 'console.log("check")'], {
  env: customEnv,
  shell: false,
});
```

## 变体与关联

- **NODE_OPTIONS 变体**：`--require`/`-r`、`--import`、`--loader`、`--experimental-loader`；不同 Node 版本支持不同。
- **环境变量 gadget 变体**：`PATH` 劫持、`LD_PRELOAD`（Linux）、`NODE_PATH` 模块解析劫持、`PYTHONPATH` 等。
- **过滤绕过变体**：`constructor.prototype`、嵌套键、Unicode 转义、表单参数；见关联卡片。
- **关联卡片**：[[web-nodejs-prototype-pollution-filter-bypass]]（constructor.prototype/Unicode/表单绕过）、[[web-nodejs-prototype-pollution-merge-json-parse]]（merge 原型污染基础）、[[web-nodejs-prototype-pollution-undeclared-identifier-function-rce]]（原型污染控制未声明标识符）。
- **边界**：`NODE_OPTIONS` 被清空、`env` 只复制自有属性且上游未 merge、Node 禁用 `--require`、子进程不继承环境时失效。

## 检测与防御

- **检测特征**：请求体出现 `constructor`/`prototype`/`NODE_OPTIONS`；子进程环境含异常 `NODE_OPTIONS`；Node 启动错误中出现 flag 文件片段。
- **修复**：merge 递归拒绝 `__proto__`/`constructor`/`prototype`（解析后按层级校验）；`env` 使用白名单显式构造，不继承原型；启动子进程前删除 `NODE_OPTIONS`/`NODE_PATH`/`LD_PRELOAD` 等危险变量；禁用 `shell` 并限制可执行文件。
- **最小权限**：子进程以低权限运行，flag 文件不可读；对 `spawn` 输入做类型/长度校验。
