---
id: web-generic-auth-astrbot-dashboard-weak-password
title: AstrBot 仪表盘默认/弱口令登录后台并泄露宿主机管理员凭据，复用口令 Pass-the-Hash 横向
type: scenario
domain: web
path: web/generic/auth
technique: dashboard-weak-password-credential-harvest
aliases:
- AstrBot 弱口令
- AstrBot 仪表盘默认密码
- astrbot/admin123
- AstrBot 后台登录
- AstrBot 凭据泄露
- 管理面板弱口令横向
tags:
- web
- auth
- weak-password
- default-credentials
- astrbot
- dashboard
- credential-reuse
- pass-the-hash
- python
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:34:33+08:00'
  notes: 已对照原文与 img/11-17 核对：img/12 登录页为 AstrBot 仪表盘并提示默认 astrbot；原文称 astrbot/admin123 登录成功；img/14 显示用 cs1ab@ow 计算 NTLM=261e22a0d3b39f95b7440c526860a421，img/15 psexec64 以该哈希横向 WIN-AJIGQ5JSPVF 并上线。未验证点：后台内取得 cs1ab@ow 的具体位置无截图，原文亦未给出成功登录后台的截图，故 confidence 维持 medium；原文未给 AstrBot 版本，未设 affected_versions。PoC 未执行。
---

## 一句话结论

AstrBot 仪表盘暴露在公网且保留默认/弱口令（登录页提示默认 `astrbot/astrbot`，原文使用 `astrbot/admin123`）时，攻击者可直接登录后台，读取机器人配置与管理员凭据；原文把后台中取得的 `cs1ab@ow` 复用为 Windows 主机 Administrator 口令，并以其 NTLM 哈希做 Pass-the-Hash 横向控制主机。

## 原理

- AstrBot 是基于 Python 的聊天机器人框架，仪表盘默认监听 6185 端口，登录路由为 `/auth/login`；登录页会直接提示“默认用户名和密码为 astrbot”，说明默认凭据是产品公开信息。
- 部署者常把默认口令改成 `admin123` 这类弱口令，或以默认 `astrbot/astrbot` 直接上线；仪表盘没有强制首次改密、失败锁定或来源限制时，弱口令即可被猜中/爆破。
- 仪表盘内保存机器人接入配置、平台 API Key、账号设置以及部署/运维相关凭据。原文登录后在后台“信息搜集管理员密码 `cs1ab@ow`”，说明该应用把宿主机管理员的口令以可读形式暴露给了后台用户。
- 拿到明文口令后，可以离线计算其 NTLM 哈希（`md4(UTF-16LE(password))`），再用 PSExec/WinRM 等工具的哈希登录参数做 Pass-the-Hash；原文即用 `261e22a0d3b39f95b7440c526860a421` 通过 Cobalt Strike 的 psexec 横向到 `WIN-AJIGQ5JSPVF` 并上线 Beacon。
- 这条链的关键不是哈希算法本身，而是“应用后台凭据与操作系统管理员口令复用”：应用层弱口令 → 后台配置泄露 → 主机层凭据复用。

## 触发条件

- AstrBot 仪表盘（默认 6185）从攻击面可达，未被防火墙/反向代理鉴权保护。
- 使用默认口令 `astrbot/astrbot` 或弱口令（原文为 `astrbot/admin123`），且无失败锁定/验证码。
- 后台配置中保存了宿主机、数据库或其他系统的凭据，且与操作系统管理员口令复用。
- 目标主机开放 SMB/445、WinRM/5985 或 RDP/3389，允许哈希或口令登录。

## 利用步骤

1. 端口/指纹识别：扫描 6185 端口，访问 `/auth/login`，页面标题为“AstrBot 仪表盘”，并带有默认口令提示。
2. 尝试默认与弱口令：`astrbot/astrbot`、`astrbot/admin123`、`admin/admin123` 等；原文使用 `astrbot/admin123` 登录成功。
3. 登录后检查机器人配置、平台接入、账号设置、日志与部署信息，寻找宿主机/数据库/第三方系统的凭据。
4. 原文在后台取得管理员口令 `cs1ab@ow`；用 `md4(UTF-16LE("cs1ab@ow"))` 计算 NTLM 哈希。
5. 用 PSExec/WinRM/evil-winrm 等以 `Administrator` + 该哈希登录目标 Windows 主机；若目标允许明文口令，也可直接尝试 RDP/3389。
6. 上线后读取敏感文件/凭据，继续内网横向。

## PoC

登录页（原文入口）：

```text
http://target:6185/auth/login
默认用户名和密码为 astrbot
```

弱口令登录（请求体字段随版本可能是 JSON 或表单，按实际抓包调整）：

```http
POST /auth/login HTTP/1.1
Host: target:6185
Content-Type: application/json

{"username":"astrbot","password":"admin123"}
```

计算 NTLM 哈希（等价于 CyberChef 的 MD4(UTF-16LE)）：

```python
import hashlib
password = "cs1ab@ow"
print(hashlib.new("md4", password.encode("utf-16le")).hexdigest())
# 261e22a0d3b39f95b7440c526860a421
```

Pass-the-Hash（Cobalt Strike psexec 等价命令）：

```text
psexec \\<target> -u Administrator -p <NTLM_HASH> -d cmd.exe
# 或 impacket：
psexec.py -hashes :<NTLM_HASH> Administrator@<target>
```

## 变体与关联

- 变体：默认 `astrbot/astrbot` 未改时无需猜解；改密后若为 `admin123`、`astrbot123` 等弱口令，可用小字典在线爆破。
- 变体：后台若提供插件安装、WebHook、消息推送配置，可进一步写入恶意配置或利用第三方集成回调。
- 变体：后台泄露的口令可复用到 SSH、数据库、其他管理面板；若只能拿到哈希，则走 Pass-the-Hash 而不是明文登录。
- 关联：[[web-generic-auth-uid-resetpwd-hardcoded-default-password]]（默认口令类问题）、[[pentest-ad-lsass-minidump-pypykatz-offline]]（NTLM 哈希提取与 Pass-the-Hash）、[[pentest-lateral-movement-ms17-010-eternalblue-psexec]]（SMB/PSExec 横向）、[[pentest-lateral-movement-psreadline-history-credential-harvest]]（凭据复用）。
- 边界：仪表盘仅内网可达、已改强口令并启用失败锁定、后台不保存主机凭据、主机禁用哈希登录时，链条不成立。

## 检测与防御

- 检测：外网访问 `:6185/auth/login`；同一 IP 对登录接口高频失败或使用 `astrbot/admin123` 等弱口令；登录后访问配置/账号页并导出凭据；随后目标 Windows 主机出现异常 445/135/5985 登录与 psexec 服务创建。
- 修复：修改 AstrBot 默认口令为强随机值并强制首次改密；为仪表盘加独立鉴权、来源 IP 限制与失败锁定；不要把宿主机/数据库口令明文存放在应用配置中。
- 加固：应用后台凭据与操作系统/其他系统口令不得复用；启用 Windows 凭据保护（Credential Guard）、限制 NTLM 与远程哈希登录；管理面板只在内网/VPN 暴露。
