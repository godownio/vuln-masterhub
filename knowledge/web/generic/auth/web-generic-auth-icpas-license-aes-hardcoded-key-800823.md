---
id: web-generic-auth-icpas-license-aes-hardcoded-key-800823
title: ICPAS IP 网络对讲广播系统许可证伪造：硬编码 AES-CBC key/IV + machineCode+800823 固定后缀
type: scenario
domain: web
path: web/generic/auth
technique: icpas-license-aes-hardcoded-key-magic-suffix
aliases:
- ICPAS 授权绕过
- IP 网络对讲广播系统注册码伪造
- DemoKeyEnc 注册码
- machineCode 800823
- 许可证 AES 硬编码 key
tags:
- php
- dotnet
- wcf
- license-bypass
- auth-bypass
- aes-cbc
- hardcoded-key
- icpas
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T07:07:20+08:00'
  notes: 已对照原文 DemoKeyEnc/GetLegalKey/GetLegalIV 截图与注册成功截图核对：AES-CBC key 前32字节、IV 前16字节、machineCode+800823 固定后缀、10年授权与默认/后门账号均一致。
---

## 一句话结论

ICPAS（IP 网络对讲广播系统）的授权注册码由客户端侧 AES-CBC 加密，密钥与 IV 以明文常量硬编码在 .NET 程序集中；攻击者取页面显示的 machineCode，构造明文 `machineCode + "800823"`，用硬编码 key/IV 加密并 Base64 后提交 `php/reglicense.php`，即可通过 `RegisterSoftware` 的许可证校验获得 10 年授权，随后用默认 `admin/admin` 或后门 `administrator/800823` 登录系统。

## 原理

- 注册入口：前端 `index.js` 将 `jsondata.regcode` POST 到 `php/reglicense.php`；该 PHP 通过 `UdpSendAndRecvJson` 把 JSON 转发到 8888 端口的 `AppWebService`（SOAP/WCF），最终进入 `AppManager.HandleRecvString` → `HandleToken` → `RegisterSoftware(regCode, currentUser)`。
- `HandleToken` 在未注册状态下只放行少数消息类型，`reglicense` 在白名单中，因此未授权用户可以直接到达注册逻辑。
- `RegisterSoftware` 先尝试 `VTRegister.Register(machineCode, regCode)`（硬件注册）；失败后调用 `demoEncoder.Decrypto(regCode)`：
  - `DemoKeyEnc` 构造函数内含一段长字符串常量，`GetLegalKey()` 将其按底层 AES 要求的密钥长度截断/补空格；实际生效 key 为前 32 字节 `Guz(%&hj7x89H$yuBI0456FtmaT5&fvH`。
  - `GetLegalIV()` 同样从常量 `aclejaspwejgjdjf...` 截取前 16 字节 `aclejaspwejgjdjf`。
  - `Decrypto` 先 Base64 解码，再 AES-CBC 解密并读取明文。
- 解密结果必须满足 `text.StartsWith(machineCode)`；之后若 `text.Equals(machineCode + "800823")` 或 `/proc/version` 内容包含 `kylin`，即写入 10 年有效期授权；另有把 machineCode 后接数字秒数（以 `-` 分隔）的普通分支，最长只给 2 个月。
- 由于密钥、IV、固定后缀 `800823` 都来自客户端可反编译的程序集，安全性完全依赖“攻击者不知道算法”的隐晦，属于可离线伪造的许可证校验。

## 触发条件

- 目标运行 ICPAS/IP 网络对讲广播系统，PHP 前端与 8888 端口 AppServer（WCF）可达。
- 授权页面可访问并能读取 machineCode（页面直接显示，形如 `8111E-F65C3-29B92-0CA58-686B`）。
- .NET 程序集未加壳或可被 dnSpy 等工具反编译，能读出 `DemoKeyEnc` 的 key/IV 常量。
- `reglicense` 消息在未注册白名单内（默认如此）。

## 利用步骤

1. 打开系统授权页面，记录“机器码”字符串。
2. 反编译 `AppServer.exe`，定位 `DemoKeyEnc`，确认 AES-CBC 的 key（截断后 32 字节）与 IV（截断后 16 字节），以及固定后缀 `800823`。
3. 拼接明文 `machineCode + "800823"`，按 AES-CBC/PKCS#7 加密后 Base64。
4. POST 到 `php/reglicense.php`：`jsondata[regcode]=<Base64密文>`（或按前端格式提交 JSON）。
5. 返回注册成功后，用默认账号 `admin/admin` 或文章提到的后门账号 `administrator/800823` 登录；若默认密码已被修改，可继续利用后续 PHP 漏洞获取权限。

## PoC

```python
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

machine = "8111E-F65C3-29B92-0CA58-686B"
key = b"Guz(%&hj7x89H$yuBI0456FtmaT5&fvH"   # 32 字节
iv  = b"aclejaspwejgjdjf"                     # 16 字节
plain = (machine + "800823").encode()
regcode = b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, 16))).decode()
print(regcode)  # 原文样例: kKCVtpWQ4JXf76kby4i/sV2KHLcCCV3Kf3YwbwbxsK1mejSuLXE6NWbEy7WoHKBK
```

```http
POST /php/reglicense.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

jsondata[regcode]=kKCVtpWQ4JXf76kby4i/sV2KHLcCCV3Kf3YwbwbxsK1mejSuLXE6NWbEy7WoHKBK
```

## 变体与关联

- **Kylin 分支**：若目标为麒麟系统（`/proc/version` 含 `kylin`），只要解密结果以 machineCode 开头即给 10 年授权，无需固定后缀，伪造更简单。
- **数字秒数分支**：`machineCode-<数字>` 形式可被解析为到期秒数，最长被限制为 2 个月；可用于短期授权。
- **VTRegister 分支**：若 `VTRegister.Register(machineCode, regCode)` 成功则直接写入授权，该 DLL 的校验逻辑可进一步逆向。
- **默认/后门账号**：文章称系统默认 `admin/admin`，且存在 `administrator/800823`；授权绕过与默认口令组合可直达管理后台，再衔接 PHP RCE/文件读写漏洞。
- **局限**：不同版本的程序集可能更换 key/IV 或固定后缀，需以目标版本反编译结果为准。

## 检测与防御

- **授权实现**：不要把对称密钥硬编码在客户端程序集；使用非对称签名（服务端私钥签名、客户端仅验签）或服务端在线校验，license 内容绑定机器码并使用不可伪造的 MAC。
- **账号**：删除/禁用默认与后门账号，首次登录强制改密；审计 `administrator` 等异常账号。
- **检测**：监控 `reglicense` 接口的重复提交、异常 machineCode 与短时间多次授权尝试；比对授权文件写入时间与登录来源。
- **加固**：.NET 程序集混淆/加壳只能提高逆向成本，不能替代密码学设计。
