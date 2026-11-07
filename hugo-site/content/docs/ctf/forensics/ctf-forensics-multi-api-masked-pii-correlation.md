---
id: ctf-forensics-multi-api-masked-pii-correlation
title: 多接口脱敏数据关联还原身份链：手机号爆破 + 姓名/生日/身份证/邮箱/IP 交叉匹配
type: scenario
domain: ctf
path: ctf/forensics
technique: multi-api-masked-pii-correlation
tags:
- ctf
- forensics
- pii
- de-anonymization
- pcap
- rsa
- aes
- correlation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:30+08:00'
  notes: 已对照原文 接口未授权 3 核对：/cryptodemo 的 AES-ECB+RSA、费马分解、解密 /api/lottery/result 找中奖手机号 18210104751、winners/participants/user.info/get_comment 交叉关联到张俊-420300196010318621-123.7.15.172 均一致；未实际运行。
url: /docs/ctf/forensics/ctf-forensics-multi-api-masked-pii-correlation/
draft: false
kb_aliases:
- 脱敏数据关联
- 多接口 PII 聚合
- 手机号爆破
- 身份证生日补全
- 身份链还原
- 数据安全赛道
---

## 一句话结论

多个未授权接口分别泄露姓名、脱敏手机号、脱敏身份证、明文 IP、用户名/生日；先用 RSA 私钥解出 AES key、AES-ECB 解密抽奖请求，从“中奖”响应定位完整手机号，再与中奖名单的脱敏手机号匹配到姓名，用生日补全身份证中间 8 位，用评论接口的明文 IP 关联，最终拼出完整身份链。

## 原理

- **单字段脱敏不等于匿名化**：手机号只隐藏中间四位、身份证只隐藏中间八位、姓名只隐藏名，但跨接口的准标识符（姓名、生日、手机号后四位、IP、用户名）组合后可唯一化。
- **生日是身份证的强关联键**：中国大陆 18 位身份证第 7–14 位是出生日期；`/api/user/info` 泄露 `birthday` 后可直接补全 `420300********8621` 的中间 8 位。
- **响应 oracle**：抽奖接口对正确手机号返回“恭喜你中奖”，对错误号码返回失败；这给出一个可验证的真值，用来从爆破请求中定位完整手机号。
- **前端混合加密可离线解**：`/cryptodemo` 泄露前端实现与 RSA 公钥；若模数 p、q 接近，可用费马分解恢复私钥 d，再用 RSA 解出每次请求的 AES key，用 AES-ECB 解出明文参数。
- **关联链**：完整手机号 → winners 中 `182****4751` → 姓名 `张俊`；姓名 + user/info 生日 → 身份证；姓名 + comment 明文 IP → 网络身份；四元组即完整身份链。

## 触发条件

- 多个接口分别返回同一批人的不同字段，且至少一个字段可跨接口匹配。
- 存在可验证的 oracle（中奖、登录成功、查询命中）或已知格式约束。
- 加密流量可解密（公钥可分解/私钥泄露/前端密钥硬编码）。
- 脱敏规则固定且可从样本推断。

## 利用步骤

1. 流量审计列出未授权接口：`/api/user/info`（用户名/生日/密码 MD5）、`/api/lottery/winners`（姓名/脱敏手机号）、`/api/lottery/participants`（脱敏姓名/脱敏身份证/发票号）、`/api/get_comment`（脱敏姓名/IP）、`/cryptodemo`（前端加密逻辑）。
2. 从 `/cryptodemo` 提取 RSA 公钥与 AES-ECB 逻辑；用费马分解恢复 p、q、d。
3. 解 `POST /api/lottery/result` 的 `{key,data}`：RSA 解 key 得 AES key，AES-ECB 解 data 得手机号；收集返回“恭喜你中奖”的那条。
4. 用完整手机号后四位匹配 winners 的 `182****4751`，得到姓名。
5. 用姓名匹配 user/info 的生日，补全 participants 中对应身份证的中间 8 位。
6. 用姓名匹配 comment 的明文 IP；按题目格式拼接 `姓名-手机号-身份证-IP`。

## PoC

```python
from Crypto.PublicKey.RSA import construct
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import unpad
import base64, json

priv = construct((n, e, d, p, q))
rsa_cipher = PKCS1_v1_5.new(priv)

def decrypt_payload(obj):
    aes_key = rsa_cipher.decrypt(base64.b64decode(obj["key"]), None)
    pt = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(base64.b64decode(obj["data"])), 16)
    return json.loads(pt)

# 对每条 /api/lottery/result 请求解密，找到响应为“恭喜你中奖”的手机号
# 再用手机号后四位 / 姓名 / 生日 / IP 做跨接口 join
```

## 变体与关联

- **关联键变体**：邮箱、地址、设备 ID、订单号、发票号、时间戳；身份证前 6 位是地区码，可与 IP 归属地交叉验证。
- **脱敏变体**：全掩码、哈希、差分隐私噪声、k-匿名；需要更多辅助信息或统计推断。
- **oracle 变体**：登录成功、短信验证码、查询命中、响应时间差异；也可用已知格式（手机号段/身份证校验位）过滤候选。
- **关联卡片**：[[crypto-rsa-fermat-close-prime-factorization]]（费马分解恢复 d）、[[ctf-forensics-http-unauth-api-audit]]（未授权接口发现）、[[ai-security-rag-security-pii-masking-coverage-output-side]]（脱敏覆盖不足）。
- **边界**：若各接口使用不同的匿名 ID 且无任何准标识符重叠，关联不成立；若脱敏字段加了不可逆噪声，需统计推断。

## 检测与防御

- **CTF/审计验证**：先确认手机号 oracle 命中，再用姓名/生日/身份证规则交叉验证，最后检查四元组是否唯一。
- **防御**：统一脱敏策略（同一实体在不同接口使用同一匿名 ID，或全部返回最小必要字段）；避免返回生日、完整 IP、发票号等准标识符；对批量查询/爆破做速率限制与行为检测；加密密钥不要放前端。
- **检测信号**：短时间内大量手机号枚举请求；跨接口按姓名/生日/手机号后四位的高频关联查询；未授权接口返回 PII。
