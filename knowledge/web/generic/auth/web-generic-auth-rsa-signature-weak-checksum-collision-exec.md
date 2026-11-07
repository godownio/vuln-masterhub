---
id: web-generic-auth-rsa-signature-weak-checksum-collision-exec
title: RSA 签名只绑定 sum(data)*len(data)：校验和碰撞复用签名执行任意脚本
type: scenario
domain: web
path: web/generic/auth
technique: rsa-signature-weak-checksum-collision
aliases:
- 弱签名校验和碰撞
- RSA 签名对象过弱
- sum*len 签名绕过
- ZSig 弱校验
- 签名复用执行任意脚本
tags:
- rsa
- signature-bypass
- checksum
- collision
- archive
- code-execution
- authentication
- weak-validation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V118
  verified_at: '2026-11-06T01:47:51+08:00'
  notes: 已对照原文核对；ZSig 格式、sum*len 弱校验、108/9818 约束、注释填充碰撞与 exec 链均一致
---

## 一句话结论

验证器用 RSA 公钥验证 `pow(signature, e, n) == sum(data) * len(data)`，签名只绑定了字节和与长度这两个线性约束，而不是数据哈希；攻击者保持长度和字节和不变即可构造任意新脚本，复用原签名通过校验，随后被 `exec` 执行。

## 原理

- 数字签名的安全性取决于“签的是什么”。RSA 本身不可伪造，但如果被签对象是 `checksum(data) = sum(data) * len(data)`，攻击者无需私钥，只需构造 `sum` 与 `len` 相同的另一段数据。
- 长度固定为 n 时，`sum(d[i]) = S` 是 n 个变量上的一个线性等式；把 n-1 个字节自由取值，最后一个字节由等式唯一确定，只要结果落在合法字节范围即可。碰撞构造只需一次减法和越界检查，不需要搜索。
- 可打印 ASCII 范围 32–126 给每个字节 95 种取值，自由变量极多，碰撞空间巨大；注释、填充、无用变量都可参与字节和，但不影响脚本执行。
- 校验通过后直接 `exec(data.decode(), {"__name__": "__main__"})`，签名验证的“数据完整性”承诺完全落空，等于把脚本执行权交给攻击者。
- 另一个细节：签名长度常量 `SIG_LEN=128` 声明了却未参与校验，解析只按固定偏移取 128 字节；声明了却未执行的约束常是完整实现被简化后的残留，审计时应关注。

## 触发条件

- 目标接受归档/脚本文件，文件头包含签名、长度与数据区；验证器用公钥验签后才执行数据。
- 被签对象是弱校验和（`sum`、`sum*len`、CRC32、简单异或等），不是 SHA-256/HMAC 等强摘要。
- 归档格式允许攻击者控制 Data 区的全部字节，且长度字段与数据区长度一致。
- 验证器在验签通过后执行脚本/反序列化/加载配置，未做二次完整性校验或来源校验。
- 攻击者能拿到一份合法基线样本及其签名（通常随客户端/更新包分发）。

## 利用步骤

1. 解析归档格式：确认 magic、分隔符、签名偏移、长度字段与 Data 起始位置；记录基线样本的 `size`、`len(data)`、`sum(data)`。
2. 计算基线校验值：`checksum = sum(data) * len(data)`；用公钥 `pow(sig, e, n)` 验证其与签名匹配，确认弱校验关系。
3. 编写目标脚本：例如输出指定字符串或执行目标动作，尽量短，减少填充负担。
4. 构造碰撞：保持总长度等于基线长度，字节和等于基线字节和。可用 Python 注释 `#` 后填充任意字符；也可按剩余预算均匀分配可打印字节。
5. 拼装新归档：保留原头部（magic/分隔符/原签名/长度/分隔符），只替换 Data 区；新文件长度与基线一致。
6. 提交验证器：验签通过后 `exec` 执行新脚本，完成任意代码执行/业务绕过。

## PoC

```python
base = b"print('archive-disposal-bypassed')\n"   # 目标脚本
target_len, target_sum = 108, 9818               # 基线约束

# 用注释填充到相同长度与字节和
pad_len = target_len - len(base)
pad_sum = target_sum - sum(base)
pad = b"#" + b"Z" * (pad_len - 2) + bytes([pad_sum - ord("#") - ord("Z") * (pad_len - 2)])
data = base + pad
assert len(data) == target_len and sum(data) == target_sum

# 复用原签名，拼装新归档
archive = (b"\x01ZSig" + b"\x02" + signature + b"\x03"
           + len(data).to_bytes(4, "big") + b"\x04" + data)
```

```python
# 均匀分配版本（更通用）
core = b"print('archive-disposal-bypassed')\n#"
remain_len = target_len - len(core)
remain_sum = target_sum - sum(core)
fill = []
extra = remain_sum - 32 * remain_len
for _ in range(remain_len):
    add = min(94, extra)
    fill.append(32 + add)
    extra -= add
payload = core + bytes(fill)
assert len(payload) == target_len and sum(payload) == target_sum
```

无真实目标 PoC：原文为 CTF 归档格式，字段偏移与常量需按实际验证器调整；核心是“保持长度与字节和不变、复用签名”。

## 变体与关联

- **其他弱校验**：`sum(data)`、`len(data)`、`sum*len`、CRC32、Adler-32、单字节 XOR、`hash % N` 都可能被线性/低成本碰撞。
- **签名字段未覆盖**：签名只覆盖头部/部分字段，Data 区未纳入；或长度字段未参与校验，可截断/追加数据。
- **签名算法误用**：RSA 未使用 PSS/OAEP、PKCS#1 v1.5 填充校验不严、`e=3` 低指数、模数过小可分解。
- **执行点**：验签后 `exec`/`eval`、反序列化、加载插件、解压覆盖文件；签名通过即信任，缺少二次校验。
- **关联**：JAR 重打包签名校验边界、API 签名只覆盖部分方法、JWT 只验签不验角色、客户端 MD5 签名可复现。

## 检测与防御

- **签强摘要**：签名对象必须是 SHA-256/SHA-3 等强哈希，或直接对完整规范化的数据签名；不要对 `sum`、`len`、CRC 等线性校验和签名。
- **签名覆盖全字段**：magic、长度、Data、元数据全部纳入签名范围；长度字段与实际数据长度强校验，拒绝截断/追加。
- **验签后最小权限**：不要在校验通过后直接 `exec` 任意脚本；使用白名单动作、沙箱、只读配置解析，禁止动态代码执行。
- **密钥与算法**：使用足够长的 RSA 模数（≥2048 位）和 PSS 填充；优先 Ed25519/ECDSA；校验签名长度与编码，拒绝非规范签名。
- **检测**：监控签名验证通过但 Data 哈希/长度与基线不符的归档；对同一签名对应多个不同 Data 的情况告警；审计声明未使用的安全常量。

## 可信度与边界

- 原文为 CTF 题，基线签名、校验和计算、碰撞构造与验证器执行均有实测输出；攻击链完整。
- 归档格式（`\x01ZSig`、128 字节签名、108 字节 Data）与模数/指数为该题实现；真实目标需按实际格式复现。
- 未在真实目标复跑 PoC；卡内不包含题目 flag。
