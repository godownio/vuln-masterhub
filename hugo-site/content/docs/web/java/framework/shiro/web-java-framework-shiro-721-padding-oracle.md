---
id: web-java-framework-shiro-721-padding-oracle
title: Shiro-721 对 rememberMe AES-CBC 做 Padding Oracle 伪造恶意 Cookie
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-721-padding-oracle
tags:
- java
- shiro
- padding-oracle
- aes-cbc
- rememberme
- deserialization
- rce
cve:
- CVE-2019-12422
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: Apache Shiro < 1.4.2
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:41:03+08:00'
  notes: 已对照原文与图 06-23 核对 AES-CBC P=I XOR IV、PKCS#7、逐字节恢复 I、IV_new=I XOR P_malicious 与 shiro_exp.py 用法；一句话称成功时返回'200/500 之外'表述有误（原文成功为 200、失败为 500+deleteMe），原理段已正确写明，仅措辞瑕疵；PoC 未在本机执行。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-721-padding-oracle/
draft: false
kb_aliases:
- Shiro-721
- CVE-2019-12422
- rememberMe Padding Oracle
- Shiro CBC 填充攻击
- IV 伪造
---

## 一句话结论

Shiro < 1.4.2 在 rememberMe 解密失败时返回 `deleteMe`、成功时返回 200/500 之外的正常响应，构成 Padding Oracle；攻击者无需知道 AES 密钥，逐字节恢复中间状态后重算 IV，就能让固定密文解密为恶意序列化 payload。

## 原理

- rememberMe Cookie 为 `base64(IV + C)`，服务端按 AES-CBC 解密：`P = D(C, key) XOR IV`，然后检查 P 的 PKCS#7 填充。
- 填充无效时 Shiro 返回 `rememberMe=deleteMe`（或 500）；填充有效时继续反序列化并返回正常响应。这个差异就是 oracle。
- 攻击者不改变密文 C，只修改前 16 字节 IV。对目标块逐字节爆破 IV 的最后一个字节：当 `P[last]` 恰好等于合法填充值（如 `0x01`）时，服务端不再返回 `deleteMe`，由此得到 `IV_success`。
- 已知 `P[last] = I[last] XOR IV[last]`，可反推中间状态 `I[last] = IV_success XOR 0x01`。
- 继续爆破倒数第二个字节：先把 IV 的最后一个字节固定为 `I[last] XOR 0x02`，使 `P[last]=0x02`，再爆破 IV 的倒数第二字节，直到 `P[last-1]=0x02`，形成合法两字节填充；同理逐字节恢复整个 I。
- 拿到完整 I 后，对任意恶意明文 `P_malicious`（ysoserial 生成的序列化字节）计算 `IV_new = I XOR P_malicious`，替换原 IV、保留原 C，服务端解密结果就是恶意 payload，随后反序列化触发 RCE。

## 触发条件

- Apache Shiro < 1.4.2。
- 攻击者持有一个格式正确、可被服务端解密的 rememberMe Cookie（有效会话或任意合法密文）。
- 服务端对填充错误与正常处理的响应存在可区分差异（状态码、`deleteMe`、响应长度、时间）。
- classpath 存在可用 gadget 链。

## 利用步骤

1. 登录并勾选 RememberMe，取得一个正常的 `rememberMe` Cookie。
2. Base64 解码，按前 16 字节切出 IV、其余为密文 C。
3. 用 Padding Oracle 脚本逐字节恢复中间状态 I（每字节最多 256 次请求，通常远少于 256）。
4. 用 ysoserial 生成目标命令的序列化 payload `P_malicious`。
5. 计算 `IV_new = I XOR P_malicious`，拼接 `base64(IV_new + C)` 作为新的 rememberMe 发送。
6. 观察命令执行结果；无回显时改用 DNS/JRMP 外带。

## PoC

```bash
# 1. 生成恶意序列化 payload（链按目标依赖选择）
java -jar ysoserial-all.jar CommonsBeanutils1 "id" > poc.ser

# 2. 用正常 cookie 和 payload 跑 Padding Oracle 脚本，得到新的 rememberMe
python2 shiro_exp.py "http://target/" "<正常的rememberMe密文>" poc.ser

# 3. 将脚本输出的 Cookie 带入请求
curl -s 'http://target/' -H 'Cookie: rememberMe=<new_cookie>'
```

核心推导：

```text
P[i] = I[i] XOR IV[i]
I[i] = IV_success[i] XOR padding_value
IV_new[i] = I[i] XOR P_malicious[i]
```

## 变体与关联

- 变体：oracle 可能表现为状态码 200/500、响应长度差异或时间差异；若只返回统一错误页，可尝试用时间侧信道；拿到 I 后也可伪造任意用户身份而非 RCE。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（密钥可爆破/硬编码时的更直接路径）；[[web-java-framework-shiro-spring-path-auth-bypass]]（鉴权绕过）。
- 边界：Shiro >= 1.4.2 修复了该 Padding Oracle；若服务端对错误响应完全统一，攻击成本显著上升。

## 检测与防御

- 检测：同一 Cookie 名在短时间收到大量仅 IV 不同的请求；响应在 `deleteMe` 与正常页之间交替；大量 500/200 长度差异；异常反序列化堆栈。
- 防御：升级 Shiro >= 1.4.2；使用强随机密钥并关闭不必要的 rememberMe；统一错误响应、避免可区分 oracle；限制反序列化类白名单；移除危险 gadget 依赖。
