---
id: web-java-framework-shiro-550-hardcoded-key-deserialization
title: Shiro-550 硬编码 AES 密钥导致 rememberMe 反序列化 RCE
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-550-rememberme-deserialization
aliases:
- Shiro-550
- CVE-2016-4437
- rememberMe 反序列化
- Shiro 硬编码密钥
- Shiro rememberMe RCE
tags:
- java
- shiro
- deserialization
- rememberme
- aes
- hardcoded-key
- rce
cve:
- CVE-2016-4437
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: Apache Shiro <= 1.2.4
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:41:02+08:00'
  notes: 已对照原文与图 03-04、24-31 核对：rememberMe=base64(IV+ciphertext)、CookieRememberMeManager 硬编码密钥 kPH+bIxk5D2deZiIxcaaaA==、ShiroAttack2 爆破/CommonsBeanutils1+TomcatEcho、无回显 DNS(URLDNS)/JRMP 均与原文一致；affected_versions 按原文 Apache Shiro<=1.2.4。
---

## 一句话结论

Apache Shiro <= 1.2.4 的 `CookieRememberMeManager` 使用硬编码 AES 密钥处理 `rememberMe` Cookie，攻击者用该密钥加密 `ysoserial` 生成的序列化 payload，即可在服务端反序列化时执行任意命令。

## 原理

- 登录勾选 RememberMe 时，Shiro 将用户信息序列化 → AES 加密 → Base64 编码，写入 `rememberMe` Cookie；Cookie 结构是 `base64(IV + ciphertext)`。
- 服务端收到请求后反向执行 Base64 解码 → 用密钥 AES 解密 → Java 反序列化。反序列化本身就会触发 gadget 链。
- 问题在于默认/示例配置中的 AES 密钥是硬编码的（常见为 `kPH+bIxk5D2deZiIxcaaaA==`），所有部署相同。攻击者知道密钥即可自行构造合法密文。
- 即使服务端修改了密钥，若密钥落在常见字典中，也可以用工具爆破；爆破成功后的利用方式与硬编码相同。
- 无回显时，可用 URLDNS/JRMP 等出口把执行结果或连接带出（DNS 查询、JRMP 回调），不影响反序列化本身。

## 触发条件

- Apache Shiro <= 1.2.4，或更高版本仍使用默认/弱密钥。
- 应用启用 rememberMe（登录页有“记住我”，或响应/请求中出现 `rememberMe` Cookie）。
- 服务端 classpath 存在可利用的 gadget 依赖（CommonsBeanutils、CommonsCollections 等）或 JNDI 链。

## 利用步骤

1. 识别 Shiro：未登录请求无 `rememberMe`；登录失败响应出现 `Set-Cookie: rememberMe=deleteMe`；勾选记住我后 Cookie 中出现 `rememberMe`。
2. 用 ShiroAttack2 等工具检测当前密钥、爆破字典密钥。
3. 选择可用 gadget 链（如 CommonsBeanutils1），生成命令 payload。
4. 用密钥加密 payload，按 `base64(IV + ciphertext)` 放入 `rememberMe` Cookie 发送。
5. 观察命令回显；无回显时改用 DNS/JRMP 外带。

## PoC

工具方式（ShiroAttack2）：

```text
目标地址填入 http://target:8080/
关键字 rememberMe
点击“爆破密钥” → 得到 kPH+bIxk5D2deZiIxcaaaA==
利用链选 CommonsBeanutils1，回显方式 TomcatEcho
点击“爆破利用链及回显” → 命令执行
```

手工构造思路：

```bash
java -jar ysoserial-all.jar CommonsBeanutils1 "id" > poc.ser
# 用泄漏/爆破得到的 AES key，按 AES-CBC + 随机 IV 加密 poc.ser
# Cookie: rememberMe=base64(IV + ciphertext)
```

## 变体与关联

- 变体：密钥被修改但仍在字典中 → 先爆破再按本链利用；无回显 → URLDNS 探测或 JRMPListener + 反弹 shell；AES-GCM 配置需使用对应加密模式。
- 关联：[[web-java-framework-shiro-721-padding-oracle]]（密钥随机时改用 Padding Oracle 伪造 Cookie）；[[web-java-framework-shiro-spring-path-auth-bypass]]（Shiro 鉴权绕过，可与 RCE 组合）。
- 边界：Shiro >= 1.2.5 默认改为随机密钥；若应用使用强随机密钥且不在字典中，本链不成立。

## 检测与防御

- 检测：请求 Cookie 中出现异常长的 `rememberMe`；响应反复出现 `rememberMe=deleteMe`；反序列化异常堆栈；服务端出现 `ysoserial` gadget 类名或异常子进程。
- 防御：升级 Shiro 并配置强随机密钥（不要使用默认值）；不需要 rememberMe 时关闭；限制反序列化白名单/使用安全的序列化格式；移除不必要的 gadget 依赖；将 Shiro 会话与业务鉴权分层。
