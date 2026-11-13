---
id: web-java-deser-shiro-redis-cache-session-deserialization
title: shiro-redis RedisCache 缓存反序列化：拿到 Redis 口令后写 shiro:session 缓存投递 CommonsBeanutils1Shiro 载荷 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: shiro-redis-cache-session-deserialization-redis-write
tags:
- java
- deserialization
- shiro
- shiro-redis
- redis
- session
- ysoserial
- commons-beanutils
- templatesimpl
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V666
  verified_at: '2026-11-13T08:40:47+08:00'
  notes: 已对照原文53图核对并经复核修正：写入键为 shiro:session:test（RedisUtil.java 截图），触发为 POST /login Cookie JSESSIONID=test 返回 500（Shiro AbstractShiroFilter 过滤器栈）；原文 GET 展示的是真实会话键 shiro:session:937c9042-... 的序列化内容，1231 仅出现在注释行；hydra 命令为 hydra -P top1000.txt redis://192.168.10.175（默认线程）。待验证：CommonsBeanutils1Shiro 生成器源码与 JDK 适配原文未给出；500 具体抛错步骤未展开，以监听结果为准。affected_versions 原文未标注，保持为空。
url: /docs/web/java/deserialization/web-java-deser-shiro-redis-cache-session-deserialization/
draft: false
kb_aliases:
- shiro-redis 反序列化
- RedisCache.get 反序列化
- org.crazycake.shiro.RedisCache
- ObjectSerializer.deserialize
- shiro:session
- CommonsBeanutils1Shiro
- Redis session 投毒
- 缓存反序列化 RCE
---

# 一句话结论

应用集成 shiro-redis（crazycake）后，Shiro 的会话/缓存对象以 Java 原生序列化形式存放在 Redis（键如 `shiro:session:<id>`）；攻击者只要拿到 Redis 口令（弱口令或未授权），就能把该键的值替换成 ysoserial 的 CommonsBeanutils1Shiro（CommonsBeanutils + TemplatesImpl，Javassist 生成恶意 Translet）载荷，再带对应 session id 的 Cookie 请求应用——`RedisCache.get` 会调用 `ObjectSerializer.deserialize` 执行 `readObject`，直接触发 RCE（文章案例：web 用户反弹 shell，随后 msf 上线）。

# 原理

- **sink 在 RedisCache.get**：shiro-redis 的 `org.crazycake.shiro.RedisCache#get(K key)` 先 `keySerializer.serialize` 得到缓存键，再 `redisManager.get(...)` 取原始字节，最后 `valueSerializer.deserialize(rawValue)` 还原对象。默认 `valueSerializer` 为 `ObjectSerializer`，其 `deserialize(byte[])` 直接 `new ObjectInputStream(...).readObject()`（MultiClassLoaderObjectInputStream）。因此“Redis 中可控的字节”就是标准的 Java 反序列化入口，不需要 RFC/协议层漏洞。
- **会话如何落进 Redis**：shiro-redis 的 SessionDAO 通常以 `shiro:session:<sessionId>` 形式把会话对象写入 Cache，并在后续请求按 session id 读回。攻击者写好键后，只要让请求携带同一个 session id（Shiro 默认 Cookie 名 JSESSIONID/或应用自定义，可从抓包/登录响应获得），SessionManager 就会从 Redis 读取并反序列化该值。
- **gadget 选择**：案例应用 classpath 含 `commons-beanutils:1.9.4`（依赖截图），使用 ysoserial 的 `CommonsBeanutils1Shiro` 变体：CommonsBeanutils 链负责触发 `TemplatesImpl.newTransformer`，`TemplatesImpl` 的 `_bytecodes` 由 Javassist 动态生成的 `Evil extends AbstractTranslet` 类字节码填入（构造器里执行命令）。该变体规避了标准 CommonsBeanutils1 对 JDK 版本/字段的适配问题，适合 Shiro 类目标。
- **投递方式**：`Jedis.auth("abc123"); jedis.set("shiro:session:test", payload)`（或 `redis-cli -x set`），见文章 RedisUtil 测试代码（其中的 `shiro:session:1231` 只是被注释掉的 get 行）；随后用携带 `Cookie: JSESSIONID=test` 的请求触发。案例：`redis-cli -h 192.168.10.175 auth abc123` 后 `KEYS *` 为空，GET 真实会话键（如 `shiro:session:937c9042-f1a8-4680-8a08-752bb0441b24`）可见 `\xac\xed\x00\x05sr ... java.util.HashMap` 序列化内容（另一个键 `shiro:session:65211a17-...` 的值为字符串 `"1111"`），说明会话值确为 Java 原生序列化。
- **为什么能写 Redis**：案例 6379 对内网可达且口令弱，`hydra -P top1000.txt redis://192.168.10.175`（截图为默认 16 线程）爆破得到 `abc123`；同一手法也适用于 Redis 未授权访问。
- **注意触发反馈**：文章触发请求（`POST /login`，`Cookie: JSESSIONID=test`）返回 HTTP 500，响应堆栈可见 `java.servlet.ServletException: Filtered request failed` 及 Shiro `AbstractShiroFilter/OncePerRequestFilter` 过滤器链，但命令已在反序列化阶段执行——不能以“请求报错”判定利用失败，应看反弹监听是否收到连接（案例随后 msf 会话 getuid=web）。

# 触发条件

- 目标应用使用 shiro-redis（或把 Java 序列化对象写入外部缓存并在读取时 `readObject` 的同类实现），会话/缓存数据存于 Redis。
- 攻击者能访问并写入 Redis：未授权或弱口令（案例 `abc123`），且键空间未被 ACL 限制为只读。
- 应用 classpath 存在可用 gadget（案例 commons-beanutils 1.9.4 + TemplatesImpl；另可尝试 CommonsCollections 3.2.1 等）。
- 请求可携带与写入键一致的 session id（Cookie 名/格式已知或可从响应/抓包获得）。
- 目标 JVM 允许 TemplatesImpl 路线（JDK 8 等常规环境；更高版本需其它 gadget 适配）。

# 利用步骤

1. 信息收集：fscan/nmap 发现 8080（Shiro/Spring 应用）与 6379 Redis；`hydra -P <字典> redis://<target>`（案例 `hydra -P top1000.txt redis://192.168.10.175`）或未授权连接确认可写。
2. `redis-cli -h <target> -p 6379 auth <口令>`，`KEYS *` 查看 `shiro:session:*`，`GET` 一个键确认以 `\xac\xed\x00\x05` 开头（Java 序列化）。
3. 编写 `Evil extends AbstractTranslet`（transform 空实现，构造器执行反弹/命令）；用 Javassist 取其字节码，交给 ysoserial `CommonsBeanutils1Shiro` 生成序列化 payload。
4. 通过 Jedis/redis-cli 写入 `shiro:session:<id>` = payload。
5. 发送带 `Cookie: JSESSIONID=<id>`（案例为 `test`）的请求触发 `RedisCache.get → ObjectSerializer.deserialize`；即使返回 500，也检查监听端是否收到反弹 shell/命令执行。
6. 上线后按需提权与横向（案例：web 用户会话，后续翻到 id_rsa 与域环境信息）。

# PoC

```java
// 文章 RedisUtil 的核心思路（简化）
ClassPool pool = ClassPool.getDefault();
CtClass clazz = pool.get(Evil.class.getName());          // Evil extends AbstractTranslet
byte[] payload = new CommonsBeanutils1Shiro().getPayload(clazz.toBytecode());
Jedis jedis = new Jedis("192.168.10.175", 6379);
jedis.auth("abc123");
jedis.set("shiro:session:test".getBytes(), payload);     // 随后带 Cookie: JSESSIONID=test 请求应用触发
```

```text
# Redis 侧确认
redis-cli -h 192.168.10.175 -p 6379
auth abc123
GET shiro:session:<id>      # 真实会话键如 shiro:session:937c9042-...，以 \xac\xed\x00\x05 开头即 Java 序列化值
```

# 变体与关联

- 与库内 Shiro rememberMe 系列卡（`web-java-framework-shiro-550-*`、`configured-weak-cipherkey-rememberme-rce` 等）区分：那些入口是 rememberMe Cookie 的 AES 解密后 `readObject`；本卡入口是“可写 Redis → 缓存/session 值反序列化”，不需要 Shiro 密钥。
- 与 Django/Redis session pickle、Django FileBasedCache、PHP Memcached 对象注入等卡同构：**缓存/session 存储可写 + 反序列化 sink** 的组合；可对照这些卡理解“投递—触发”两段式。
- gadget 可替换：CommonsCollections 3.2.1、CommonsBeanutils1（标准版）、其它 TemplatesImpl/BCEL 链；依赖版本不同选择不同链。案例依赖还包括 commons-collections:3.2.1、commons-beanutils:1.9.4。
- 若 Redis 暴露在公网且应用为 shiro-redis，可作为未授权打点直接 RCE，无需先拿 Web 漏洞。

# 检测与防御

- Redis：禁止公网暴露，绑定 127.0.0.1/内网并设置强口令与 ACL（禁用危险命令、限制键空间），及时修复未授权访问。
- 序列化：不要把 Java 原生序列化用于缓存/session；shiro-redis 显式配置 JSON/白名单序列化器（如 `JsonSerializer`），或为 ObjectInputStream 设置 `ObjectInputFilter` 类白名单，阻断 TemplatesImpl 等危险类。
- 应用：session id 使用强随机且不可枚举；对异常超长 Cookie/base64 字符告警；关闭不必要的 CommonsBeanutils 等 gadget 依赖。
- 检测：Redis 中出现 `shiro:session:*` 的 SET 且值为 Java 序列化魔数（`\xac\xed\x00\x05`）；应用日志中 `ObjectInputStream.readObject → TemplatesImpl.newTransformer` 调用栈；Java 进程加载非业务 Translet 类并拉起 `bash -c`/nc 反弹连接。

# 待验证点

- 文章未给出 CommonsBeanutils1Shiro 生成器的完整源码与 JDK 版本细节，仅展示 RedisUtil 调用与依赖；实际复现需按目标 JDK/依赖调整 gadget。
- 文章触发请求返回 500 但命令已执行，具体是哪一步抛错未展开；可见堆栈为 `ServletException: Filtered request failed` + Shiro 过滤器链，复用时以监听结果为准。
- 写入 payload 的键必须与触发请求的 `JSESSIONID` 一致（案例 RedisUtil 写 `shiro:session:test`，Burp 以 `JSESSIONID=test` 触发）；真实会话键的 UUID 形式与字符串 `"1111"` 键并存，说明会话键空间取决于应用配置，实战需先枚举确认。
