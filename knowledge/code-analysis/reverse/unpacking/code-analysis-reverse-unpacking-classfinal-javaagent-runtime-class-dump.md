---
id: code-analysis-reverse-unpacking-classfinal-javaagent-runtime-class-dump
title: ClassFinal 加密 JAR 逆向：javaagent 运行时解密 + Arthas 枚举、反编译并修改已加载类
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: classfinal-javaagent-runtime-class-dump
aliases:
- ClassFinal 脱壳
- ClassFinal 加密 JAR 逆向
- CoreAgent premain
- AgentTransformer ClassFileTransformer
- javaagent 运行时解密
- Arthas sc jad dump
- 加密 JAR 内存取证
tags:
- code-analysis
- reverse
- unpacking
- java
- jar
- classfinal
- javaagent
- arthas
- classloader
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:16:45+08:00'
  notes: 已对照原文与图01-18核对 CoreAgent.premain 取密码、AgentTransformer 解密与 CAFEBABE 检查、sc/ognl 改 Authorization；原文图10显示 strict 模式下 setAccessible 失败、图12需 options strict false，已在卡中补齐该步骤；keygen 部分原文未给脚本，按跳过理由未成卡。未在本机运行目标 JAR/Arthas。
---

## 一句话结论

ClassFinal 保护的 JAR 通过内嵌 javaagent 在 JVM 启动时注册 `ClassFileTransformer`，在类加载时把加密 class 解密后交给 JVM；因此运行中的 JVM 内存里已经是明文字节码，只需以正确方式启动 JAR 并 attach Arthas，用 `sc` 枚举已加载类、`jad`/`dump` 反编译或导出，就能绕过静态加密分析业务逻辑。

## 原理

- **ClassFinal 是 class 加密壳**：它把 JAR 中的 class 加密，加密后的 JAR 不能直接 `java -jar` 运行，必须通过 `java -javaagent:yourproject-encrypted.jar -jar yourproject-encrypted.jar` 启动；agent 与加密 JAR 是同一个文件，JVM 先加载 agent 再启动应用。
- **premain 入口取密码**：`CoreAgent.premain(String args, Instrumentation inst)` 是 agent 入口。它从多个渠道获取密码：
  - `JarDecryptor.readPassFromJar(JarUtils.getRootPath(null))` 读取 JAR 内嵌密码；
  - 命令行参数 `-pwd` / `-pwdname`（环境变量名）；
  - `-nopwd` 无密码模式（把 pwd 设为 `#`）；
  - `-del` 读取后删除密码。
  拿到密码后初始化 `AgentTransformer` 并注册到 `Instrumentation`。
- **ClassFileTransformer 在加载时解密**：`AgentTransformer.transform(loader, className, classBeingRedefined, domain, classBuffer)` 对每个被加载的类调用 `JarDecryptor.getInstance().doDecrypt(projectPath, className, pwd)`；解密成功后检查字节前四字节是否为 `CAFEBABE`（有符号字节 `-54,-2,-70,-66`），是则返回解密后的字节，否则返回原始 `classBuffer`。
- **为什么内存里是明文**：JVM 的类加载流程要求 transformer 返回可用的 class 字节；ClassFinal 必须在 `defineClass` 之前把密文解成明文，否则类无法验证/执行。因此任何成功加载的类，其字节码在 JVM 内都是明文，静态加密无法阻止运行时提取。
- **Arthas 的分析能力**：attach 后 `sc <package>.*` 列出已加载类；`jad <class>` 反编译字节码；`dump <class>` 把 class 字节写到磁盘；`ognl` 可读取/修改静态字段。样例用 `sc com.exploit.gui.*` 找到 `com.exploit.gui.obfuscated.l`，用 `ognl` 把静态字段 `Authorization` 置为 `true` 绕过激活校验。注意 Arthas 默认 `strict=true`，OGNL 严格模式下 `setAccessible`/`setBoolean` 会抛 `IllegalAccessException`（原文图10），必须先执行 `options strict false` 再改字段（图12/13）。
- **局限**：只有“已经被加载”的类才能 dump；未触发的方法/类仍是密文。需要先运行到目标逻辑，或改用 keygen/静态解密。样例中作者因此转向 keygen，而不是完整脱壳。

## 触发条件

- 目标 JAR 使用 ClassFinal 保护，且攻击者能按其要求以 `-javaagent` 方式启动（或目标已在运行，可 attach）。
- 能 attach Arthas（同一用户/JVM，attach API 可用，未被安全策略/agent 阻止）。
- 目标类已被加载（访问过对应功能），否则 `sc`/`jad` 看不到。
- 没有额外的反调试/反 attach 保护；ClassFinal 自身不阻止 Arthas。

## 利用步骤

1. 确认启动方式：命令行含 `-javaagent:xxx-encrypted.jar`，且 JAR 内可见 `CoreAgent`/`AgentTransformer`/`JarDecryptor` 等类。
2. 按原方式启动应用（有密码用 `-pwd`/`-pwdname`，无密码用 `-nopwd`），确保目标功能被触发、相关类已加载。
3. attach Arthas：`java -jar arthas-boot.jar <pid>`。
4. 枚举类：`sc com.target.*`，或用 `sc -d <class>` 看类加载器/来源。
5. 反编译/导出：`jad <class>` 查看逻辑；`dump <class>` 导出 class 文件；必要时 `heapdump` 后离线分析。
6. 运行时改写：先 `options strict false` 关闭 OGNL 严格模式，再用 `ognl` 读取/修改静态字段（如授权标志、license 校验结果），或调用方法验证逻辑。
7. 若需完整脱壳，遍历已加载类批量 `dump`；对未加载类，结合启动流程触发或分析 `JarDecryptor` 的密钥/算法静态解密。

## PoC

```bash
# 1. 以 ClassFinal 要求的方式启动
java -javaagent:app-encrypted.jar -jar app-encrypted.jar

# 2. attach Arthas
java -jar arthas-boot.jar <pid>

# 3. 枚举已加载类
sc com.exploit.gui.*

# 4. 反编译/导出目标类
jad com.exploit.gui.obfuscated.l
dump com.exploit.gui.obfuscated.l
```

```text
# 5. 关闭 OGNL 严格模式，避免 setAccessible 抛 IllegalAccessException
options strict false

# 6. 用 OGNL 修改静态授权字段（示例）
ognl '
#c=@com.exploit.gui.obfuscated.l@class,
#f=#c.getDeclaredField("Authorization"),
#f.setAccessible(true),
#f.setBoolean(null,true),
@com.exploit.gui.obfuscated.l@Authorization
'
```

## 变体与关联

- 变体：`-nopwd` 无密码模式、密码来自环境变量 `-pwdname`、`-del` 读取后删除。
- 变体：不解密 JAR，直接从运行进程的 Heap Dump 中提取 `JarDecryptor` 的密钥/明文 class。
- 变体：用 Java agent 的 `ClassFileTransformer` 在类加载时把 `classfileBuffer` 写到磁盘（与 XJar 卡相同的辅助思路）。
- 关联卡片：[[code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key]]、[[defense-forensics-java-memshell-heapdump-bytecode]]、[[defense-detection-arthas-agent-memshell-detect-remove]]、[[defense-detection-proxyvalve-memshell-arthas-remove]]。

## 检测与防御

- 检测：启动命令行出现 `-javaagent:*-encrypted.jar`、`CoreAgent`、`ClassFinal` 等特征；JAR 内存在 `AgentTransformer`/`JarDecryptor` 类。
- 检测：运行期出现 Arthas attach（`arthas-boot.jar`、`com.taobao.arthas` agent）、`sc`/`jad`/`dump`/`ognl` 调用；静态授权字段被反射修改。
- 防御：ClassFinal 只提高静态分析成本，不能防运行时提取；敏感逻辑应放服务端，客户端只做展示。
- 防御：检测/限制 java agent attach（`-XX:+DisableAttachMechanism`、OS 级 ptrace 限制），校验授权状态的服务端签名，避免仅靠客户端静态字段。
