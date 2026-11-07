---
id: cloud-cicd-jlink-java-base-jmod-backdoor
title: jlink 供应链植入：替换 java.base.jmod 在定制运行时镜像中植入 JVM 级后门
type: scenario
domain: cloud
path: cloud/ci-cd
technique: jlink-jmod-runtime-image-backdoor
aliases:
- jlink 后门
- jmod 投毒
- java.base.jmod 篡改
- 定制 JRE 后门
- JDK 供应链植入
- jimage 后门
tags:
- supply-chain
- ci-cd
- java
- jlink
- jmod
- asm
- bytecode
- backdoor
- persistence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: OpenJDK 21.0.11（原文环境；原文称 JDK 工具链到 21 未提供 jmod 内置完整性保护）
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:33:37+08:00'
  notes: 已对照原文与12张图核对：图01 jlink流程（jmods→jlink→custom runtime image）；图02 jmod extract；图03-05 BackdoorHook与--patch-module编译及class复制；图06 ASM下载；图07-09 PatchSocket与javap确认connect入口aload_1/toString/iload_2/invokestatic，20116→20182字节；图10 custom-jre版本21.0.11与正常一致；图11 TestAuto正常连接；图12 /tmp/.jvm_diag.log记录example.com:80与github.com:443及timeout。卡内原理、PoC、容器多阶段变体、检测/防御与原文一致；affected_versions按原文环境与'到21版本为止'表述保留，未外推。PoC未在本机执行。frontmatter 无 sources/source_url。
---

## 一句话结论

`jlink` 不校验输入 jmod 的签名或哈希，且 `java.base` 作为根模块不受任何上游哈希约束；攻击者只要能替换构建环境的 `java.base.jmod`，用 ASM 修改 `java.net.Socket` 等核心类并重新打包，就能让 jlink 生成的 JRE 自带 JVM 级后门，产物版本、目录结构和模块描述符与正常 JRE 完全一致。

## 原理

- jmod 格式本质是带 4 字节 `JM` 魔数和 ZIP 结构的归档，格式本身没有签名字段；jlink 只做格式检查，不验证来源或完整性，默认信任 `$JAVA_HOME/jmods/` 或 `--module-path` 指定的文件。
- JPMS 允许模块描述符记录依赖模块的哈希，但 `java.base` 是根模块，不被任何模块依赖链约束，没有上游模块来校验它。
- 攻击者在 `java.base.jmod` 的 `classes/java/net/` 中新增一个与 `Socket` 同包的类（如 `BackdoorHook`），再用 ASM 在 `Socket.connect(SocketAddress, int)` 方法入口插入 `ALOAD 1 → toString → ILOAD 2 → INVOKESTATIC BackdoorHook.logConnection`，即可在所有出站连接建立前执行恶意逻辑，且不改变原方法的参数校验与连接流程。
- 重新执行 `jmod create` 打包，再用 `jlink --module-path` 生成运行时镜像。jlink 把类打包进 `lib/modules`（JIMAGE 私有格式），最终镜像不包含 JDK 工具、源码或 jmod，常规文件扫描很难发现。
- 隐蔽性来源：
  - `java --version`、目录结构、时间戳与正常 jlink 产物一致；
  - `BackdoorHook` 放在已有 `java.net` 包内，模块的 `exports/requires/provides` 数量不变；
  - 代码在 `java.base` 内运行，拥有 JVM 级权限；
  - 不经过 `java.lang.instrument`，RASP 的 Instrumentation 监控看不到；
  - 调用栈是 `Socket.connect → BackdoorHook`，整条链路都在 JDK 内部。
- 该攻击不修改应用源码，而是污染构建输入（JDK/jmod/基础镜像），后门随所有使用该运行时镜像的应用扩散。

## 触发条件

- 攻击者能写入构建环境的 `$JAVA_HOME/jmods/java.base.jmod`，或能通过 `--module-path` 提供被篡改的 jmod（CI/CD 提权、基础镜像投毒、开发机持久化）。
- 目标使用 `jlink` 生成定制运行时镜像，且未在构建前校验 jmod 哈希或镜像来源。
- 运行时镜像被部署并执行正常的 Java 应用；后门在 `Socket.connect` 等被注入方法被调用时触发。
- 实验环境：Kali Linux 2026.1、OpenJDK 21.0.11、ASM 9.7.1。

## 利用步骤

1. 提取目标 JDK 的 `java.base.jmod`：`jmod extract java.base.jmod`，得到 `classes/` 等目录。
2. 在 `classes/java/net/` 中新增与 `Socket` 同包的恶意类（演示用写连接日志；实际可换成反弹 Shell、凭据外传、内存马加载器）。
3. 用 `javac --patch-module java.base=src/java.base` 编译恶意类，把 `.class` 放进提取出的 `classes/java/net/`。
4. 用 ASM `ClassVisitor/MethodVisitor` 修改 `Socket.class` 的 `connect(Ljava/net/SocketAddress;I)V`，在 `visitCode()` 中插入对恶意类的静态调用。
5. 用 `jmod create --class-path classes ... java.base.jmod` 重新打包。
6. 把篡改后的 jmod 覆盖到模块库，执行 `jlink --module-path modlib --add-modules ... --output custom-jre`。
7. 部署 `custom-jre`，应用正常运行；后门在连接建立时静默执行。

## PoC

```bash
# 1. 提取并准备
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
mkdir -p /tmp/jlink-lab/patched_base && cd /tmp/jlink-lab/patched_base
cp $JAVA_HOME/jmods/java.base.jmod .
jmod extract java.base.jmod

# 2. 编译同包恶意类
javac --patch-module java.base=src/java.base \
      src/java.base/java/net/BackdoorHook.java -d out/java.base
cp out/java.base/java/net/BackdoorHook.class classes/java/net/

# 3. 用 ASM 在 Socket.connect 入口插入静态调用
#    等价字节码：aload_1; invokevirtual Object.toString; iload_2;
#    invokestatic java/net/BackdoorHook.logConnection(Ljava/lang/String;I)V
java -cp asm.jar:. PatchSocket

# 4. 重新打包并生成运行时镜像
rm java.base.jmod
jmod create --class-path classes --cmds bin --config conf \
    --header-files include --legal-notices legal --libs lib \
    --man-pages man java.base.jmod

mkdir -p /tmp/jlink-lab/modlib
cp $JAVA_HOME/jmods/*.jmod /tmp/jlink-lab/modlib/
cp java.base.jmod /tmp/jlink-lab/modlib/
jlink --module-path /tmp/jlink-lab/modlib \
      --add-modules java.base,java.logging,java.net.http \
      --output /tmp/jlink-lab/custom-jre \
      --no-header-files --no-man-pages --strip-debug
```

验证：`custom-jre/bin/java --version` 与正常 JRE 一致；运行任意使用 `Socket.connect` 的程序后，后门日志出现目标地址、端口和超时。

## 变体与关联

- 注入目标可换成 `java.lang.ProcessBuilder`（劫持进程调用）、`java.lang.ClassLoader.defineClass()`（通用类加载注入）、`javax.crypto` 实现（降级/外传密钥）、`java.security.SecureRandom`（可预测随机数）。
- 容器场景：多阶段 Dockerfile 中构建阶段执行 `jlink --module-path $JAVA_HOME/jmods`，攻击者只需污染构建镜像的 jmod 或推送同 tag 篡改镜像，运行阶段只复制 `runtime`，后门已进入 `lib/modules`。
- 关联：[[cloud-cicd-java-annotation-processor-filer-backdoor-injection]]（编译期注入后门类）、[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（依赖安装期投毒）同属构建链污染。
- 关联：[[defense-hardening-jar-signature-repackage-verification]] 讨论 JAR 签名校验边界；jmod/jlink 没有等价的签名强制。
- 边界：需要写构建环境或替换基础镜像；若构建前强制校验 jmod 哈希、使用镜像摘要和可重现构建，该链被阻断。

## 检测与防御

- **检测（构建输入）**：对 `$JAVA_HOME/jmods/*.jmod` 建立 SHA-256 基线，在 `jlink` 前强制比对；用 `jmod list` 对比 `java/net/` 类数量（如正常 147 个，篡改后 148 个）和 `Socket.class` 字节码。
- **检测（构建产物）**：用 `jimage list custom-jre/lib/modules` 与干净构建基线 diff；对 `lib/modules` 做整体哈希/签名校验。
- **检测（运行时）**：Java Agent 在类加载时校验 `java/net/Socket`、`ProcessBuilder`、`Runtime`、`ClassLoader` 的字节码哈希；监控 JVM 进程对非预期路径的写入和对外连接。
- **防御**：Dockerfile 使用镜像 SHA-256 摘要而非 tag；构建前运行 jmod 哈希校验脚本，失败即中止；每次构建使用全新容器，避免持久化植入；用 Sigstore/cosign 对 jlink 产物签名并在部署前验签。
- **加固**：限制 CI/CD 构建节点的写权限与网络；对 JDK 发行版使用官方校验和；将 `jlink` 产物纳入供应链安全审计，不把 `$JAVA_HOME/jmods/` 和定制 JRE 当作天然可信组件。
