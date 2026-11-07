---
id: defense-hardening-jar-signature-repackage-verification
title: JAR 重打包后的签名校验边界与发布前验签
type: scenario
domain: defense
path: defense/hardening
technique: jar-signature-repackage-verification
tags:
- java
- jar
- signing
- supply-chain
- integrity
- jarsigner
- classloader
- hardening
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T21:40:44+08:00'
  notes: 已对照原文与 45 张图片核对：classpath 不触发验签、Class.forName 触发 JarVerifier/ManifestEntryVerifier、覆盖 class 保留旧签名报 SHA-384 digest error、checkCerts 同包拒绝、删除签名块后 certificates=0、重签名后 tampered-v2+certificates=1、构建期/运行期验签脚本均与截图一致；JDK 21.0.11 仅为实验环境，非受影响版本；PoC 未在目标环境执行。
url: /docs/defense/hardening/defense-hardening-jar-signature-repackage-verification/
draft: false
kb_aliases:
- JAR 签名失效
- 重打包验签
- jarsigner 验证
- META-INF 签名剥离
- ClassLoader.checkCerts
---

## 一句话结论

把 JAR 放进 `classpath` 不等于完成验签：JAR 签名只在 `ClassLoader` 读取某个 class 条目并准备定义时校验。重打包后若保留旧签名，覆盖的 class 在被加载时会触发 `digest error`；若追加未签名条目，新包条目可加载但 `certificates=0`，同包条目会被 `ClassLoader.checkCerts` 拒绝；删除签名块会让篡改内容以未签名状态加载；重新签名则只证明“当前内容与当前签名匹配”，不再代表原签名方的背书。

## 原理

- JAR 签名是三层摘要链：
  1. `META-INF/MANIFEST.MF` 记录每个条目的摘要（`SHA-256-Digest`/`SHA-384-Digest`，算法取决于 `jarsigner`/JDK 默认）；
  2. `META-INF/*.SF` 记录 Manifest 或其中条目的摘要；
  3. `META-INF/*.RSA`/`.DSA`/`.EC` 对 `.SF` 内容签名。
- `-cp` 只把 JAR 加入类搜索路径，不会立即校验所有条目。只有 `ClassLoader` 真正读取 class 条目、准备定义 class 时，`JarVerifier`/`ManifestEntryVerifier` 才比对摘要；`Class.forName` 会触发，纯启动不加载业务类不会触发。
- `ProtectionDomain.getCodeSource().getCertificates()` 反映的是“该 class 来自已验证的签名条目”，不是“classpath 中有签名 JAR”。`certificates=0` 表示该 class 未被签名保护。
- 覆盖 class 但保留旧 `META-INF`：class 内容变化，Manifest 中旧摘要不匹配，条目读取时抛 `SecurityException: ... digest error`。
- 追加未签名条目：
  - 新包中的 class 没有 Manifest 摘要、没有签名证书，可以加载，`certificates=0`；
  - 已签名包中的新 class 会触发 `ClassLoader.checkCerts` 的包内 signer 一致性检查，被拒绝（`signer information does not match signer information of other classes in the same package`）。
- 删除 `.SF`/`.RSA`/`.DSA`/`.EC`：JVM 不再把条目当作已签名条目，摘要冲突消失，class 以未签名状态加载，`certificates=0`。
- 删除后重新签名：新摘要与篡改后的内容匹配，`jarsigner` 显示 `jar verified`、运行期 `certificates=1`；但这只说明当前内容与新签名一致，不能证明原签名方仍为当前内容背书。
- `jarsigner` 的 `jar verified` 只覆盖已有签名条目；若同时存在 `unsigned entries` 警告，新增条目仍不受完整性保护。

## 触发条件

- Java 应用从可写目录、插件目录、用户指定路径或运行时拼接的 classpath 加载 JAR。
- 构建/发布链路会重打包、shade、字节码增强、压缩重建或替换 JAR 条目。
- 安全校验只检查 `META-INF/*.RSA` 是否存在、JAR 是否在 classpath、或只看 `jar verified` 而忽略 `unsigned entries`。
- 攻击者能替换/追加 JAR 条目，或能影响构建产物。

## 利用步骤（分析/验签）

1. 列出 JAR 条目，确认 `MANIFEST.MF`、`.SF`、`.RSA` 是否存在；不要仅凭 `.RSA` 存在判断已验签。
2. 运行 `jarsigner -verify -verbose -certs`，同时检查 `jar verified` 与 `unsigned entries`/`digest error`。
3. 对目标 class 用 `Class.forName` 主动加载，读取 `ProtectionDomain.getCodeSource().getCertificates()`，确认 `certificates` 数量。
4. 若怀疑重打包，比较 class 字节码/常量池与 Manifest 摘要，确认条目是否被替换。
5. 按场景判定：
   - 覆盖 class + 旧签名 → 加载时 digest error；
   - 新包未签名条目 → 可加载、`certificates=0`；
   - 同包未签名条目 → `checkCerts` 拒绝；
   - 删除签名块 → 可加载、`certificates=0`；
   - 重新签名 → `certificates=1`，但签名者已变。
6. 发布前用脚本拒绝摘要错误、未签名 JAR 和 `unsigned entries`；运行期对插件/用户 classpath 按实际加载的 class 校验证书与签名者指纹。

## PoC

```bash
# 1) 验签：同时看 jar verified / unsigned entries / digest error
LC_ALL=C jarsigner -verify -verbose -certs build/signed-lib.jar

# 2) 覆盖已签名 class 但保留旧签名
cp build/signed-lib.jar build/signed-lib-tampered.jar
jar --update --file build/signed-lib-tampered.jar \
  -C build/tamper-classes signedpkg/SignedGreeter.class
jarsigner -verify -verbose build/signed-lib-tampered.jar
# -> SecurityException: SHA-384 digest error for signedpkg/SignedGreeter.class

# 3) 只挂 classpath、不加载业务类：不会触发验签
java -cp build/app.jar:build/signed-lib-tampered.jar app.Main --noop

# 4) 删除签名块（.SF/.RSA/.DSA/.EC），保留篡改 class
#    可用 Python zipfile 重写，跳过 META-INF 下这些后缀
jar --list --file build/signed-lib-stripped.jar
java -cp build/app.jar:build/signed-lib-stripped.jar app.Main signedpkg.SignedGreeter
# -> message=tampered-v2, certificates=0
```

```java
// 5) 运行期按实际加载的 class 校验证书
Class<?> type = Class.forName(name);
CodeSource source = type.getProtectionDomain().getCodeSource();
Certificate[] certs = source == null ? null : source.getCertificates();
if (certs == null || certs.length == 0) {
    throw new SecurityException("unsigned class rejected: " + name);
}
```

```bash
# 6) 发布前验签脚本（核心判断）
out="$(mktemp)"
if ! LC_ALL=C jarsigner -verify -verbose -certs "$1" >"$out" 2>&1; then cat "$out"; exit 1; fi
grep -q "jar verified" "$out" || { cat "$out"; echo "reject: not verified"; exit 1; }
grep -q "unsigned entries" "$out" && { cat "$out"; echo "reject: unsigned entries"; exit 1; }
echo "accept: $1"
```

说明：以上为本地复现/验签命令，需按实际 JAR 路径与类名调整；PoC 未在目标环境执行。

## 变体与关联

- 变体：同包未签名 class 被 `checkCerts` 拒绝；新包未签名 class 可加载。攻击者若只能追加条目，会选择新包路径。
- 变体：shade/fat JAR 重打包常同时改变条目内容与 `META-INF`，需重新签名；否则运行期才暴露 digest error。
- 变体：删除签名块后重新签名可让篡改内容通过 `jarsigner`，因此发布链路必须校验证书链/签名者指纹/时间戳，而不只是“有签名且验证通过”。
- 变体：自签名证书与缺少时间戳不影响当前摘要匹配，但会影响信任策略与证书过期后的长期验证。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]（ClassLoader 与类定义机制的另一面）；[[web-java-classloader-tccl-nested-jar-type-loading]]（类加载器选择对类型解析的影响）。
- 关联：[[defense-forensics-ransomware-entry-host-encrypted-last]]（供应链/主机完整性问题的取证思路，非同一场景）。

## 检测与防御

- 检测：发布/构建阶段对最终 JAR 运行 `jarsigner -verify -verbose -certs`，拒绝 `digest error`、`jar is unsigned`、`unsigned entries`；不要只检查 `META-INF/*.RSA` 是否存在。
- 检测：运行期对插件/用户 classpath 的 class 读取 `ProtectionDomain` 证书，拒绝 `certificates=0`；进一步校验签名者证书指纹/证书链/时间戳白名单。
- 检测：监控 JAR 文件在部署目录中被替换、追加条目、`META-INF` 签名文件被删除或重写；对构建产物的哈希做比对。
- 防御：修改 class/资源后必须重新签名；删除签名块只能消除旧摘要冲突，不能保留签名属性，应按未签名处理。
- 防御：不要把“JAR 在 classpath 中”“存在 .RSA 文件”“jarsigner 输出 jar verified”单独当作安全证明；三者都可能与实际保护范围不一致。
- 防御：插件/扩展机制使用签名白名单 + 独立目录权限 + 加载前完整性校验；对用户可写的 classpath 路径做隔离。
