---
id: defense-hardening-fastjson-autotype-three-layer-jndi-trustcodebase-whitelist
title: Fastjson 不能升级时的三层加固：关 JDK 远程 Codebase 与 trustSerialData、关 autoType 并开 SafeMode、必须用 @type 时改走 addAccept 白名单
type: scenario
domain: defense
path: defense/hardening
technique: fastjson-autotype-jndi-trustcodebase-whitelist-hardening
aliases:
- fastjson 加固
- autoTypeSupport 关闭
- SafeMode 开启
- addAccept 白名单
- fastjson.parser.autoTypeAccept
- trustURLCodebase false
- trustSerialData false
tags:
- java
- fastjson
- autotype
- jndi
- hardening
- whitelist
- safe-mode
- jvm-args
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:36:38+08:00'
  notes: 已对照原文核对；本次核对未读取图片；三层加固（trustURLCodebase/trustSerialData 启动参数、setAutoTypeSupport(false)、addAccept/autoTypeAccept 白名单）与正文 4.1-4.3 一致；「spring.application.jvm.args 写在 application.yml 不会生效」为本卡基于 JVM 启动时序的补充判断，非原文断言，已在卡片与提卡 notes 中声明；攻击侧各版本绕过（1.2.24/1.2.25-1.2.41/1.2.42-1.2.47/<=1.2.62/<=1.2.66）按重复未出卡，原文未给加固卡的受影响版本区间，故未 set-versions
---

## 一句话结论

Fastjson 反序列化链的落点几乎都要经过 JNDI 的远程加载或反序列化，所以在"不能升级 fastjson/JDK"的场景下，加固要按三层同时做：第一层在 JVM 启动参数上关掉 `com.sun.jndi.ldap.object.trustURLCodebase`、`com.sun.jndi.rmi.object.trustURLCodebase` 与 `com.sun.jndi.ldap.object.trustSerialData`，把远程 Codebase 与 LDAP 反序列化两条通路掐死；第二层用 `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`（高版本另有 SafeMode）让 `@type` 直接失效；第三层只对确有 `@type` 需求的业务，改走 `addAccept(...)` 包/类白名单或 `-Dfastjson.parser.autoTypeAccept=...` 启动参数，把可实例化的类收敛到一个极小集合。三层缺一层都还剩利用面——尤其"只加白名单不关 autoType、或只在代码里 `setProperty`"这类半吊子加固。

## 原理

- **为什么第一层是 JNDI**：`JdbcRowSetImpl`（`dataSourceName` + `autoCommit`）、各类第三方 `JndiConverter`/`JndiObjectFactory`/`JndiDataSourceFactory` 的终点都是 `InitialContext.lookup`。lookup 之后能做什么，取决于 JDK 允不允许①远程 Codebase 加载类、②对 LDAP 返回的序列化数据做反序列化。把这两件事关掉，即便 `@type` 通关，也拿不到代码执行。
- **JDK 版本差异**：8u191 起默认禁用 LDAP/RMI 远程 Codebase（`trustURLCodebase` 默认 false），但"本地工厂 + 本地 gadget"（BeanFactory、c3p0、H2 INIT 等）仍可用，所以仍要显式设置；`com.sun.jndi.ldap.object.trustSerialData` 默认允许，用于关闭 LDAP 侧序列化数据的反序列化，这是"远程 Codebase 已禁用后"的主要残余面。
- **为什么必须用启动参数而非代码**：`System.setProperty` 只有在相关 JNDI 代码执行前生效才有意义。应用中若存在"类加载前就发生 lookup"（静态初始化、容器启动期装配）或攻击者能影响类加载顺序，代码方式会被绕过；启动参数在 JVM 启动即生效，且不受业务代码部署形态影响。
- **第二层的作用面**：`setAutoTypeSupport(false)` 让 `checkAutoType` 对未登记的 `@type` 直接抛异常，`@type` 指定类不再被实例化，setter 不会被调用，链断在第一步。高版本的 SafeMode 语义更强（完全禁止 autoType 与部分反序列化特性），但会让依赖 `@type` 的业务直接失败，这是它的代价。
- **第三层的必要性**：若业务确实用 `@type`，白名单是唯一可行的收敛方式。`addAccept("com.example.model.")` 是**前缀**匹配（末尾点表示整包），`addAccept("com.example.another.SpecificClass")` 才是单类；`-Dfastjson.parser.autoTypeAccept=<包前缀或类名,逗号分隔>` 与之等价但走启动参数，能避免"代码没执行到"的问题。
- **半吊子加固为什么等于没加固**：只 `setAutoTypeSupport(true)` + `addAccept` 而不关 JNDI → 白名单外的类仍可能通过 `java.lang.Class` 缓存/描述符绕过（1.2.25–1.2.47 的 `L...;`、`[`、`java.lang.Class` 三套手法）；只在代码里设 `trustURLCodebase` 而不设启动参数 → 时序上可能晚于首次 lookup；把 JVM 参数写进 `application.yml` 的 `spring.application.jvm.args` → **JVM 启动时还没读到这份配置，参数不会生效**，必须走 `JAVA_OPTS`/容器启动命令/`setenv.sh` 之类真正的启动入口。
- **为什么这三层是互补而非重复**：①断掉"加载什么"（JNDI 远程能力）、②断掉"能不能指定类"（autoType）、③断掉"能指定哪些类"（白名单）。任意一层单独存在都能被针对：只有①时本地工厂链仍可用；只有②时管理员手工开 autoType 就复原；只有③时白名单前缀写宽（如 `com.`、`java.`）等于裸奔。

## 触发条件

- 目标使用 Fastjson（1.2.x 全系，或 fastjson2 的兼容模式），且存在把用户输入交给 `JSON.parse`/`parseObject` 的入口。
- 业务因兼容性无法升级 fastjson 到已默认关闭 autoType 的安全版本、无法升级 JDK 到 8u191+（或虽升级但仍有本地 gadget 风险）。
- 具备修改 JVM 启动参数与发布流程的权限（否则第一层、第三层的启动参数无从落地）。
- 存在需要保留 `@type` 的合法业务（否则直接第二层即可，不需要白名单）。

## 利用步骤

1. **盘点入口**：找出所有把外部输入交给 `JSON.parse`/`parseObject`/`parseArray` 的位置，确认是否显式传了目标类型（传了具体类时 `@type` 影响力较小，传 `Object`/`Map`/`JSONObject` 时风险最高）。
2. **第一层（启动参数）**：在真实启动入口（`JAVA_OPTS`、Dockerfile `ENTRYPOINT`、Tomcat `setenv.sh`、systemd `Environment=`）追加：
   `-Dcom.sun.jndi.ldap.object.trustURLCodebase=false -Dcom.sun.jndi.rmi.object.trustURLCodebase=false -Dcom.sun.jndi.ldap.object.trustSerialData=false`。
3. **第二层（关 autoType）**：在应用初始化最早处（如 `@PostConstruct`、`ServletContextListener`、`main` 第一行）执行 `ParserConfig.getGlobalInstance().setAutoTypeSupport(false)`；高版本同时开启 SafeMode（`ParserConfig.getGlobalInstance().setSafeMode(true)`）。
4. **第三层（白名单）**：确需 `@type` 的业务，改为 `setAutoTypeSupport(true)` 后 `addAccept("<精确包前缀>.", ...)` 与 `addAccept("<精确类全名>")` 组合；或改用 `-Dfastjson.parser.autoTypeAccept=<包前缀,类名>`，避免代码路径未执行。
5. **验证不得回退**：构造 `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/x","autoCommit":true}` 与 `{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;",...}`，确认均抛异常且无外连；再用业务真实报文确认白名单内类仍正常反序列化。
6. **复核配置来源**：确认没有另一处代码/配置文件把 `setAutoTypeSupport(true)` 或宽前缀白名单加回来（含第三方 starter、低代码平台、`@type` 相关的兼容开关）。

## PoC

```text
# 第一层：真实启动入口追加（示例为容器/JVM 参数）
JAVA_OPTS="-Dcom.sun.jndi.ldap.object.trustURLCodebase=false \
           -Dcom.sun.jndi.rmi.object.trustURLCodebase=false \
           -Dcom.sun.jndi.ldap.object.trustSerialData=false"
```

```java
// 第二层：全局关 autoType（越早越好）；高版本再开 SafeMode
@Configuration
public class FastjsonSecurityConfig {
    @PostConstruct
    public void init() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(false);
        // 高版本：ParserConfig.getGlobalInstance().setSafeMode(true);
    }
}
```

```java
// 第三层：确需 @type 时的最小白名单（前缀 + 单类）
@Configuration
public class FastjsonWhitelistConfig {
    @PostConstruct
    public void init() {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
        ParserConfig.getGlobalInstance().addAccept("com.example.model.");        // 整包
        ParserConfig.getGlobalInstance().addAccept("com.example.dto.OrderView"); // 单类
    }
}
```

```text
# 第三层替代写法（启动参数，避免代码未执行）
-Dfastjson.parser.autoTypeAccept=com.example.model.,com.example.dto.OrderView
```

```text
# 加固后的回归判据
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/x","autoCommit":true}
  -> 应抛 autoType is not support / 未在白名单，且 LDAP 服务无连接
{"@type":"Lcom.sun.rowset.JdbcRowSetImpl;","dataSourceName":"..."}
  -> 同上（描述符绕过也应被拒）
白名单内类 -> 正常反序列化（业务不回归）
```

## 变体与关联

- 关联：[[web-java-deser-fastjson-thirdparty-jndi-factory-blacklist-gap]]（给出"黑名单覆盖不到的第三方 JNDI 工厂"这一攻击面，本卡是对应的收敛方案）、[[web-java-deser-fastjson-autotype-descriptor-bypass-evolution]]（`L...;`/`[` 描述符绕过，说明为何白名单必须是精确前缀）、[[web-java-deser-fastjson-1247-class-cache-bypass]]（`java.lang.Class` 缓存绕过，说明"只关 autoType 不关 JNDI 不够"）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（`trustURLCodebase` 的版本分界与远程 Codebase 利用）、[[defense-hardening-java-rasp-sink-hookpoints-limits]]（运行期 hook 兜底与其绕过面，可与本卡的配置层叠加）。
- 变体：Spring Boot 可在启动类里用 `SpringApplicationBuilder.properties()` 或 `System.setProperty` 于 `main` 最前置；fastjson2 有独立的 `JSONFactory`/`JSONReader.Feature` 与 autoType 过滤接口（`ObjectReaderProvider.addAutoTypeFilter`），思路相同但 API 不同；网关/WAF 侧可再加"JSON 体含 `@type` 即拦截"的规则作为补丁（会误伤合法用法，只做兜底）。
- 边界：白名单只覆盖类名，若白名单内的类本身带危险 setter（如可控 `URL`/`DataSource` 属性）仍可能被二次利用；`trustSerialData=false` 只作用于 LDAP 侧，RMI 侧另有 `com.sun.jndi.rmi.object.trustURLCodebase`；若容器/JDK 版本过低根本不支持某些系统属性，需实测确认生效。

## 检测与防御

- 检测：启动参数中缺失上述三个 `-D` 项；代码里出现 `setAutoTypeSupport(true)`；白名单前缀过宽（`com.`、`org.`、`java.`）；运行期出现 `@type` 指向 `com.sun.rowset`、`org.apache.xbean`、`com.mchange`、`org.apache.shiro.jndi` 等敏感类的请求；JVM 出现向非常规 LDAP/RMI 端口的出连。
- 防御：优先升级 fastjson 到默认关闭 autoType 的版本与 JDK 8u191+；无法升级时按本卡三层同时落地并由发布流程强制校验启动参数；把白名单纳入代码评审（禁止前缀放宽）；对 `JSON.parse` 入口统一封装，强制传具体目标类型；上线前用标准 PoC 做回归，确保加固未被回退。
