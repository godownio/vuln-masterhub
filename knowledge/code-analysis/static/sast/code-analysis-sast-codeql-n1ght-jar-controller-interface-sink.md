---
id: code-analysis-sast-codeql-n1ght-jar-controller-interface-sink
title: CodeQL_n1ght 从 jar 建库 + 接口分派补边：Controller→Impl→DAO getConnection 查 JDBC 注入
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-n1ght-jar-controller-interface-dispatch-jdbc-sink
aliases:
- codeql_n1ght
- jar 包 CodeQL 建库
- Controller 到 getConnection 调用链
- 接口分派补边
- Java OA 代码审计
- JDBC 注入挖掘
tags:
- codeql
- sast
- java
- jar
- code-audit
- call-chain
- interface-dispatch
- jdbc
- sql-injection
- vulnerability-discovery
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V236
  verified_at: '2026-11-07T09:30:46+08:00'
  notes: 已对照原文及全部 15 张图核对：lib.zip 131 文件/78.1MB、建库命令与环境变量、数据库 1.66GB/221 文件/32 目录、Controller/Impl source 与 getConnection sink、接口分派补边 QL、3 条结果 tableList/columnList/saveTable、CodeJdbcDaoImpl 字符串拼接 executeQuery 均一致。未验证点：未复跑 codeql_n1ght/CodeQL 2.17.0；MCP 与 HTML 报告漏洞仅原文截图，未纳入卡片主张。
---

## 一句话结论

对只有 jar 包、没有源码的 Java OA，可以先用 codeql_n1ght 以 Ant 反编译生成 CodeQL 数据库；QL 中把类名匹配 `.+Controller`/`.+Resource`/`.+Impl`（排除 `.+DaoImpl`）的 Callable 作为 source、把 `getConnection` 作为 sink，并针对“Controller 调用 Service 接口、真正实现和 DAO 调用在 Impl 里”的情况，用 `getDeclaringType().getASupertype()` + 接口同名方法补一条调用边，才能把 Controller→ServiceImpl→DAO `getConnection` 串成链；拿到候选后人工检查 DAO 里的字符串拼接，即可定位 JDBC 注入。

## 原理

- 只有 jar 的审计痛点：OA 通常只交付 jar，没有源码；codeql_n1ght 把 `lib/` 下的多个 jar 打成 `lib.zip`，借助 Ant/CodeQL Java extractor 批量反编译并建库（依赖错误可忽略，建库成功即可）；`-deps none` 跳过依赖反编译、`-deps all` 全依赖；数据库可能很大（示例 1.66GB、221 个文件/32 个目录）。
- CodeQL Java 语义：`Callable` 表示可调用方法，`MethodCall` 表示 `xxx.yyy()` 调用，`getDeclaringType()` 取方法所在类，`getASupertype()` 取父类型，`getAMethod()` 取接口中的同名方法；这些 API 让查询可以描述“接口调用 + 实现类”的间接关系。
- source 选择：常见分层是 `mapper/service/serviceImpl/controller`；Controller 通过注解注入 Service 接口，真正执行在 ServiceImpl。作者用正则 `.+Controller`、`.+Resource`、`.+Impl`（排除 `.+DaoImpl`）覆盖入口；把 Impl 也算 source，是因为某些项目有路由直接调用 Impl 方法，追求不漏报。
- sink 选择：`MethodCall` 的方法名为 `getConnection` 即 JDBC 连接获取点；实际注入通常发生在同一 DAO 类里 `createStatement`/`executeQuery` 前的字符串拼接，`getConnection` 只是定位 DAO 的锚点。
- 朴素查询的缺陷：`source.calls(sink.getCaller())` 只能找到直接调用；Controller 调的是 `IDatabaseService.tableList`（接口方法），而 `getConnection` 在 `CodeJdbcDaoImpl.getAllTables` 里，中间还有 `DatabaseServiceImpl.tableList → codeJdbcDao.getAllTables`，直接调用边会断。
- 接口分派补边：对 sink 的声明类型（CodeJdbcDaoImpl）取父类型（CodeJdbcDao 接口），在接口里找同名方法（getAllTables），再让 source 去 `calls` 这个接口方法；同时用 `source2 → source` 两级 edge 把 Controller→Impl→DAO 串起来。查询返回 3 条结果（`tableList`、`columnList`、`saveTable` → `getConnection`），再人工打开 `CodeJdbcDaoImpl` 确认 `strSql += " AND table_name LIKE '%" + tableName + "%'"` 后 `executeQuery(strSql)`，`tableName` 来自请求参数 `DatabaseQueryPara`，即 JDBC 注入。
- 为什么成立：CodeQL 数据库保留了类/方法/接口/调用关系，接口分派补边弥补了静态调用图在 Java 多态调用上的缺失；把“入口类名 + 危险方法名 + 调用链”作为过滤条件，能在海量 jar 中把人工审计范围缩小到少量候选。

## 触发条件

- 目标为 Java OA/Web 应用，只有 jar/war/class 包，没有可直接构建的源码。
- 本机有 codeql_n1ght 与匹配版本的 CodeQL（原文 2.17.0）；能运行 Ant/Java，磁盘足够容纳大数据库。
- 代码采用 Controller→Service 接口→ServiceImpl→DAO 的分层与依赖注入；存在 `getConnection`/`executeQuery` 等 JDBC 调用。
- 存在路由直接调用 Impl 方法或 DAO 接口实现，需把 Impl 纳入 source 才能不漏报。
- 查询结果仍需人工确认参数可控性与拼接点，CodeQL 只负责缩小范围。

## 利用步骤

1. 把目标的多个 jar 按 `lib/` 目录结构打包成 `lib.zip`（示例中 131 个文件、78.1MB）。
2. 建库：`codeql_n1ght.exe -database jar\lib.zip -goroutine -max-goroutines 4`；按 TUI 选择要反编译的 jar，或用 `-deps none`/`-deps all` 跳过/包含依赖。
3. 若建库时报 JVM 内存错误，调整 `SEMMLE_JAVA_EXTRACTOR_JVM_ARGS`（原文工具按物理内存 1/2 自动设置）；等待 `Successfully created database`，数据库可能到 GB 级。
4. 编写 QL：定义 `DangerousMethod`（方法名 `getConnection`）与 `RestApiCallable`（类名匹配 Controller/Resource/Impl，排除 DaoImpl）；先跑直接调用版，再跑接口分派补边版（见 PoC）。
5. 对查询结果逐条人工跟进：打开 DAO 实现类，检查 `getConnection` 后是否用 `createStatement`/`executeQuery` 执行拼接 SQL，拼接字段是否来自请求参数/过滤器；确认后构造注入 PoC。
6. 可配合作者的 codeql_n1ght MCP 服务把建库/扫描/SARIF/HTML 报告自动化；MCP 的 LLM 生成 QL 可能有语法错误，需要人工修复查询。

## PoC

建库命令：

```powershell
codeql_n1ght.exe -database jar\lib.zip -goroutine -max-goroutines 4
# 或跳过 TUI：
./codeql_n1ght -database your-app.jar -deps none   # 空依赖
./codeql_n1ght -database your-app.jar -deps all    # 全依赖
```

基础查询（直接调用）：

```ql
import java

class DangerousMethod extends MethodCall {
    DangerousMethod() {
        this.getMethod().getName().regexpMatch("getConnection")
    }
}

class RestApiCallable extends Callable {
    RestApiCallable() {
        (this.getDeclaringType().getName().regexpMatch(".+Controller")
         or this.getDeclaringType().getName().regexpMatch(".+Resource")
         or this.getDeclaringType().getName().regexpMatch(".+Impl"))
        and not this.getDeclaringType().getName().regexpMatch(".+DaoImpl")
    }
}

query predicate edge(Method source, Callable sink) {
    source.calls(sink)
}

from DangerousMethod sink, RestApiCallable source
where edge(source, sink.getCaller())
select source, source.getQualifiedName(), sink, sink.getCaller().getQualifiedName()
```

接口分派补边查询（原文用于把 Controller→ServiceImpl→DAO 串起来）：

```ql
import java

class DangerousMethod extends MethodCall {
    DangerousMethod() {
        this.getMethod().getName().regexpMatch("getConnection")
    }
}

class RestApiCallable extends Callable {
    RestApiCallable() {
        (this.getDeclaringType().getName().regexpMatch(".+Controller")
         or this.getDeclaringType().getName().regexpMatch(".+Resource")
         or this.getDeclaringType().getName().regexpMatch(".+Impl"))
        and not this.getDeclaringType().getName().regexpMatch(".+DaoImpl")
    }
}

query predicate edge(Method source, Callable sink) {
    exists(Interface interface, Callable able
        | interface = sink.getDeclaringType().getASupertype()
          and not interface instanceof TypeObject
        | able = interface.getAMethod()
          and able.getName() = sink.getName()
          and source.calls(able))
}

from DangerousMethod sink, RestApiCallable source, RestApiCallable source2
where edge(source, sink.getCaller()) and edge(source2, source)
select source2, source2.getQualifiedName(),
       source, source.getQualifiedName(),
       sink, sink.getCaller().getQualifiedName()
```

查询结果示例（3 条）：`tableList`、`columnList`、`saveTable` 三个 Controller 方法 → `getConnection`。人工跟进到 `CodeJdbcDaoImpl.getAllTables`：

```java
// 简化示意（原文截图）
String strSql = "select table_name,TABLE_COMMENT from information_schema.tables where table_schema='" + dbConfig.getDbSchema() + "'";
if (StringUtils.isNotBlank(tableName)) {
    strSql += " AND table_name LIKE '%" + tableName + "%'";
}
ResultSet rs = stmt.executeQuery(strSql);
```

`tableName` 来自 `DatabaseQueryPara`（请求体），未使用 `PreparedStatement`，形成 JDBC 注入；原文未展示最终注入 PoC（避免风险）。

## 变体与关联

- 变体（sink）：把 `getConnection` 换成 `executeQuery`、`createStatement`、`prepareStatement`、`Runtime.exec`、`readObject`、`FileInputStream` 等，可扩展到 SQL 注入、命令执行、反序列化、任意文件读取。
- 变体（source）：Controller 名匹配可换成 `@RequestMapping`/`@PostMapping` 注解、`@Path`、`service`/`doGet`/`doPost`；也可加入 Struts Action、Servlet。
- 变体（接口分派）：多层接口/抽象类时可递归取父类型；也可用 CodeQL 官方数据流库的 `DataFlow`/`TaintTracking` 替代手写调用链。
- 关联：[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]（Neo4j 调用链查询同一目标）、[[code-analysis-sast-codeql-spring-multipartfile-upload-endpoints]]（CodeQL 枚举上传入口）、[[code-analysis-sast-qlcoder-llm-codeql-query-synthesis]]（LLM 生成 QL）、[[code-analysis-sast-codeql-custom-taint-steps]]（污点传播补模型）。
- 边界：CodeQL 建库失败/依赖缺失会漏类；接口分派查询仍是启发式，可能漏掉反射/动态代理/MyBatis XML 注入；看到 `getConnection` 不等于一定注入，必须人工确认拼接与参数可控。

## 检测与防御

- 对审计者：先用 codeql_n1ght 建库 + 入口/ sink 正则查询缩小范围，再对候选 DAO 做人工字符串拼接审计；把查询结果导出 SARIF/HTML 便于复核；对反射、动态代理、XML Mapper 另做补充查询。
- 对开发者：JDBC 一律使用 `PreparedStatement` 参数化；MyBatis 使用 `#{}` 而非 `${}`；对表名/列名等无法参数化的部分做白名单校验；禁止把请求参数直接拼进 SQL。
- 对防御/检测：CI 中集成 CodeQL/SAST 与自定义查询，阻断 `getConnection` 后拼接 SQL 的提交；对动态拼接 SQL 的代码做代码评审；运行期启用 SQL 审计与 WAF 作为补充。
