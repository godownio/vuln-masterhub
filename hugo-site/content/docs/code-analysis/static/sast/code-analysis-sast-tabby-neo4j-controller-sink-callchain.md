---
id: code-analysis-sast-tabby-neo4j-controller-sink-callchain
title: tabby + Neo4j 从 Controller 入口批量查询危险 sink 调用链
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: tabby-neo4j-callgraph-sink-query
tags:
- tabby
- neo4j
- cypher
- callgraph
- sast
- java
- code-audit
- vulnerability-discovery
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V56
  verified_at: '2026-11-05T09:00:50+08:00'
  notes: 已对照原文核对：tabby 导 Neo4j、按 Controller/RequestMapping/doGet/doPost 选入口、按 vul_list/vul_class 选 sink、apoc.algo.allSimplePaths 查询、排除 java.* 中间节点、Python 拼接去重写 xlsx，均与正文及图片 16 一致。小问题：原文未说明按链长度/sink 类型/命名空间排序，卡片该句属补充；原理段关系串 CALLS>|ALIAS> 与原文 ALIAS>|CALL> 不一致，PoC 段用的是原文写法。不影响核心方法，保留。
url: /docs/code-analysis/static/sast/code-analysis-sast-tabby-neo4j-controller-sink-callchain/
draft: false
kb_aliases:
- tabby 调用链查询
- Neo4j 代码审计
- Cypher 危险函数调用链
- 自动化漏洞挖掘
- allSimplePaths 审计
---

## 一句话结论

用 tabby 把目标 jar 解析成类/方法/别名/调用关系图并导入 Neo4j 后，可以从 `@RequestMapping`/`doGet`/`doPost`/`service` 等外部入口出发，用 `apoc.algo.allSimplePaths` 查询到 `Runtime.exec`、`defineClass`、`FileInputStream` 等危险 sink 的调用链，把人工翻代码变成可排序、可导出的候选漏洞列表。

## 原理

- tabby 对 Java 字节码做静态分析，产出 Class/Method/CALL/ALIAS 等节点与关系；导入 Neo4j 后可用 Cypher 做图查询。
- 外部可达入口可以按注解或方法名枚举：`@RequestMapping`/`@PostMapping`/`@GetMapping`、`@WebServlet`、`@Path`、`service`、`doGet`、`doPost`、类名含 `Controller` 等。
- 危险 sink 按方法名或所属类枚举：`exec`/`getRuntime`/`parseExpression`/`eval`/`readObject`/`loadClass`/`defineClass`/`getConnection`/`executeQuery`/`FileInputStream`/`FileOutputStream`/`getInputStream` 等。
- 用 `apoc.algo.allSimplePaths(source, sink, "CALLS>|ALIAS>", depth)` 找出从入口到 sink 的简单路径；再过滤掉 `java.*` 中间节点、`toString`/`equals` 等无意义跳转，避免海量误报。
- 结果按调用链字符串去重后写入 xlsx，按链长度、sink 类型、入口命名空间排序，优先人工核验短链和可控参数链。

## 触发条件

- 目标为 Java Web 应用，具备可解析的 jar/war/class 文件。
- 本机可运行 tabby，并有 Neo4j（含 APOC 插件）用于导入和查询。
- 已整理入口注解/方法名清单与 sink 方法名/类名清单。
- 仅做静态候选挖掘；最终可利用性仍需结合参数污点、过滤与运行时验证。

## 利用步骤

1. 用 tabby 分析目标 jar，生成图数据并导入 Neo4j。
2. 给 `java.*` 等系统类打标签，便于后续排除：
   ```cypher
   MATCH (m:Method) WHERE m.CLASSNAME STARTS WITH 'java.'
   SET m:JavaSystemClass
   ```
3. 选定入口：按 `CLASSNAME` 前缀（如 `weaver.monitor.controller`）和 `NAME in ['doGet','doPost','service']` 过滤。
4. 选定 sink：`sink.NAME in {vul_list}` 或 `sink.NAME0 in {vul_class}`（构造器 sink 需加 `#<init>`）。
5. 查询调用链并排除系统类中间节点：
   ```cypher
   MATCH (source:Method)
   WHERE source.CLASSNAME STARTS WITH 'com.example.controller'
     AND source.NAME IN ['doGet','doPost','service']
   MATCH (sink:Method)<-[:CALL]-(m1:Method)
   WHERE sink.NAME IN ['exec','readObject','parseExpression','defineClass','getConnection']
   CALL apoc.algo.allSimplePaths(source, m1, "ALIAS>|CALL>", 6) YIELD path
   WHERE NONE(n IN nodes(path)[1..] WHERE n:JavaSystemClass)
   RETURN path
   LIMIT 5000
   ```
6. 用 Python 遍历返回的 path，拼成 `方法(类) -> 方法(类)` 字符串，去重后写入 xlsx；按链长度和 sink 排序。
7. 人工核对最短链：检查入口参数是否可控、路径上是否有校验/白名单，再构造 PoC。

## PoC

入口/sink 清单与查询骨架：

```cypher
// 入口：Controller 类中的请求处理方法
MATCH (source:Method)
WHERE source.CLASSNAME CONTAINS 'Controller'
  AND source.NAME IN ['doGet','doPost','service','execute']
// sink：危险方法或危险类的构造器
MATCH (sink:Method)<-[:CALL]-(m1:Method)
WHERE sink.NAME IN ['exec','getRuntime','parseExpression','eval','readObject',
                    'loadClass','defineClass','getConnection','executeQuery',
                    'FileInputStream','FileOutputStream','getInputStream']
CALL apoc.algo.allSimplePaths(source, m1, "ALIAS>|CALL>", 6) YIELD path
WHERE NONE(n IN nodes(path)[1..] WHERE n:JavaSystemClass)
RETURN path
LIMIT 5000
```

Python 侧对 `path.nodes`/`path.relationships` 逐段拼接调用链并写 xlsx；原文脚本还包含按 `RequestMapping` 注解和自定义 `LoginStatusChecker` 过滤入口的变体。

## 变体与关联

- 变体：按注解而非类名选入口（`source_c.ANNOTATIONS CONTAINS "RequestMapping"`），可覆盖命名不规范的 Controller。
- 变体：给业务包打 `weaverClass` 等标签，要求路径中间节点都来自业务包，减少框架内部调用噪声。
- 变体：按 sink 类型分组查询（文件读写、命令执行、反序列化、SQL、表达式），分别导出报告。
- 关联：CodeQL 自定义 source/sink 查询、污点分析；动态插桩验证候选链。

## 检测与防御

- 对攻击者：该方法是静态候选挖掘，结果需人工确认参数可控性与过滤条件，不能把“存在调用链”直接当作漏洞。
- 对防御方：在 CI 中集成同类调用图/SAST 扫描，重点关注外部入口到危险 sink 的短链；对反射、类加载、表达式求值、反序列化等 sink 做集中治理。
- 检测：代码评审中检查 Controller 到 `Runtime.exec`、`defineClass`、`readObject` 等 sink 的可达路径；对外部输入做白名单与类型约束。
