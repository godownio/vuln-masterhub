---
id: code-analysis-source-audit-ai-sast-java-gadget-chain-mining
title: AI+SAST 挖掘 Java gadget 链：JavaParser 符号解析 + CHA 数据流 + Neo4j 图谱 + AI 筛选
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: ai-sast-java-gadget-chain-mining-neo4j
tags:
- java
- saas
- code-audit
- gadget
- call-graph
- taint-analysis
- neo4j
- llm
- xstream
- source-sink
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V105
  verified_at: '2026-11-05T23:03:20+08:00'
  notes: 已对照原文与图01-04核对JavaParser Symbol Solver、CHA/override控制、粗粒度污点、Neo4j Cypher、500→29条骨架、AI选中5-hop链；原文工具代码未完整公开、LLM筛选偏定性，卡片confidence=medium合理，未复跑流水线。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-ai-sast-java-gadget-chain-mining/
draft: false
kb_aliases:
- AI 代码审计
- Java gadget 链挖掘
- JavaParser Symbol Solver
- CHA 调用图
- Neo4j 调用链查询
- XStream gadget 挖掘
- source-sink 链路筛选
- LLM 辅助漏洞挖掘
---

## 一句话结论

把 Java 源码/jar 用 JavaParser 做符号解析、用 CHA 构建覆盖 override 的调用图、做粗粒度污点分析与 source→sink 路径枚举、导入 Neo4j 打标签并用 Cypher 查链，最后让 LLM 对候选链做可行性筛选，可以在大量 Java 组件中半自动化地挖出可用 gadget 链；原文用该流程从约 500 条路径收敛到 29 条骨架，并据此发现 TeamCity 的 `Map.get → HashAdapter.get → BeansWrapper.invokeMethod → Method.invoke` RCE 链。

## 原理

- **符号解析是前提**：Java 源码里 `import com.foo.*; import com.xxx.*;` 后使用 `Test`，仅靠文本无法确定类来源。JavaParser 的 Symbol Solver 会按 classpath/sourcepath 优先级解析符号；为了让它构建完整的 JVM 类型系统，最好下载目标全部 jar（而不是只给源码目录），否则大量符号会解析失败。
- **CHA 调用图与路径爆炸控制**：Java 以 Class Hierarchy Analysis（CHA）处理多态：`Test test` 的任意子类都可能被调用。为控制路径爆炸，原文只覆盖“被 override 的方法/子类”，不展开所有可能子类；对 `invoke`、`call` 这类无法直接串联的反射/动态调用，用“夹逼”思路（从两端已知的 source/sink 往中间补）连接。
- **粗粒度污点分析**：不追求精确的字段级污点传播，只做 source→sink 的粗跟踪；重点保留中间链的特定函数白名单与黑名单过滤，减少噪声。原文的思路是“粗略数据流交给机器，语义判断交给 AI”。
- **Neo4j 图谱化**：把方法/类/调用边导入 Neo4j，给节点打 tag（如 XStream 相关、JDBC 相关、反射相关），用 Cypher 按 source 名称、sink 限定名、调用深度查询路径。图上可以直观看到 `getConnection → createDataSource → createPoolableConnectionFactory → validateConnectionFactory → makeObject → initializeConnection → execute` 这类链。
- **LLM 筛选**：把候选链交给 AI 分析可达性、类型约束、参数可控性；由于候选链调用的类/函数高度重叠，AI 可以快速去重并指出哪条链最可能成立。原文最终从 29 条骨架中选出 `Map#get → HashAdapter#get → BeanModel#get → BeansWrapper#invokeMethod → Method#invoke`，以及 getter 链 `BasicDataSource.getConnection() → ... → Statement.execute(sql)`。
- **为什么有效**：gadget 挖掘本质是“从可控入口方法（source）到危险 sink 的可达性 + 类型/参数约束”问题；图数据库擅长路径枚举，LLM 擅长语义筛选，二者结合可以显著降低人工翻调用链的成本，但最终仍需人工写 harness 验证。
- **局限**：CHA 仍可能漏掉动态代理、反射、SPI、运行时生成的类；污点分析精度有限；LLM 可能误判可达性；原文也强调 AI 目前无法完全自主完成复杂漏洞发现，需要人工不断修正 harness 和约束。

## 触发条件

- 有目标 Java 应用的源码或可下载的 jar，且能构建完整 classpath（Maven/Gradle 依赖、容器镜像内的 jar）。
- 目标存在可枚举的 source（如 XStream 反序列化入口、HTTP 参数入口）与 sink（`Method.invoke`、`Statement.execute`、`Runtime.exec`、JNDI `lookup`、文件写入等）。
- 有 JavaParser（含 Symbol Solver）、Neo4j、图构建脚本和可用的 LLM；需要一定的工程化能力，不是开箱即用。
- 目标使用存在 gadget 生态的库（Commons Collections、FreeMarker、DBCP、XStream、Groovy 等），且安全配置（白名单/黑名单）有可绕过的空间。
- 分析者能人工复核候选链并编写 harness/PoC 验证。

## 利用步骤

1. **收集代码与依赖**：拉取目标源码/反编译 jar，整理完整 classpath；用 Maven/Gradle 下载依赖，或从运行环境提取 jar。
2. **符号解析**：用 JavaParser Symbol Solver 解析每个编译单元，解决 import 通配符、继承、泛型带来的符号歧义；对解析失败的类补充 jar/sourcepath。
3. **构建调用图**：按 CHA 生成类层级与方法调用边，覆盖 override 的子类方法；对反射/动态调用单独标注，后续用“夹逼”连接。
4. **定义 source/sink 与污点**：列出攻击者可控入口（反序列化、参数解析、模板输入）和危险 sink（反射调用、SQL 执行、命令执行、JNDI、文件写）；做粗粒度数据流跟踪，保留中间链白名单/黑名单。
5. **导入 Neo4j 并查询**：把方法节点、类节点、CALLS/OVERRIDES 边导入；用 Cypher 查询 source→sink 路径，例如：
   ```cypher
   MATCH p=(g:Method)-[:CALLS*1..8]->(sink:Method)
   WHERE g.name =~ 'get.*'
     AND sink.qualified_name = 'java.sql.Statement#execute(String)'
   RETURN p LIMIT 200
   ```
   以及：
   ```cypher
   MATCH p=(g:Method)-[:CALLS*1..8]->(sink:Method)
   WHERE g.name =~ 'get.*'
     AND sink.qualified_name = 'java.lang.reflect.Method#invoke(Object,)'
   RETURN p LIMIT 200
   ```
6. **筛选与打标**：给节点打 tag（如 XStream gadget、JDBC、反射、集合），按 source→sink、特定函数白名单、黑名单过滤，输出候选骨架（原文约 500 条路径收敛为 29 条）。
7. **AI 分析与人工验证**：把候选链交给 LLM 判断类型兼容性、参数可控性和链完整性；对高置信链写 harness（构造对象、触发 source、观察 sink），确认后迁移到目标 payload。
8. **沉淀规则**：把验证过的链、无效链、过滤条件回写到图/规则库，迭代提高下一轮挖掘的准确率。

## PoC

Neo4j 查询与结果（原文截图）：

```cypher
// 1) 从任意 get* 方法到 SQL 执行 sink 的调用路径
MATCH p=(g:Method)-[:CALLS*1..8]->(sink:Method)
WHERE g.name =~ 'get.*'
  AND sink.qualified_name = 'java.sql.Statement#execute(String)'
RETURN p LIMIT 200
```

命中链示例：`getConnection → createDataSource → createPoolableConnectionFactory → validateConnectionFactory → makeObject → initializeConnection → execute`。

```cypher
// 2) 从 Map#get 到 Method.invoke 的路径（XStream gadget 候选）
MATCH p=(g:Method)-[:CALLS*1..8]->(sink:Method)
WHERE g.name =~ 'get.*'
  AND sink.qualified_name = 'java.lang.reflect.Method#invoke(Object,)'
RETURN p LIMIT 200
```

候选骨架列表（原文 29 条，节选）：

```text
[1] x321  Map#get → HashAdapter#get → BeanMap#put → Method#invoke
[12] x3   Map#get → HashAdapter#get → BeansWrapper#invokeMethod → Method#invoke
...
[29] x1   Map#get → Row#get → InvokerTransformer#transform → Method#invoke
```

AI 选中的 5-hop 链：

```text
START java.util.Map#get(Object)
 [1] CHA/OVERRIDES  freemarker.ext.beans.HashAdapter#get(Object)
 [2] CALLS+CHA      freemarker.ext.beans.BeanModel#get(String)
 [3] CALLS          freemarker.ext.beans.BeanModel#invokeGenericGet(Map,Class,String)
 [4] CALLS          freemarker.ext.beans.BeansWrapper#invokeMethod(Object,Method,Object[])
 [5] CALLS          java.lang.reflect.Method#invoke(Object,)
```

最小 harness 思路：用与目标一致的 XStream 配置反序列化构造对象，触发 `Map.get`，在 `Method.invoke` 处下断点或打印，确认到达 `BasicDataSource.getConnection` 后的 `Statement.execute`。

## 变体与关联

- **source 扩展**：反序列化入口（XStream/Jackson/Hessian）、表达式/模板输入、HTTP 参数、RPC 参数；不同 source 对应的触发方法不同（`readObject`、`hashCode`、`get`、`toString`、`compareTo`）。
- **sink 扩展**：`Method.invoke`、`Statement.execute`、`Runtime.exec`、`ProcessBuilder.start`、JNDI `lookup`、`Files.write`、`ScriptEngine.eval`；按目标 classpath 选择最易触发的 sink。
- **图构建扩展**：用 Soot/ByteBuddy/Tai-e 替代 JavaParser；用 CodeQL/Joern 做更精确的数据流；把动态代理、反射字符串常量纳入图谱。
- **LLM 用法**：让模型做候选链去重、类型兼容性检查、payload 骨架生成；也可让模型根据报错迭代修正 harness；需人工校验，避免幻觉。
- **关联卡片**：[[web-java-deserialization-xstream-teamcity-agent-error-defaultmapbag-rce]]（该流程挖出的完整 TeamCity RCE 链）、[[web-java-deserialization-xstream-type-permission-bypass]]（链所依赖的 XStream 白名单绕过特性）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（用 Tabby 代码属性图 + Cypher 挖链的同类方法论）、[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（用 CodeQL 从 sink 反查的同类方法论）、[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]（Tabby+Neo4j 从 Controller 入口查 sink 调用链）、[[code-analysis-source-audit-jdbc-hql-concat-regex]]（同属源码审计方法论）。

## 检测与防御

- **防御方视角**：这类挖掘难以从流量上直接检测，重点是把攻击面收敛——XStream/Jackson 等反序列化入口使用严格白名单、禁用多态类型、最小化 classpath 中的 gadget 库（Commons Collections、DBCP、HSQLDB、FreeMarker 等）。
- **CI 集成**：在构建流水线加入 CodeQL/Joern/自研 SAST，对 source→sink 链做持续扫描；对新增的反射调用、`Statement.execute`、`Runtime.exec` 做评审。
- **依赖治理**：移除不用的 gadget 依赖，锁定版本；对 CI/TeamCity 等公网暴露服务做认证、网络隔离与补丁跟踪。
- **监控**：对反序列化入口的异常类名/超长 XML、`Method.invoke` 调用链、`Statement.execute` 的异常 SQL、web 目录新增 JSP 文件做告警。
- **AI 安全研究**：该流程同样可被攻击者用于批量找链，防御方应假定攻击者具备 AI 辅助审计能力，按“最小 gadget 面”而非“未知漏洞不可知”来设计。
