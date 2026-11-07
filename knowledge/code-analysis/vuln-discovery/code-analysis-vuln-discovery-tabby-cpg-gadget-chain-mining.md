---
id: code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining
title: 用 Tabby 代码属性图查询挖掘 Java 反序列化 gadget 链
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: tabby-cpg-gadget-chain-mining
aliases:
- tabby 挖链
- tabby Cypher gadget
- findJavaGadget
- 代码属性图挖 gadget
- Java gadget 链挖掘
- Tabby Neo4j 查询
tags:
- java
- deserialization
- gadget
- tabby
- code-property-graph
- cypher
- neo4j
- static-analysis
- vulnerability-discovery
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V17
  verified_at: '2026-11-05T02:00:38+08:00'
  notes: 已对照原文与15张图核对：Tabby 节点/边语义、findJavaGadget/findPathWithState 用法、逐跳收窄与 WITH sink 续接两种查法均与原文图05-10 一致；新链发现段落 transform→toString 查询命中 StringValueTransformer(valueOf→toString，图12-14)，并落到 CSS+LazyMap+JSONArray+TemplatesImpl 完整链(图15)。卡片明确静态图不覆盖反射/代理的局限。方法卡无受影响版本。未在本机复现；无 sources/source_url。
---

## 一句话结论

Tabby 把 Java 字节码转成以 `Class`/`Method`/`Field` 为节点、以 `CALL`/`ALIAS`/`EXTENDS`/`HAS`/`INTERFACE` 为边的代码属性图并存入 Neo4j；用 Cypher 限定 source/sink 节点，再调 `tabby.algo.findJavaGadget` 或逐跳拼接路径，可系统复现已知反序列化链并发现新的“桥接方法”，例如 `StringValueTransformer.transform → String.valueOf → toString` 这类把 `transform` 调用转成任意 `toString` 的节点。

## 原理

- Java 反序列化 gadget 链可抽象为三段：**source**（反序列化入口，如 `readObject(ObjectInputStream)`，或 `hashCode`/`equals`/`toString` 触发点）→ **传播段**（`Map`/`Transformer`/虚方法分派）→ **sink**（`Runtime.exec`、`TemplatesImpl.newTransformer`、JNDI `lookup` 等最终危险调用）。
- Tabby 对目标 classpath 做静态分析，生成代码属性图：
  - `Method` 节点的关键属性：`NAME`、`CLASSNAME`、`SIGNATURE`、`IS_SOURCE`、`IS_SINK`；`Class` 节点还有 `INTERFACES`、`SUPERCLASS`。
  - `CALL` 表示静态调用点；`ALIAS` 表示同一语义对象的不同引用/重写实现（图中用于把 `Object.toString` 等声明类型上的调用连接到 `TiedMapEntry.toString` 等实际实现）；`EXTENDS`/`INTERFACE`/`HAS` 描述继承、接口实现与成员关系。
- 因此“找链”变成图上的有向路径搜索：
  - `tabby.algo.findJavaGadget(source, "OUT", sink, maxNodeLength, isDepthFirst)`：从 source 沿 `CALL`/`ALIAS` 边做深度/广度搜索到 sink，返回 path。
  - `findPathWithState` / `findJavaGadgetWithState`：额外要求 sink 满足状态约束（如参数可控/污点条件）。
  - 也可用 APOC（`apoc.algo.allSimplePaths`、`apoc.path.expand`）或普通 Cypher 变长关系 `[:CALL|ALIAS*1..4]` 自行遍历。
- 为什么有效：gadget 链的每一跳都是“某个方法把可控对象传给另一个方法”；代码属性图把这些调用关系显式化，`ALIAS` 边补上虚方法分派，路径搜索就能跨类、跨 jar 找到人工容易遗漏的长链，尤其是 `transform`、`get`、`toString`、`hashCode` 这类“看起来无害”的桥接方法。
- 局限：静态调用图无法覆盖反射、动态代理、运行时生成类等路径，`ALIAS` 边也可能引入不真实的路径；图查询结果必须回到源码确认参数可控性和状态，不能直接当作可用链。

## 触发条件

- 已用 Tabby 索引目标应用/依赖 jar，并运行 Neo4j；图中存在 `Method`/`Class` 节点与 `CALL`/`ALIAS` 边。
- 已知至少一个反序列化 source（如 `readObject`）和一个 sink 候选；若不知道 sink，可按 `IS_SINK:true` 或危险方法名（`exec`、`newTransformer`、`lookup`、`invoke`）反查。
- 目标 classpath 完整（缺 jar 会漏边）；分析结果需逐节点人工审计。
- 该方法是漏洞研究手段，不直接产生危害；最终仍需构造并验证序列化 payload。

## 利用步骤

1. **定 sink**：按 `IS_SINK:true`、`NAME` 或 `CLASSNAME` 找命令执行/字节码加载/JNDI/文件读写方法，确定链的终点。
2. **定 source**：找带 `ObjectInputStream` 参数的 `readObject`，或用 `hashCode`/`equals`/`toString` 作为触发点；用 `SIGNATURE CONTAINS "java.io.ObjectInputStream"` 精确限定。
3. **一次查询 source→sink**：先直接跑 `findJavaGadget`，观察是否存在路径；`CLASSNAME` 用 `CONTAINS` 可避免写全限定名。
4. **逐跳收窄（可靠但慢）**：从 source 出发查一跳，人工确认中间方法的参数可控后，把该节点类名/方法名固定进下一条查询，重复直到 sink；适合复现已知链。
5. **直接查询 + `WITH sink` 续接（快但有噪声）**：先一次性找到 source→sink，再用 `WITH sink` 把 sink 作为下一段起点，拼上 sink 之后的固定链；适合已知后半段的情况。
6. **发现新桥接**：对高频中间方法（如 `transform`）反查其到 `toString`/`get`/`exec` 的路径，逐个读代码确认参数是否可控；确认后组合成新链并本地序列化验证。

## PoC

```cypher
// 1) 已知入口 readObject 到任意 toString
MATCH (source:Method)
WHERE source.CLASSNAME CONTAINS "BadAttributeValueExpException"
  AND source.NAME = "readObject"
  AND source.SIGNATURE CONTAINS "java.io.ObjectInputStream"
MATCH (sink:Method)
WHERE sink.NAME = "toString"
CALL tabby.algo.findJavaGadget(source, "OUT", sink, 5, true)
YIELD path
RETURN path LIMIT 20;
```

```cypher
// 2) 固定中间节点后逐跳收窄：toString 的实现在 TiedMapEntry
MATCH (source:Method)-[:CALL]->(m1:Method {NAME:"toString"})
WHERE source.CLASSNAME CONTAINS "BadAttributeValueExpException"
  AND source.NAME = "readObject"
  AND source.SIGNATURE CONTAINS "java.io.ObjectInputStream"
MATCH (sink:Method)
WHERE sink.NAME = "toString" AND sink.CLASSNAME CONTAINS "TiedMapEntry"
CALL tabby.algo.findJavaGadget(source, "OUT", sink, 3, true)
YIELD path
RETURN path LIMIT 20;
```

```cypher
// 3) 直接 source→sink，再用 WITH sink 续接固定后半段
MATCH (source:Method)
WHERE source.CLASSNAME = "java.util.Hashtable"
  AND source.NAME = "readObject"
  AND source.SIGNATURE CONTAINS "java.io.ObjectInputStream"
MATCH (sink:Method)
WHERE sink.CLASSNAME CONTAINS "TiedMapEntry" AND sink.NAME = "equals"
CALL tabby.algo.findJavaGadget(source, "OUT", sink, 4, true)
YIELD path
WITH sink
MATCH path1 = (sink)-[:CALL]->(:Method {NAME:"getValue"})
  -[:CALL]->(:Method {NAME:"get"})
  -[:ALIAS*1..2]-(:Method {NAME:"get"})
  -[:CALL]->(:Method {NAME:"transform"})
  -[:ALIAS*]-(:Method)
  -[:CALL]->(:Method {IS_SINK:true})
RETURN path1 LIMIT 20;
```

```cypher
// 4) 找 transform→toString 的新桥接：逐个读返回节点源码确认参数可控
MATCH (source:Method)
WHERE source.NAME = "transform"
MATCH (sink:Method)
WHERE sink.NAME = "toString"
CALL tabby.algo.findJavaGadget(source, "OUT", sink, 5, true)
YIELD path
RETURN path LIMIT 20;
```

```text
上述第 4 条查询可命中 StringValueTransformer.transform → String.valueOf → toString；
确认 transform 的入参可控后，即可把它接到 LazyMap/TiedMapEntry 等已有触发段，形成新链。
```

## 变体与关联

- 变体：用 `findJavaGadgetWithState(source, "OUT", sink, sinkState, max, dfs)` 给 sink 增加“参数可控/污点”约束，减少人工筛选。
- 变体：用 `[:CALL|ALIAS*1..4]` 混合关系遍历，或 APOC 的 `allSimplePaths`/`path.expand` 控制深度和边类型；与 `findJavaGadget` 结果交叉验证可降低误报。
- 变体：同一方法也可换用 CodeQL 自定义污点传播、Joern CPG 等工具；Tabby 的优势是 Neo4j 里可直接写任意 Cypher，适合探索性挖链。
- 关联卡片：[[web-java-deser-stringvaluetransformer-css-jsonarray-templatesimpl]]（由 `transform→toString` 查询发现并落地的完整链）；[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]（`TiedMapEntry`/`LazyMap`/`TemplatesImpl` 经典组合，可作为图查询的复现样本）。
- 边界：反射、代理、JNI、动态生成类不在静态图中；`ALIAS` 可能产生“图上连通、源码不可控”的假路径；缺依赖 jar 会漏掉关键边。

## 检测与防御

- 防御方可反向使用同一方法：对自己 classpath 建图，枚举 `readObject` → `IS_SINK` 的路径，优先移除或隔离可达的危险 sink（`TemplatesImpl`、`Runtime.exec`、JNDI `lookup`），并清理 Commons Collections、Fastjson 等不必要依赖。
- 检测/加固：对外关闭原生 Java 反序列化入口，启用 JEP 290 `ObjectInputFilter` 类白名单；对必须反序列化的入口做签名/来源校验；升级 JDK 限制内部 Xalan 等类。
- 注意：图查询只给出候选路径，不能替代源码审计与实机验证；防御评估时应对命中路径逐条确认可达性。
