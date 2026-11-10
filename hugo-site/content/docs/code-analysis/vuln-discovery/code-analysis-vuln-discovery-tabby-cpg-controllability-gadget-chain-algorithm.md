---
id: code-analysis-vuln-discovery-tabby-cpg-controllability-gadget-chain-algorithm
title: Tabby 论文算法：CPG（ORG+PCG+MAG）与可控性剪枝 + Gadget 链回溯（Action/LocalMap/PP/TC/Expander/Evaluator）
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: tabby-cpg-controllability-gadget-chain-algorithm
tags:
- java
- deserialization
- gadget
- tabby
- cpg
- static-analysis
- controllability
- paper
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V384
  verified_at: '2026-11-09T08:54:13+08:00'
  notes: 已对照原文与图片01-12核对：边语义表(E_Interface/E_Extend/E_Has/E_Call/E_Alias)、Action变量表(this/this.x/init-param-i/final-param-i/return/null)、可控权重表(∞/0/[1,n])、Trigger权重表(0=caller可控,[1,n]=参数可控)、Algorithm1 doMethodAnalysis、Algorithm2 Expander(TC_next=fTraverse(TC,CALL.PP)，∞剪枝，ALIAS→TC不变)、Algorithm3 Evaluator(到source成功/深度上限失败)、sink表(Runtime.exec TC=[1]、Method.invoke TC=[0,1]等)、Fig.6找链示例、实验对比表均与卡片一致；TC 公式与论文 f_Traverse 定义一致。属论文算法/方法论卡，含可复用的权重规则与回溯公式，非纯综述。未在本机跑 Tabby 复现论文实验。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-tabby-cpg-controllability-gadget-chain-algorithm/
draft: false
kb_aliases:
- Tabby 论文
- Tabby 可控性分析
- Action LocalMap Pollution Position
- Trigger Condition
- Expander Evaluator
- ORG PCG MAG
- 代码属性图 gadget 链查找
---

## 一句话结论

Tabby（IEEE DSN 论文）把 Java 源码与依赖统一构建成代码属性图 CPG = ORG + PCG + MAG，用 Action/LocalMap/Pollution Position 的可控性权重剪掉不可控的函数调用边，再以 sink 的 Trigger Condition（TC）为约束、用 Expander/Evaluator 从 sink 反向回溯到 source，自动枚举 Java 反序列化 gadget 链；相比纯 Cypher 用法，理解这套可控性模型能判断为什么某些“图上连通”的链实际不可利用、以及反射/动态代理为何是静态挖链的盲区。

## 原理

- **CPG 结构**：节点为 `Class`/`Method`，边为 `Interface`（类实现接口）、`Extend`（继承）、`Has`（类拥有方法）、`Call`（方法调用）、`Alias`（父类/接口中的同名方法，用于 Java 多态下的虚方法分派）。CPG 由三部分叠加：
  - ORG（Object Relation Graph）：类/方法节点及 has/extends/interface 基础关系；
  - PCG（Precise Call Graph）：由语义提取阶段的 CFG 生成调用图（MCG），再经可控性分析剪枝；
  - MAG（Method Alias Graph）：记录父类/子类、接口/实现之间的同名函数关系。
- **可控性分析（Action / LocalMap / PP）**：
  - `Action` 是 method 节点属性，字典表示变量在执行过程中的指向变化；变量类型包括 `this`、`this.x`、`init-param-i`、`init-param-i.x`、`final-param-i`、`final-param-i.x`、`return`，`null` 表示不可控。
  - `LocalMap` 是变量到权重的映射；权重语义：`∞` 当前变量不可控；`0` 来自 caller 类或类属性；`[1,n]` 来自方法第 n 个参数（可被上游控制）。
  - `Pollution Position (PP)` 是函数调用边属性，数组存储 caller 与传入参数的权重，供链查找使用；Trigger 权重规则：`0` 表示需要 method caller 可控，`[1,n]` 表示需要第 n 个参数可控。
  - 算法 `doMethodAnalysis(CFG)`：遍历 CFG 语句；非 return/调用语句做赋值分析分配权重；遇到可控函数调用则递归分析 callee 的 CFG，用 `calc()` 合并 caller/callee 的 LocalMap、`correct()` 修正；遇 return 保存 result。由此把“参数是否可从入口污染到 sink”编码成权重。
- **Gadget 链查找（TC / traverse / Expander / Evaluator）**：
  - sink method 带 `trigger condition (TC)` 数组，规定触发该 sink 需要哪些参数可控（如 `Runtime.exec` TC=[1] 表示第 1 个参数必须可控；`Method.invoke` TC=[0,1]）。
  - 从 sink 开始反向扩展：对 `CALL` 边，`TC_next = fTraverse(TC, PP) = { PP[x] | x ∈ TC }`；若 `TC_next` 出现 `∞`，说明该跳存在不可控变量，路径失败；对 `ALIAS` 边，`TC_next = TC`（同名方法不改变可控性要求）。
  - `Expander(path,node_end,relationship,TC)` 每次扩展一个节点并返回新 path/TC；`Evaluator(source,path,depth)` 判断是否到达 source（成功）或达到深度上限（失败），用于限制回溯时间。
  - 为什么有效：在 CPG 上直接搜 source→sink 的组合爆炸；先做可控性剪枝去掉无效边、再以 TC 约束反向回溯，可把搜索限制在“参数确实可控”的路径上，并支持源码+依赖 jar 一起分析。
- **论文实验**：对 Apache Dubbo 等组件挖出 80+ 链、7 个 CVE；与 GadgetInspector、Serianalyzer 对比，Tabby 在误报率/漏报率与耗时上有优势（具体数字见论文表格）。局限：静态分析难以覆盖反射、动态代理、运行时生成类，`ALIAS` 边也可能产生“图上连通但源码不可控”的假路径，结果必须回源码验证。

## 触发条件

- 审计/研究场景：已用 Tabby 对目标应用及其依赖构建 CPG 并导入 Neo4j。
- 已知或自定义 sink 列表及 TC（论文列出 FILE/CODE/JNDI/EXEC/XXE/SSRF/JDV 等 sink 及触发参数）。
- 目标 classpath 完整（缺 jar 会漏边）；分析结果需人工复核可达性与参数污染。
- 本卡描述的是分析方法，不直接产生危害。

## 利用步骤（分析流程）

1. 构建 CPG：用 Tabby 提取目标源码与依赖 jar 的类、方法、CFG，生成 ORG，再经可控性分析得到 PCG，叠加 MAG 形成 CPG 并写入 Neo4j。
2. 选定 sink：按 `IS_SINK` 或危险方法名（`Runtime.exec`、`Method.invoke`、`Context.lookup`、`DocumentBuilder.parse` 等）确定终点，并写明其 TC。
3. 反向回溯：从 sink 用 Expander 沿 `CALL`/`ALIAS` 边扩展，按 `TC_next = {PP[x] | x ∈ TC}` 传播可控性要求，遇到 `∞` 剪枝；用 Evaluator 控制深度并在到达 source 时输出链。
4. 人工复核：检查每一跳参数是否真能由反序列化入口控制，剔除 `ALIAS` 造成的假路径；对反射/动态代理路径补动态验证。
5. 构造并验证序列化 payload；记录链与触发条件。
6. 防御侧可反向使用：枚举自己 classpath 中 `readObject`/`hashCode` 等到危险 sink 的可控路径，优先移除 sink 或不必要依赖。

## PoC

无直接可执行 PoC（论文/算法分析）。核心公式与伪代码：

```text
TC_next = { PP[x] | x ∈ TC }        # CALL 边：按 PP 截取可控性要求
if ∞ ∈ TC_next: path fails          # 出现不可控变量，剪枝
if ALIAS: TC_next = TC              # 同名方法不改变要求
Evaluator: node_end == source -> chain; depth(path) >= limit -> false
```

```text
sink: java.lang.Runtime.exec(String)  TC = [1]
  <- CALL PP = [∞, 1]  => TC_next = [1]     (第 1 个参数可控，继续)
  <- CALL PP = [∞, ∞]  => TC_next = [∞]     (不可控，剪枝)
```

## 变体与关联

- 变体（工具用法）：[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]] 讲的是 CPG 建好后如何用 Cypher/`findJavaGadget` 查询；本卡讲 CPG 与可控性/回溯算法的设计，二者互补。
- 变体（其他静态分析）：CodeQL 污点传播、Joern CPG、Soot 数据流分析都能做 source→sink 搜索；Tabby 的特点是把结果存 Neo4j 以便复用与探索。
- 变体（动态补充）：对反射、动态代理、JNI、运行时生成类，静态图覆盖不到，需用动态调试/字节码插桩确认。
- 边界：权重模型是近似的，`ALIAS` 与虚方法分派可能引入假阳性/假阴性；缺依赖、混淆、反射会降低召回。

## 检测与防御

- 防御：对自己维护的 Java 应用/依赖建 CPG，枚举 `readObject`/`hashCode`/`equals`/`toString` 等入口到危险 sink 的可控路径，优先移除 `TemplatesImpl`、`Runtime.exec`、JNDI `lookup` 等不必要 sink 与 Commons Collections 等依赖。
- 防御：对外关闭原生反序列化入口，启用 JEP 290 `ObjectInputFilter` 类白名单；对必要入口做签名/来源校验；升级依赖与 JDK。
- 注意：图查询/算法输出只是候选链，必须逐条源码审计与实机验证；不要用“工具命中”直接当作可利用结论。
