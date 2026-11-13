---
id: code-analysis-sast-tabby-1-2-pathfinder-endpoint-sink-pitfalls
title: Tabby 1.2 + tabby-path-finder 实战：IS_ENDPOINT/IS_SINK 检索、findPath 单节点限制与 new/HAS 图语义陷阱
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: tabby-pathfinder-endpoint-sink-query-pitfalls
tags:
- tabby
- neo4j
- cypher
- sast
- java
- code-audit
- callgraph
- tabby-path-finder
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V613
  verified_at: '2026-11-12T19:59:58+08:00'
  notes: '已对照原文《tabby静态分析实践》通读全文并逐张核对 15 张图（img_small 最长边1200 JPEG，15/15 成功，无失败文件）：图01 CALL apoc.help(''all'') 列出 apoc.algo.allSimplePaths 等；图02 CALL tabby.help(''tabby'')（findPath/findPathWithState/beta.*/findJavaGadget 等 procedure）；图03 tabby-path-finder-1.0 的 tabby.help(''all'') 与 plugins 目录（tabby-path-finder-1.0.jar）；图04 tabby v1.2.0 启动（Java 1.8.0_371，57 rules，478 targets，6.9s）；图05 164387 classes 构建进度；图06 原文引用的『使用小 trick』文档（-Dlogging.level.tabby=DEBUG、system.json ignore 规则）；图07 构建完成统计（24734 classes、call 392737、alias 70952、8 分 41 秒并写 Neo4j）；图08 93494/93494 classes 时 OutOfMemoryError: GC overhead limit exceeded；图09 :sysinfo（Node 251651、Property 3740442、Relationship 713788、12 种类型）；图10/15 db.schema.visualization（Class/Method/Movie 标签与 ALIAS/CALL/EXTENDS/HAS/INTERFACE 关系）；图11 某赛通 web 模式扫描 33280 classes；图12 POLLUTED_POSITION 属性查询结果；图13 service<-CALL 方法图（ServletContainer.service 签名）；图14 MaxNodeLength=15 查询白页。核对：Tabby 版本 v1.2.0-2 2023.02.24、tabby-path-finder 1.1、Neo4j 5.12.0、procedures.unrestricted
    配置、索引/约束、web/gadget 模式、debug/ignore 提速、IS_ENDPOINT/IS_SINK/VUL 检索、findPath 单节点限制、new 不算 CALL、HAS 只表示类声明方法、深度 10 秒查/15 白页、254MB 16w classes 跑不完、31MB 2w classes 约 7 分钟等均与原文及截图一致；cve=[] 正确；此为工具方法论卡，无受影响组件版本，未设 affected_versions 正确。修正：原文模板中 collect 列表传参给 findAllVul 与后文『1.2 的 findXxx 只支持单节点』自相矛盾，已在 PoC 该代码块标题注明列表写法在 1.2 不可用、需拆单节点查询。另原文 1b 称下载 1.0（1.1 适配 tabby 2.x）但随后又写成功导入 1.1、页首测试版本为 1.1，属原文自身矛盾，卡片按测试版本 1.1 记录并在环境要点注明 1.0 少一些 procedure。dedup：与 code-analysis-sast-tabby-neo4j-controller-sink-callchain（APOC allSimplePaths 批量导出 xlsx）为不同 procedure/不同主题且互补，与 tabby-cpg-gadget-chain-mining（论文算法）、tabby-chain-mcp、phply、Tai-e 等均不同链；dup-scan 无涉及 pair；两个 wiki 链接均存在。cards.json notes 中图04-08 编号与实际有偏移（04=小jar启动、05=16w构建、06=trick文档、07=2w完成、08=OOM），不影响卡内容。未重跑 tabby/Neo4j；frontmatter 无 sources/source_url（validator 禁止）。'
url: /docs/code-analysis/static/sast/code-analysis-sast-tabby-1-2-pathfinder-endpoint-sink-pitfalls/
draft: false
kb_aliases:
- Tabby 1.2
- tabby-path-finder
- IS_ENDPOINT
- IS_SINK
- findAllVul
- findPath 单节点限制
- new 不算 CALL
- HAS 语义
- Tabby 性能踩坑
- 代码属性图审计
---

## 一句话结论

Tabby 1.2（配 tabby-path-finder 1.1、Neo4j 5）可以用内置的 `IS_ENDPOINT`/`IS_SINK` 属性与 `tabby.algo.findPath/findAllVul` 从 `service`/Controller 等入口查向 `FILE_WRITE` 等 sink；但 1.2 的这些 procedure 只接受**单节点**（不支持节点列表）、`new FileOutputStream(...)` **不产生 CALL 边**（构造器 sink 是 `<init>`、需按 SIGNATURE 匹配）、`HAS` 只表示“类声明了该方法”而非“方法代码里包含调用”，且路径深度 >10 会路径爆炸——不理解这些图语义就会把“图上查不到/查出一堆”误判为工具结论。

## 原理

- **图模型**：Tabby 把 `Class`/`Method` 建模为节点，关系为 `EXTENDS`/`INTERFACE`（类之间）、`HAS`（类→方法，声明关系）、`CALL`（方法调用）、`ALIAS`（父类/接口同名方法，处理多态）。`IS_ENDPOINT`、`IS_SINK`、`VUL` 等信息保存在节点属性里；CALL 边的 `pollution_positions` 保存污点位置，但 1.2 的污点流信息有限。
- **内置端点识别**：Tabby 默认识别 Struts/Servlet/JSP/注释等端点类型。查询 `match (source:Method {IS_ENDPOINT:true}) return source` 可得候选入口；也可按接口继承链手写，例如 `doAction <-[:HAS]- Class -[:INTERFACE|EXTENDS*]-> IHttpServletAdaptor`。
- **sink 标签**：`match (sink:Method {IS_SINK:true, VUL:"FILE_WRITE"}) return sink` 可直接取文件写入类 sink；但 `new FileOutputStream(path)` 对应的是构造方法 `<init>`，其 SIGNATURE 形如 `<java.io.FileOutputStream: void <init>(java.lang.String)>`，需要按 SIGNATURE/CLASSNAME 精确查，而不是按 NAME 查。
- **procedure 的单节点限制**：tabby-path-finder 1.2 的 `tabby.algo.findAllVul(sources, sinks, depth, false)`/`findPath(source, "forward", sink, depth, false)` 只接受单个 source/sink 节点；把 `collect(source)` 得到的列表直接传入会失败，必须先人工选定入口或改写成多次单节点查询。
- **CALL 边语义（关键坑）**：Tabby 的 CALL 只跟踪 `this.function()` 与形参 `param.function()` 两种调用；`new Xxx()` 不算 CALL 边。因此从 `service` 出发用 `CALL*` 找不到“service 里直接 `new FileOutputStream()`”的路径；要么改用 sink 类的方法（如 `getInputStream`）做中间跳点，要么从构造器 sink 反向按一次调用边找包含它的方法。文章案例中 `service()` 直接 `new FileOutputStream` 导致调用链查询为空，正是踩了这个语义。
- **HAS 语义**：`(:Class)-[:HAS]->(:Method)` 只表示类声明了该方法，不表示方法体里包含某个调用；所以 `Class-[:HAS]->FileOutputStream.<init>` 永远查不到“类里 new 了 FileOutputStream”，HAS 不能替代 CALL。
- **查询深度与性能**：`findPath(..., MaxNodeLength=10)` 秒查，调到 15 时 30 分钟仍白页（路径爆炸）；加 `limit` 能明显提速。用 tabby-path-finder 时关系串可用 `-`（更快），用 APOC 时用 `ALIAS>|CALL>`。
- **构建性能**：`tabby.build.mode` 选 `web` 或 `gadget`（默认全量 gadget 模式对大系统会跑很久）；`tabby.build.libraries=false` 不分析依赖库；254MB/9w~16w classes 的 Jar 即使 `-Xmx8g` 跑数小时也难完成（原文还遇到 `OutOfMemoryError: GC overhead limit exceeded`），31MB/2w classes 业务包约 8 分 41 秒。建议先扫业务包，再按需补依赖。
- **卡住时的取舍技巧**：运行时加 `-Dlogging.level.tabby=DEBUG` 定位卡在哪个函数；若人工判断该函数可忽略（如 `com.seeyon.ctp.common.parser.BytesEncodingDetect.initialize_frequencies`），在 knowledge 库的 `sinks.json`/`system.json` 中加 ignore 规则（`{"name": "<类名>", "rules": [{"function": "<方法>", "type": "ignore", "vul": "", "actions": {}, "polluted": []}]}`），再跑即可跳过该函数的分析。
- **环境要点**：Neo4j 需允许 `dbms.security.procedures.unrestricted=...apoc.*,tabby.*`；tabby-path-finder 1.1 适配 Tabby 2.x/1.2 实验环境，1.0 少一些 procedure；提前给 Class.ID/NAME、Method.ID/SIGNATURE 建唯一约束，给 NAME/CLASSNAME/NAME0 建索引可提升查询速度。

## 触发条件

- 目标为 Java jar/war/class，Tabby 能完成代码属性图构建并导入 Neo4j（含 APOC 与 tabby-path-finder 插件）。
- 分析者知道入口形态（Servlet `service`/`doGet`/`doPost`、Struts `doAction`、Controller 注解等）与目标 sink 类型（文件写入、命令执行、反序列化等）。
- 目标体量可控（业务包优先，避免一次性全量依赖库）；Neo4j 内存与 JVM 堆足够。
- 仅作候选挖掘：图上可达不等于可利用，仍需人工核对参数可控性与过滤。

## 利用步骤

1. 按官方文档装 Neo4j 5 + APOC，配置 `dbms.security.procedures.unrestricted=jwt.security.*,apoc.*,tabby.*`，放入 tabby-path-finder 1.1 jar；用 `CALL tabby.help('tabby')` 验证 procedure 已导入。
2. 建约束/索引（Class.ID/NAME、Method.ID/SIGNATURE 唯一，Method.NAME/CLASSNAME/NAME0/SIGNATURE 索引），减少查询耗时。
3. 配置 `config/settings.properties`：`tabby.debug.details=true`、`tabby.build.target=<jar>`、`tabby.build.mode=web`（或 gadget）、`tabby.build.libraries=false`；`java -Xmx8g -jar tabby.jar` 生成图并导入。
4. 端点枚举：`match (source:Method {IS_ENDPOINT:true}) return source`；或按接口链/方法名（service、doAction、doGet、doPost）筛。
5. sink 枚举：`match (sink:Method {IS_SINK:true, VUL:"FILE_WRITE"}) return sink`；构造器 sink 用 `SIGNATURE:"<java.io.FileOutputStream: void <init>(java.lang.String)>"` 定位。
6. 单节点查询调用链：`call tabby.algo.findPath(source, ">", sink, 10, false) YIELD path return path limit 10`；深度先用 10，避免 15 路径爆炸。
7. 若查不到 `new Xxx()` 相关路径，改用同类的上游方法（文件上传案例用 `getInputStream`）作为 sink 或从构造器反向找包含它的业务方法，再人工确认参数来源。
8. 对候选链回源码/web.xml 核实路由与可控性（文章中 `FilesService` 虽有路由，但文件后缀写死 `.cdg`，不是任意上传）。

## PoC

端点与 sink 枚举：

```cypher
match (source:Method {IS_ENDPOINT: true}) return source;
match (sink:Method {IS_SINK: true, VUL:"FILE_WRITE"}) return sink;
```

按接口链识别端点（如某框架的 IHttpServletAdaptor，原文模板如下；其中 `collect(...)` 得到的列表在 1.2 实测不被 `findPath`/`findAllVul` 接受，需拆成单节点多次查询，见上文「procedure 的单节点限制」）：

```cypher
match (source:Method {NAME:"doAction"})
  <-[:HAS]-(c:Class)-[:INTERFACE|EXTENDS*]->(c1:Class {NAME:"nc.bs.framework.adaptor.IHttpServletAdaptor"})
with collect(source) as sources
match (sink:Method {IS_SINK: true, VUL:"FILE_WRITE"})
with sources, collect(sink) as sinks
call tabby.algo.findAllVul(sources, sinks, 8, false) yield path
return path limit 10;
```

单节点 findPath（1.2 不支持列表参数）：

```cypher
match (source:Method {NAME:"service", CLASSNAME:"com.sun.jersey.spi.container.servlet.ServletContainer"})
match (sink:Method {SIGNATURE:"<java.io.FileOutputStream: void <init>(java.lang.String)>",
                    CLASSNAME:"java.io.FileOutputStream"})
call tabby.algo.findPath(source, ">", sink, 10, false) YIELD path
return path limit 10;
```

构造器 sink 的 CALL 语义验证（`new` 不产生 CALL，因此 service 直接调用时查不到）：

```cypher
match path=(source:Method {NAME:"service"})-[]-(sink:Method)
where sink.SIGNATURE = "<java.io.FileOutputStream: void <init>(java.lang.String)>"
return path;
```

改用 `getInputStream` 作为跳点（文件上传场景）：

```cypher
MATCH path=(source:Method)-[:CALL]->(sink:Method {NAME:"getInputStream"})
WHERE source.CLASSNAME STARTS WITH "com.example.servlet"
RETURN path;
```

## 变体与关联

- **APOC 变体**：不用 tabby-path-finder 的内置 procedure 时，可用 `apoc.algo.allSimplePaths(source, m1, "ALIAS>|CALL>", depth)` 做通用图查询；两者的关系串写法不同，`-` 关系查询通常更快。
- **关联**：[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]] 覆盖 APOC allSimplePaths 的 Controller→sink 批量查询与导出；本卡补充 Tabby 1.2 + tabby-path-finder 的内置端点/sink 检索、procedure 单节点限制与 `new`/`HAS` 图语义陷阱，两者互补。
- **关联**：[[code-analysis-vuln-discovery-tabby-cpg-controllability-gadget-chain-algorithm]] 讲 Tabby 论文的 CPG/可控性剪枝与 gadget 回溯算法，本卡是工程化 Cypher 使用与踩坑。
- **变体**：对大 Jar 先按 `commonJar` 配置排除不需要分析的依赖，或只分析业务包；`gadget` 模式适合反序列化链挖掘，`web` 模式适合 Web 入口扫描。
- **边界**：Tabby 1.2 的 taint flow 信息少，调用链结果需人工核对；反射、动态代理、运行时生成类可能漏报；文件名/路由写死或强校验时，候选链不等于漏洞。

## 检测与防御

- **定位**：该卡是审计/漏洞挖掘方法论，不是可直接利用的攻击；对外部入口到危险 sink 的调用链应作为候选清单人工复核。
- **给防御方**：在 CI 中集成同类调用图/SAST 扫描，重点看外部入口到文件写入、命令执行、反序列化等 sink 的短链；对 `new FileOutputStream`、`MultipartFile.transferTo` 等直接落盘点做 path 可控性审查。
- **检测信号**：攻击者使用 Tabby/Neo4j 属于离线分析，主机侧无直接流量特征；防御重点是减少源码/字节码泄露与缩短外部入口到 sink 的可达路径。
