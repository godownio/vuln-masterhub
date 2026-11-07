# SAST

## 这层是什么

静态分析工具、规则与误报处理。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [CodeQL isBarrier 泛型净化：把 List<Long> 等简单类型判为净化点消除 SQL 注入误报](code-analysis-sast-codeql-isbarrier-parameterized-simple-type.md) | verified | high | 2026-11-05 |
| [CodeQL Java 默认污点传播缺失的补充：TaintPreservingCallable 与 dataExtensions 库模型](code-analysis-sast-codeql-custom-taint-steps.md) | verified | high | 2026-11-05 |
| [CodeQL 启发式挖 Spring MVC 水平越权：筛选未调用 HttpSession.getAttribute 的 Controller 方法](code-analysis-sast-codeql-spring-horizontal-authz-session-attribute.md) | verified | medium | 2026-11-07 |
| [CodeQL 挖掘 Spring @RequestBody 大量赋值：未显式调用 setter 的数据流查询](code-analysis-sast-codeql-spring-mass-assignment-query.md) | verified | high | 2026-11-05 |
| [CodeQL 枚举 Spring Controller 缺失自定义鉴权注解：以 PowerJob @ApiPermission 为例](code-analysis-sast-codeql-spring-missing-auth-annotation.md) | verified | high | 2026-11-07 |
| [CodeQL 枚举 Spring MultipartFile 上传点：注解与参数类型定位文件上传面](code-analysis-sast-codeql-spring-multipartfile-upload-endpoints.md) | verified | high | 2026-11-05 |
| [CodeQL 自定义 source 用 ActiveThreatModelSource，避免漏掉 ServletRequest.getParameter 等库模型源](code-analysis-sast-codeql-active-threat-model-source-coverage.md) | verified | high | 2026-11-05 |
| [CodeQL 追踪 Struts OGNL 注入：ActionProxy source、OgnlUtil sink 与字段跨函数污点桥接](code-analysis-sast-codeql-struts-ognl-taint-modeling.md) | verified | high | 2026-11-05 |
| [CodeQL_n1ght 从 jar 建库 + 接口分派补边：Controller→Impl→DAO getConnection 查 JDBC 注入](code-analysis-sast-codeql-n1ght-jar-controller-interface-sink.md) | verified | high | 2026-11-07 |
| [nginx 双引擎状态不一致自动化检测：配置语义 + 源码模式 + 状态追踪 + 溢出断言四层扫描](code-analysis-sast-nginx-dual-engine-state-scanner.md) | verified | high | 2026-11-05 |
| [phply + Neo4j 构建 PHP 调用图：PHP7→5 语法降级、命名空间消解与 Controller→危险函数链查询](code-analysis-sast-phply-neo4j-php-callchain-sink-query.md) | draft | medium | 2026-11-07 |
| [QLCoder：LLM Agent + CodeQL LSP/RAG 从 CVE 元数据迭代合成污点查询](code-analysis-sast-qlcoder-llm-codeql-query-synthesis.md) | verified | medium | 2026-11-06 |
| [SCA 告警到 SAST/DAST 验证建议：LLM Agent 多源证据检索与可达性规则生成](code-analysis-sast-sca-llm-agent-reachability-verification.md) | verified | medium | 2026-11-07 |
| [tabby + Neo4j 从 Controller 入口批量查询危险 sink 调用链](code-analysis-sast-tabby-neo4j-controller-sink-callchain.md) | verified | medium | 2026-11-05 |
| [Tai-e Java 白盒污点分析工程化：classpath 分离 + 路由 source 提取 + 入口注入 + only-app 断链补全](code-analysis-sast-taie-java-taint-audit-toolchain.md) | verified | high | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
