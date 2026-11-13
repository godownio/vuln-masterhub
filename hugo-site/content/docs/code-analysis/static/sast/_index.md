---
title: SAST
weight: 1
---

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
| [AST 调用链深度递增扫描（depth≤3→4）+ 按 sink 分级复现：把链清单变成可验证漏洞清单](code-analysis-sast-ast-chain-depth-escalation-triage/) | verified | medium | 2026-11-08 |
| [CodeQL isBarrier 泛型净化：把 List<Long> 等简单类型判为净化点消除 SQL 注入误报](code-analysis-sast-codeql-isbarrier-parameterized-simple-type/) | verified | high | 2026-11-05 |
| [CodeQL Java 默认污点传播缺失的补充：TaintPreservingCallable 与 dataExtensions 库模型](code-analysis-sast-codeql-custom-taint-steps/) | verified | high | 2026-11-05 |
| [CodeQL 启发式挖 Spring MVC 水平越权：筛选未调用 HttpSession.getAttribute 的 Controller 方法](code-analysis-sast-codeql-spring-horizontal-authz-session-attribute/) | verified | medium | 2026-11-07 |
| [CodeQL 挖掘 Spring @RequestBody 大量赋值：未显式调用 setter 的数据流查询](code-analysis-sast-codeql-spring-mass-assignment-query/) | verified | high | 2026-11-05 |
| [CodeQL 枚举 Spring Controller 缺失自定义鉴权注解：以 PowerJob @ApiPermission 为例](code-analysis-sast-codeql-spring-missing-auth-annotation/) | verified | high | 2026-11-07 |
| [CodeQL 枚举 Spring MultipartFile 上传点：注解与参数类型定位文件上传面](code-analysis-sast-codeql-spring-multipartfile-upload-endpoints/) | verified | high | 2026-11-05 |
| [CodeQL 枚举反射调用面：按 public + 无参构造 + String 参数 + 包名白名单筛选被任务调度器反射调用的可利用方法](code-analysis-sast-codeql-reflection-invokable-method-surface/) | verified | high | 2026-11-09 |
| [CodeQL 自定义 source 用 ActiveThreatModelSource，避免漏掉 ServletRequest.getParameter 等库模型源](code-analysis-sast-codeql-active-threat-model-source-coverage/) | verified | high | 2026-11-05 |
| [CodeQL 追踪 Struts OGNL 注入：ActionProxy source、OgnlUtil sink 与字段跨函数污点桥接](code-analysis-sast-codeql-struts-ognl-taint-modeling/) | verified | high | 2026-11-05 |
| [CodeQL_n1ght 从 jar 建库 + 接口分派补边：Controller→Impl→DAO getConnection 查 JDBC 注入](code-analysis-sast-codeql-n1ght-jar-controller-interface-sink/) | verified | high | 2026-11-07 |
| [MyBatis SQL 注入 sink 提取：遍历 classpath 解析 Mapper XML/注解的 ${} 拼接点，按 @Param/JavaBean/Map/List 映射到方法参数](code-analysis-sast-mybatis-mapper-sql-concat-sink-extraction/) | verified | medium | 2026-11-09 |
| [nginx 双引擎状态不一致自动化检测：配置语义 + 源码模式 + 状态追踪 + 溢出断言四层扫描](code-analysis-sast-nginx-dual-engine-state-scanner/) | verified | high | 2026-11-05 |
| [phply + Neo4j 构建 PHP 调用图：PHP7→5 语法降级、命名空间消解与 Controller→危险函数链查询](code-analysis-sast-phply-neo4j-php-callchain-sink-query/) | verified | medium | 2026-11-07 |
| [QLCoder：LLM Agent + CodeQL LSP/RAG 从 CVE 元数据迭代合成污点查询](code-analysis-sast-qlcoder-llm-codeql-query-synthesis/) | verified | medium | 2026-11-06 |
| [RIPS v0.55 PHP token 流规范化：token_get_all 后的删除/重写、数组键折叠、控制结构补括号与三元裁剪](code-analysis-sast-rips-php-token-stream-normalization/) | verified | high | 2026-11-09 |
| [RIPS v0.55 source/sink 污点扫描：15 类规则、净化函数与 $var()/$$var 回溯](code-analysis-sast-rips-source-sink-taint-scan/) | verified | high | 2026-11-09 |
| [SCA 告警到 SAST/DAST 验证建议：LLM Agent 多源证据检索与可达性规则生成](code-analysis-sast-sca-llm-agent-reachability-verification/) | verified | medium | 2026-11-07 |
| [Semgrep 代码审计落地：本地 semgrep-rules 离线扫描、Pro 规则/引擎登录门槛与 --metrics 隐私控制](code-analysis-sast-semgrep-offline-rules-pro-engine-privacy/) | draft | high | 2026-11-13 |
| [tabby + Neo4j 从 Controller 入口批量查询危险 sink 调用链](code-analysis-sast-tabby-neo4j-controller-sink-callchain/) | verified | medium | 2026-11-05 |
| [Tabby 1.2 + tabby-path-finder 实战：IS_ENDPOINT/IS_SINK 检索、findPath 单节点限制与 new/HAS 图语义陷阱](code-analysis-sast-tabby-1-2-pathfinder-endpoint-sink-pitfalls/) | verified | high | 2026-11-12 |
| [Tai-e Java 白盒污点分析工程化：classpath 分离 + 路由 source 提取 + 入口注入 + only-app 断链补全](code-analysis-sast-taie-java-taint-audit-toolchain/) | verified | high | 2026-11-06 |
| [Tai-e MyBatis 字段级污点匹配与传播补全：JavaBean 字段 sink + SpringMVC 入参字段造污点 + Map/List/setter transfers](code-analysis-sast-taie-mybatis-field-taint-propagation/) | verified | medium | 2026-11-09 |
| [Tai-e 分析 Servlet 容器应用：@WebServlet 入口注入 + RequestFacade/ResponseFacade mock + doX 请求参数 source](code-analysis-sast-taie-servlet-container-entrypoint-taint/) | verified | medium | 2026-11-09 |
| [Tai-e 手工入口点分析 JavaWeb 方法：mock 参数必须是形参接口的实现类、source 方法必须在具体类中声明或重写](code-analysis-sast-taie-custom-entrypoint-mock-source-type-matching/) | verified | medium | 2026-11-12 |
| [Tai-e 指针分析支持 MyBatis 抽象 Mapper：MockObj 补调用边 + 抽象方法空 IR + SinkHandler 收集注解 SQL](code-analysis-sast-taie-mybatis-abstract-mapper-sink-analysis/) | verified | medium | 2026-11-09 |
| [Tai-e 指针分析补全 Spring 控制反转（CHA 启发式）：onPhaseFinish 给空指向集的 invokeinterface 接收者注入实现类 MockObj](code-analysis-sast-taie-spring-di-cha-mockobj-callgraph/) | verified | high | 2026-11-11 |
| [Tai-e 注入自定义 MyBatis ${} sink：在 TaintConfig.deserializeSinks 的 unmodifiableList 包装前 addAll，SinkHandler 内直接 add 会抛异常](code-analysis-sast-taie-mybatis-dollar-sink-inject-taintconfig/) | verified | high | 2026-11-10 |
| [Tai-e 精确建模 Spring 注解注入：@Resource/@Autowired/@Inject 注入点 + @Service/@Component 实现类 + LoadField 返回值指向集](code-analysis-sast-taie-spring-annotation-injection-loadfield-modeling/) | verified | high | 2026-11-11 |
| [Tai-e 自定义程序分析扩展提取 Spring Controller API：MethodAnalysis/ClassAnalysis/ProgramAnalysis + tai-e-analyses.yml 注册 + 注解路由解析](code-analysis-sast-taie-custom-program-analysis-api-extraction/) | verified | high | 2026-11-10 |
| [Tai-e 静态污点分析检测 Log4Shell：日志入口 call source + InitialContext/JndiManager lookup sink + StringBuilder 等 transfer 补齐](code-analysis-sast-taie-log4shell-taint-detection/) | verified | medium | 2026-11-12 |
| [用 CodeQL 定位反序列化链：Serializable 类入口 → ClassInstanceExpr 定位调用方 → 按方法名匹配 exeCmd/deserialize 定义 sink，RemoteFlowSource 接 cookie 形成完整 path-problem](code-analysis-sast-codeql-deserialization-named-method-sink/) | verified | high | 2026-11-08 |
| [用 GitHub code-scanning API 直接下载开源项目的 CodeQL 数据库，本地跑自定义查询做定向代码审计](code-analysis-static-codeql-database-download-github-api-local-query/) | verified | medium | 2026-11-09 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
