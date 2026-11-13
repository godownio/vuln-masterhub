# XStream

## 这层是什么

XStream 反序列化与 CVE 利用。

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
| [XStream 4 类型白名单绕过四特性：属性豁免、层级豁免、final 可改与 transient 不写](web-java-deserialization-xstream-type-permission-bypass.md) | verified | high | 2026-11-05 |
| [XStream ≤1.4.15（CVE-2021-21344）：PriorityQueue+IndexOrderComparator 经 JAXWS/JAXB Bridge 反射 getter 到 JdbcRowSetImpl JNDI 注入](web-java-deserialization-xstream-cve-2021-21344-priorityqueue-jaxb-jdbcrowset-jndi.md) | verified | high | 2026-11-13 |
| [XStream ≤1.4.15（CVE-2021-21351）：sorted-set+RdnEntry.compareTo 经 XRTreeFrag/SAX2DTM 到 IncrementalSAXSource_Xerces 反射 setAutoCommit 触发 JdbcRowSetImpl JNDI](web-java-deserialization-xstream-cve-2021-21351-rdnentry-xrtreefrag-jdbcrowset-jndi.md) | verified | high | 2026-11-13 |
| [XStream ≤1.4.16 黑名单漏掉 RegistryImpl_Stub：XML 反序列化触发 JRMP 回连，恶意 Listener 返回 CommonsCollections6 二次反序列化 RCE（CVE-2021-29505）](web-java-deserialization-xstream-cve-2021-29505-registryimpl-stub-jrmp.md) | verified | high | 2026-11-11 |
| [XStream ≤1.4.6（及 1.4.10 未启用安全框架）EventHandler 动态代理链：sorted-set/tree-map 触发 compareTo 反射调用 ProcessBuilder.start](web-java-deserialization-xstream-sortedset-dynamicproxy-eventhandler-processbuilder.md) | verified | high | 2026-11-13 |
| [亿赛通 GetValidateLoginUserService：请求体经 CodeDecoder 解密后直接 XStream 1.4.9 fromXML，ttt 头命令执行回显](web-java-deserialization-xstream-esafenet-getvalidateloginuser-service-rce.md) | verified | medium | 2026-11-13 |
| [泛微 e-cology /services/WorkflowServiceXml 未授权 XStream 反序列化：doCreateWorkflowRequest 的 SOAP string 经 XmlUtil.xmlToObject→XStream.fromXML（xstream-1.3）执行任意代码](web-java-deserialization-xstream-weaver-workflowservicexml-unauth-rce.md) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
