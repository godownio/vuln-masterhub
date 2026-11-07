# Comparator 链

## 这层是什么

通过 Comparator/compare 触发 toString、hashCode 等方法的 gadget 组合。

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
| [CB1 CommonsBeanutils BeanComparator + PriorityQueue 触发 TemplatesImpl](web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue.md) | verified | high | 2026-11-05 |
| [CC4/CC2 PriorityQueue + TransformingComparator 触发 TemplatesImpl 字节码](web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl.md) | verified | high | 2026-11-05 |
| [Commons Collections 4.0 CC2 链：PriorityQueue → TransformingComparator → ChainedTransformer/InvokerTransformer 反射执行 Runtime.exec 或 TemplatesImpl](web-java-deser-commonscollections-cc2-chained-invoker-priorityqueue.md) | verified | high | 2026-11-07 |
| [Fury 二次反序列化桥：UsingToStringOrdering→AbstractMemoryDataStore→IOUtils.deserialize 触发二阶段 gadget](web-java-deser-fury-usingtostring-datastore-ioutils-secondary-deser.md) | verified | high | 2026-11-06 |
| [Fury 反序列化经 PriorityQueue/TransformingComparator 触发 AspectJ StoreableCachingMap：写 JRE 扩展 jar 加载 RCE](web-java-deser-fury-priorityqueue-aspectj-jre-jar-write-rce.md) | verified | high | 2026-11-06 |
| [JDK17 模块封装下 CC4 链改写 Class.packageName 绕过校验触发 TemplatesImpl](web-java-deser-jdk17-cc4-package-name-bypass-templatesimpl.md) | verified | high | 2026-11-05 |
| [PriorityQueue 比较器触发 toString 的通用构造](priorityqueue.md) | draft | medium | 2026-11-04 |
| [Rhino 环境下 Comparator 链触发 toString](rhino.md) | draft | medium | 2026-11-04 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
