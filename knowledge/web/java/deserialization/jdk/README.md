# JDK 原生链

## 这层是什么

JDK 内置类形成的反序列化链与触发点。

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
| [EventListenerList 反序列化触发任意 toString（JDK17 可用）](web-java-deserialization-jdk-eventlistenerlist-tostring.md) | verified | high | 2026-11-05 |
| [HashMap/HotSwappableTargetSource 配合 XString.equals 触发任意 toString](web-java-deserialization-jdk-xstring-equals-tostring.md) | verified | high | 2026-11-05 |
| [Hashtable 配合 TextAndMnemonicHashMap 触发任意 toString](web-java-deserialization-jdk-hashtable-textandmnemonic-tostring.md) | verified | medium | 2026-11-05 |
| [JDK 8u20 原生链：BeanContextSupport 吞异常 + TC_REFERENCE 复用 AnnotationInvocationHandler](web-java-deserialization-jdk-8u20-beancontextsupport-native-chain.md) | verified | high | 2026-11-05 |
| [JDK8 原生链：SwingLazyValue 调 Process._main 加载落地 XSLT 注入内存马](web-java-deser-jdk-xslt-process-main-chain.md) | verified | medium | 2026-11-05 |
| [SignedObject 嵌套 ObjectInputStream 绕过反序列化过滤器](web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass.md) | verified | high | 2026-11-05 |
| [URLDNS 利用 HashMap 与 URL.hashCode 探测反序列化入口](web-java-deser-jdk-urldns-dns-probe.md) | verified | high | 2026-11-05 |
| [原生 Java 反序列化字节黑名单绕过：UTF-8 Overlong Encoding 隐藏 TemplatesImpl/EventListenerList 类名](web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
