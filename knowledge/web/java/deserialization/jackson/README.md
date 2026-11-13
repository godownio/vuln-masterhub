# Jackson

## 这层是什么

Jackson 多态反序列化与 gadget。

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
| [Jackson + SignedObject 二次反序列化绕过 resolveClass 黑名单（TemplatesImpl 短链）](web-java-deserialization-jackson-signedobject-getobject-short-chain.md) | verified | high | 2026-11-05 |
| [Jackson 2.6–2.8 多态反序列化 CVE-2017-7525：enableDefaultTyping 实例化 TemplatesImpl，SetterlessProperty 调 getOutputProperties 加载字节码 RCE](web-java-deser-jackson-cve-2017-7525-templatesimpl-setterless-rce.md) | verified | high | 2026-11-13 |
| [Jackson 2.7–2.9 多态反序列化 CVE-2017-17485：@type 实例化 ClassPathXmlApplicationContext 加载远程 XML，SpEL](web-java-deser-jackson-cve-2017-17485-classpathxmlapplicationcontext-spel-rce.md) | verified | high | 2026-11-13 |
| [Jackson 原生反序列化链：JsonNode/POJONode toString 触发 TemplatesImpl#getOutputProperties 加载字节码 RCE（2.18.0 仍可用）](jackson-native-deserialization-getter-tostring-templates-rce.md) | verified | high | 2026-11-08 |
| [Jackson 多态反序列化到 Logback JNDIConnectionSource：getConnection getter 触发 JNDI lookup](web-java-deser-jackson-logback-jndiconnectionsource-lookup.md) | verified | medium | 2026-11-12 |
| [Jackson 自定义 deObject 的 @type 任意实例化 + 递归反射赋值：改写 SecurityCheck.safe/treeMap 进入原生反序列化分支 RCE](web-java-deser-jackson-deobject-type-reflection-field-injection.md) | verified | high | 2026-11-11 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
