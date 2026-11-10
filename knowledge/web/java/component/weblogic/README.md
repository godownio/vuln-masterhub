# WebLogic

## 这层是什么

WebLogic 反序列化、T3/IIOP 与历史漏洞。

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
| [WebLogic 11g CVE-2020-2551 IIOP 反序列化 RCE：/bea_wls_internal/iiop 端点与 WebLogicTool 回显利用](web-java-component-weblogic-cve-2020-2551-iiop-echo-rce.md) | verified | medium | 2026-11-07 |
| [WebLogic CVE-2019-2725 只给命令回显时，借已控内网主机反向拉取 JSP 落盘（wget 到 bea_wls_internal 目录）](web-java-component-weblogic-wls-wsat-jsp-upload-indirect-fetch.md) | verified | high | 2026-11-08 |
| [WebLogic CVE-2024-21006 IIOP JNDI 注入：lookupSharable 续接上下文触发 MessageDestinationObjectFactory 本地工厂二次 lookup](web-java-component-weblogic-cve-2024-21006-iiop-lookupsharable-messagedestination-jndi.md) | verified | high | 2026-11-10 |
| [WebLogic CVE-2024-21181 T3/IIOP 反序列化：伪造 Reference 的 jvmId 触发 PartitionedMbsRefObjFactory.getObjectInstance 无过滤 readObject](web-java-component-weblogic-cve-2024-21181-iiop-partitionedmbsrefobjfactory-deser.md) | verified | high | 2026-11-08 |
| [WebLogic 域内 JDBC 连接密文解密：读 jdbc xml + SerializedSystemIni.dat 还原数据库口令](web-java-component-weblogic-jdbc-cipher-serializedsystemini-decrypt.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
