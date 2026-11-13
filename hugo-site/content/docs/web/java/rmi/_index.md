---
title: RMI
weight: 1
---

# RMI

## 这层是什么

RMI 注册表、DGC、动态类加载与利用。

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
| [JDK 8u141+ 绕过 RMI Registry checkAccess：自实现 lookup 传入 Remote 对象，把反序列化引到攻击者 JRMPListener](web-java-rmi-registry-lookup-checkaccess-jrmp-bypass/) | verified | medium | 2026-11-08 |
| [JDK21 JNDI 过滤器绕过：恶意 JRMP listener 返回 ExceptionalReturn 异常对象触发客户端 readObject](web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass/) | verified | high | 2026-11-08 |
| [RMI codebase 动态类加载：客户端序列化流携带 java.rmi.server.codebase，服务端 useCodebaseOnly=false 时加载攻击者类并执行静态块](web-java-rmi-codebase-remote-class-loading/) | verified | medium | 2026-11-12 |
| [RMI Registry 的 bind/rebind 分支直接 readObject：用 ysoserial RMIRegistryExploit 打 1099 拿 RCE](web-java-rmi-registry-bind-rebind-deserialization/) | draft | medium | 2026-11-08 |
| [RMI 远程方法接收 Object 参数：客户端传入 CommonsCollections payload，服务端反序列化参数时执行命令](web-java-rmi-remote-method-object-param-deserialization/) | verified | high | 2026-11-12 |
| [ysoserial payload JRMPListener：反序列化目标 reexport 自开 JRMP 端口，再用 JRMPClient 反打触发 DGC 反序列化](web-java-rmi-yso-jrmp-listener-payload-reexport-port/) | verified | high | 2026-11-11 |
| [未授权 JMX Connector Server + MLet 远程 MBean 加载：createMBean MLet + getMBeansFromURL 拉取攻击者 mlet/JAR 实现 RCE](web-java-rmi-jmx-mlet-remote-mbean-load-rce/) | verified | high | 2026-11-13 |
| [用 JRMPListener 冒充 1099 注册中心：扫描器一发 bind/list 就被「反向打回」，恶意 JRMP 端返回 gadget 反制](web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack/) | verified | medium | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
