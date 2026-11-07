---
title: Hessian
weight: 1
---

# Hessian

## 这层是什么

Hessian 反序列化与利用链。

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
| [Apache Seata 8091 Netty RPC Hessian 反序列化入口：codec 22 直接反序列化请求体](web-java-deser-hessian-seata-8091-rpc-codec22/) | verified | medium | 2026-11-05 |
| [aspectjweaver LazyMethodGen.toString 链：经 AjAttribute 读取走到 ObjectInputStream 二次反序列化](web-java-deser-hessian-aspectj-lazymethodgen-second-order/) | verified | high | 2026-11-05 |
| [Hessian + ConcurrentHashMap 交叉 MapEntry 触发 ServerManagerImpl 执行命令](web-java-deser-hessian-concurrenthashmap-servermanager-exec/) | verified | high | 2026-11-05 |
| [Hessian Groovy GString 链：hashCode → toString → Closure.call 命令执行](web-java-deser-hessian-groovy-gstring-chain/) | verified | high | 2026-11-05 |
| [Hessian JDK-only 链：UIDefaults/ProxyLazyValue 触发任意静态方法或构造](web-java-deser-hessian-jdk-only-proxylazyvalue-chain/) | verified | high | 2026-11-05 |
| [Hessian 出网 JNDI 链：Spring、Rome、Resin、XBean](web-java-deser-hessian-jndi-outbound-chains/) | verified | high | 2026-11-05 |
| [Hessian 动态代理触发 Spring InvocationHandler 链到 JNDI：ObjectFactoryDelegatingInvocationHandler→TargetBeanObjectFactory→SimpleJndiBeanFactory](web-java-deser-hessian-spring-proxy-invocationhandler-jndi/) | verified | medium | 2026-11-06 |
| [Hessian 反序列化入口：MapDeserializer 的 map.put 触发 hashCode/equals/compareTo](web-java-deser-hessian-deserialization-entry-map-put/) | verified | high | 2026-11-05 |
| [Hessian 反序列化黑名单绕过：UTF-8 Overlong Encoding 隐藏类名](web-java-deser-hessian-utf8-overlong-encoding-bypass/) | verified | high | 2026-11-05 |
| [Hessian 链用 SignedObject 二次反序列化绕过 transient 限制加载 TemplatesImpl](web-java-deser-hessian-signedobject-second-order-templates/) | verified | high | 2026-11-05 |
| [Hessian2 TreeMap + CustomProxy 触发 sun.tracing ProviderSkeleton/DTraceProbe 反射调用：FileCredentialsCache.exec RCE](web-java-deser-hessian-treemap-customproxy-dtraceprobe-exec/) | verified | high | 2026-11-06 |
| [Hessian2 前置 C 字节制造协议错误，在 expect 拼接中隐式调用 toString](web-java-deser-hessian2-protocol-error-tostring-trigger/) | verified | high | 2026-11-05 |
| [HessianProxyFactory 作为 JNDI ObjectFactory：lookup 后调用方法触发二次 Hessian 反序列化](web-java-deser-hessian-proxyfactory-jndi-deserialization/) | verified | medium | 2026-11-05 |
| [JDK 21/11.0.29 JNDI trustSerialData 绕过：Reference-only + HessianProxyFactory + POJONode/UnixPrintService 命令执行](web-java-deser-hessian-jndi-reference-only-unixprintservice/) | verified | high | 2026-11-06 |
| [XXL-Job Admin /api 前台未授权 Hessian 反序列化入口](web-java-deser-hessian-xxl-job-admin-api-entry/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
