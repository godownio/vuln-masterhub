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
| [Apache Cayenne ROP Servlet Hessian 反序列化（CVE-2022-24289）：≤4.1 默认无白名单，UIDefaults/SwingLazyValue→MethodUtil→UnixPrintServiceLookup 命令执行](web-java-deser-hessian-cayenne-rop-servlet-entry.md) | verified | high | 2026-11-11 |
| [Apache Seata 8091 Netty RPC Hessian 反序列化入口：codec 22 直接反序列化请求体](web-java-deser-hessian-seata-8091-rpc-codec22.md) | verified | medium | 2026-11-05 |
| [aspectjweaver LazyMethodGen.toString 链：经 AjAttribute 读取走到 ObjectInputStream 二次反序列化](web-java-deser-hessian-aspectj-lazymethodgen-second-order.md) | verified | high | 2026-11-05 |
| [Dubbo 2.7.6–2.7.9 Hessian 反序列化补丁绕过：方法参数类型非空使 pts≠EMPTY_CLASS_ARRAY，isGenericCall/isEcho 白名单检查被跳过](web-java-deser-hessian-dubbo-pts-emptyclassarray-filter-bypass.md) | verified | medium | 2026-11-09 |
| [Dubbo provider Hessian2 反序列化入口（<=2.7.6）：DecodeableRpcInvocation 解码 RPC 参数触发 HashMap→EqualsBean/ToStringBean→JdbcRowSetImpl JNDI RCE](web-java-deser-hessian-dubbo-provider-argument-deserialization-rce.md) | verified | high | 2026-11-09 |
| [Dubbo SerializeClassChecker 绕过（CVE-2023-23638）：native 模式用 System/ConfigUtils 打开开关、raw.return 用 Map 改写单例字段](web-java-deser-hessian-dubbo-generic-filter-serializeclasschecker-bypass.md) | verified | medium | 2026-11-12 |
| [Dubbo 泛化调用 GenericFilter 反序列化（CVE-2021-30179）：raw.return/bean/native 三种 generic 方式实例化任意类](web-java-deser-hessian-dubbo-generic-filter-realize-deserialization.md) | verified | medium | 2026-11-12 |
| [Hessian + ConcurrentHashMap 交叉 MapEntry 触发 ServerManagerImpl 执行命令](web-java-deser-hessian-concurrenthashmap-servermanager-exec.md) | verified | high | 2026-11-05 |
| [Hessian 3.x JavaDeserializer 调构造器 + 反射赋值：非 Serializable 的 sun.print.UnixPrintServiceLookup 经 PrinterChangeListener 线程执行 lpcAllCom 命令（4.x Unsafe allocateInstance 不触发）](web-java-deser-hessian-javadeserializer-constructor-unixprintservicelookup-rce.md) | verified | medium | 2026-11-13 |
| [Hessian Groovy GString 链：hashCode → toString → Closure.call 命令执行](web-java-deser-hessian-groovy-gstring-chain.md) | verified | high | 2026-11-05 |
| [Hessian JDK-only 链：UIDefaults/ProxyLazyValue 触发任意静态方法或构造](web-java-deser-hessian-jdk-only-proxylazyvalue-chain.md) | verified | high | 2026-11-05 |
| [Hessian 不出网两阶段链：ProxyLazyValue 调 DumpBytecode 把 class 写入 tmpdir，再用 keytool Main 以 -providerclass 加载执行](web-java-deser-hessian-dumpbytecode-keytool-write-class-load-provider.md) | verified | high | 2026-11-10 |
| [Hessian 出网 JNDI 链：Spring、Rome、Resin、XBean](web-java-deser-hessian-jndi-outbound-chains.md) | verified | high | 2026-11-05 |
| [Hessian 动态代理触发 Spring InvocationHandler 链到 JNDI：ObjectFactoryDelegatingInvocationHandler→TargetBeanObjectFactory→SimpleJndiBeanFactory](web-java-deser-hessian-spring-proxy-invocationhandler-jndi.md) | verified | medium | 2026-11-06 |
| [Hessian 反序列化入口：MapDeserializer 的 map.put 触发 hashCode/equals/compareTo](web-java-deser-hessian-deserialization-entry-map-put.md) | verified | high | 2026-11-05 |
| [Hessian 反序列化通防：匿名 SerializerFactory 重写 getDeserializer(String) 按类名黑名单拦截（对比 resolveClass 原生 hook）](hessian-deserialization-serializerfactory-getdeserializer-hook-blacklist.md) | verified | high | 2026-11-08 |
| [Hessian 反序列化黑名单绕过：UTF-8 Overlong Encoding 隐藏类名](web-java-deser-hessian-utf8-overlong-encoding-bypass.md) | verified | high | 2026-11-05 |
| [Hessian 链用 SignedObject 二次反序列化绕过 transient 限制加载 TemplatesImpl](web-java-deser-hessian-signedobject-second-order-templates.md) | verified | high | 2026-11-05 |
| [Hessian2 TreeMap + CustomProxy 触发 sun.tracing ProviderSkeleton/DTraceProbe 反射调用：FileCredentialsCache.exec RCE](web-java-deser-hessian-treemap-customproxy-dtraceprobe-exec.md) | verified | high | 2026-11-06 |
| [Hessian2 前置 C 字节制造协议错误，在 expect 拼接中隐式调用 toString](web-java-deser-hessian2-protocol-error-tostring-trigger.md) | verified | high | 2026-11-05 |
| [Hessian2 类型化 Map 打 Hutool JSONObject：put→JSONUtil.wrap 对 JDK 类调 toString，AtomicReference 适配 POJONode 形成任意 getter 触发](web-java-deser-hessian-typed-map-jsonobject-wrap-tostring.md) | verified | high | 2026-11-10 |
| [HessianProxyFactory 作为 JNDI ObjectFactory：lookup 后调用方法触发二次 Hessian 反序列化](web-java-deser-hessian-proxyfactory-jndi-deserialization.md) | verified | medium | 2026-11-05 |
| [HessianServlet 实战入口：手搓 Hessian 调用在方法参数/Header 处触发 readObject](web-java-deser-hessian-hessianservlet-argument-header-entry.md) | verified | high | 2026-11-07 |
| [JDK 21/11.0.29 JNDI trustSerialData 绕过：Reference-only + HessianProxyFactory + POJONode/UnixPrintService 命令执行](web-java-deser-hessian-jndi-reference-only-unixprintservice.md) | verified | high | 2026-11-06 |
| [Nacos raft 请求触发 Hessian 反序列化：AbstractProcessor#handleRequest→JRaftServer#applyOperation→InstanceMetadataProcessor#onApply](web-java-deser-hessian-nacos-raft-abstractprocessor-entry.md) | verified | medium | 2026-11-12 |
| [SOFARPC CVE-2024-23636：SOFA Hessian 黑名单绕过，TreeSet/RdnEntry.compareTo 触发 XStringForFSB/MultiUIDefaults 到 SwingLazyValue JNDI RCE（仅 JDK）](web-java-deser-hessian-sofarpc-cve-2024-23636-blacklist-bypass.md) | verified | high | 2026-11-12 |
| [XXL-Job /api Hessian 反序列化实战 WAF 绕过：//api 双斜杠 + javachain 脏数据/超长 UTF-8 混淆](web-java-deser-hessian-xxl-job-api-waf-bypass-dirty-data.md) | verified | high | 2026-11-07 |
| [XXL-Job Admin /api 前台未授权 Hessian 反序列化入口](web-java-deser-hessian-xxl-job-admin-api-entry.md) | verified | high | 2026-11-05 |
| [手搓 Hessian 1.0 业务调用包：c/m/S 结构与长度回填改参数做注入测试](web-java-hessian-manual-call-packet-parameter-injection.md) | verified | high | 2026-11-12 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
