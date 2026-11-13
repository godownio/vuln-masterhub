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
| [WebLogic CVE-2016-0638：StreamMessageImpl.readExternal 内层 ObjectInputStream 二次反序列化绕过 resolveClass 黑名单](web-java-component-weblogic-cve-2016-0638-streammessageimpl-blacklist-bypass.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2016-3510：weblogic.corba.utils.MarshalledObject.readResolve 二次反序列化绕过黑名单](web-java-component-weblogic-cve-2016-3510-marshalledobject-readresolve-bypass.md) | verified | medium | 2026-11-13 |
| [WebLogic CVE-2017-3248：T3 投递 RemoteObjectInvocationHandler+UnicastRef 令目标回连 JRMPListener 二次反序列化](web-java-component-weblogic-cve-2017-3248-jrmpclient-deserialization.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2017-3506/10271：wls-wsat WorkContext 头交给 XMLDecoder.readObject，object→void 绕过黑名单 RCE](web-java-component-weblogic-workcontext-xmldecoder-cve-2017-10271.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2018-2628：绕过 resolveProxyClass 的 Registry 过滤（直投 UnicastRef 或改用 Activator 接口代理）](web-java-component-weblogic-cve-2018-2628-resolveproxyclass-bypass.md) | verified | medium | 2026-11-13 |
| [WebLogic CVE-2018-2893：StreamMessageImpl 包裹 JRMPClient，二次反序列化绕过 UnicastRef 全局黑名单](web-java-component-weblogic-cve-2018-2893-streammessageimpl-jrmpclient.md) | verified | medium | 2026-11-13 |
| [WebLogic CVE-2018-2894：后台开启 Web 服务测试页后 ws_utc config.do/begin.do 未授权上传 JSP 到 css 目录 getshell](web-java-component-weblogic-cve-2018-2894-ws-utc-file-upload.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2018-3191：T3 反序列化 JtaTransactionManager 触发 userTransactionName 的 JNDI lookup](web-java-component-weblogic-cve-2018-3191-jtatransactionmanager-jndi.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2018-3245：以 RemoteObject 其他子类（RMIConnectionImpl_Stub）承载 UnicastRef，绕过 RMI 类黑名单](web-java-component-weblogic-cve-2018-3245-remoteobject-subclass-jrmp.md) | verified | medium | 2026-11-13 |
| [WebLogic CVE-2019-2725 只给命令回显时，借已控内网主机反向拉取 JSP 落盘（wget 到 bea_wls_internal 目录）](web-java-component-weblogic-wls-wsat-jsp-upload-indirect-fetch.md) | verified | high | 2026-11-08 |
| [WebLogic CVE-2020-14882：%252E%252E%252F 双编码路径穿越未授权进 console，handle 参数 MVEL ShellSession 或远程 Spring XML 执行命令](web-java-component-weblogic-cve-2020-14882-wls-console-path-traversal-mvel.md) | verified | high | 2026-11-13 |
| [WebLogic CVE-2024-21006 IIOP JNDI 注入：lookupSharable 续接上下文触发 MessageDestinationObjectFactory 本地工厂二次 lookup](web-java-component-weblogic-cve-2024-21006-iiop-lookupsharable-messagedestination-jndi.md) | verified | high | 2026-11-10 |
| [WebLogic CVE-2024-21181 T3/IIOP 反序列化：伪造 Reference 的 jvmId 触发 PartitionedMbsRefObjFactory.getObjectInstance 无过滤 readObject](web-java-component-weblogic-cve-2024-21181-iiop-partitionedmbsrefobjfactory-deser.md) | verified | high | 2026-11-08 |
| [WebLogic T3 反序列化基础利用（CVE-2015-4852）：握手后拼接 fe010000+aced0005 序列化流直接投递 ysoserial 链](web-java-component-weblogic-t3-deserialization-cve-2015-4852.md) | verified | high | 2026-11-13 |
| [WebLogic 域内 JDBC 连接密文解密：读 jdbc xml + SerializedSystemIni.dat 还原数据库口令](web-java-component-weblogic-jdbc-cipher-serializedsystemini-decrypt.md) | verified | high | 2026-11-08 |
| [WebLogic 控制台默认弱口令登录 → 部署页安装恶意 WAR → JSP WebShell 获取 root 权限（原文 Docker 环境）](web-java-component-weblogic-console-weak-password-war-deploy-shell.md) | verified | high | 2026-11-13 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
