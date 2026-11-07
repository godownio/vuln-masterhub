---
id: defense-detection-tomcat-memshell-scanner-arthas
title: Tomcat 内存马排查：java-memshell-scanner 枚举组件 + Arthas sc/jad 定位 + Copagent 规则扫描
type: scenario
domain: defense
path: defense/detection
technique: tomcat-memshell-live-detection
tags:
- java
- tomcat
- memshell
- detection
- arthas
- copagent
- java-memshell-scanner
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V76
  verified_at: '2026-11-05T16:50:28+08:00'
  notes: 已对照原文与 img/24-44 核对：img/25 scanner 列出 filter/servlet 及 '磁盘上没有对应 class 文件'；img/26-31 Arthas sc *.Servlet、jad、sc -d、code-source 与 classLoaderHash；img/32-34 Copagent cop.jar 生成 result.txt 与可疑 java；img/36-44 sc/jad -c/options save-result/result.log 正则过滤均与卡内步骤一致。PoC 未在本机执行；无版本区间。
url: /docs/defense/detection/defense-detection-tomcat-memshell-scanner-arthas/
draft: false
kb_aliases:
- Tomcat 内存马检测
- java-memshell-scanner
- Arthas sc jad 内存马
- Copagent 内存马排查
- Servlet Filter Listener 内存马排查
---

## 一句话结论

对 Tomcat 内存马，先用 `java-memshell-scanner` 这个 JSP 枚举 `StandardContext` 里的 Servlet/Filter/Listener，并重点标记“磁盘上没有对应 class 文件”的组件；若 JVM 可 attach，再用 Arthas 的 `sc`/`sc -d`/`jad` 按接口与 classloader 反编译确认，Copagent 则按规则批量 dump 可疑类；三者互为补充。

## 原理

- Tomcat 把组件实例与映射保存在 `StandardContext`：Servlet 对应 children/Wrapper，Filter 对应 `filterDefs`/`filterMaps`/`filterConfigs`，Listener 对应 `applicationEventListenersList`。正常组件由 WebappClassLoader 从 `WEB-INF/classes` 或 JAR 加载，类有可解析的磁盘资源；内存马通常是 JSP 匿名内部类（JasperLoader 加载，类名以 `$1` 结尾）或运行时 `defineClass` 生成的类，`getResource` 找不到对应 class 文件，这是最直接的判别特征。
- `java-memshell-scanner` 以 JSP 运行在目标应用内，直接遍历上述容器结构，输出 name/pattern/class/classloader/class file path，并提供 dump 与 kill 操作；kill 的原理就是反向调用容器的移除 API。
- Arthas 通过 Attach API 读取 JVM 已加载类：`sc` 按模式列出类，`sc -d` 显示 classloader、code-source、是否匿名类等详情，`jad` 反编译字节码；同一类被多个 classloader 加载时会出现多条记录，需用 `classLoaderHash` 区分。
- Copagent 基于 Arthas，按包名、接口、注解、是否有磁盘资源、是否含恶意关键字等规则扫描全量类，并 dump 可疑类供人工反编译；其定位是自动化初筛，不能替代人工确认。

## 触发条件

- 目标为 Servlet 容器（文章以 Tomcat 为例），排查者拥有与目标进程相同权限或可 attach 的权限；
- JSP 型 scanner 需要目标应用能解析 JSP 且能写入/访问一个 JSP（Spring Boot fat jar 等无 JSP 场景不适用）；
- Arthas/Copagent 需要 attach 通道可用（`.java_pid<PID>` 等）；攻击者开启防检测后 attach 可能失败，需转 heap dump；
- Copagent 主要适用于 JDK 1.8。

## 利用步骤

1. 将 `tomcat-memshell-scanner.jsp` 放到可访问、可执行的路径并请求，查看 Filter/Servlet/Listener 三张表。
2. 重点标记：`class file path` 为空或提示“在磁盘上没有对应 class 文件”、类名带 `$` 的匿名类、Filter 的 pattern 为 `/*`、classloader 为 `JasperLoader`、以及陌生/伪装成框架的类名。表格中的 `dump` 可导出 class，`kill` 可移除。
3. 若需进一步确认，attach Arthas：运行 `java -jar arthas-boot.jar`，选择目标进程；用 `sc *.Servlet`、`sc *.Filter`、`sc *Listener` 列出组件实现类。
4. 对可疑类执行 `sc -d <类名>`，查看 `code-source`、`class-loader`、`isAnonymousClass`；同名多 classloader 时记下 `classLoaderHash`，再用 `jad -c <hash> <类名>` 反编译，检查 `service`/`doFilter`/`requestInitialized` 是否读取参数并执行命令。
5. 需要批量筛选时先 `options save-result true`，结果写入 `{user.home}/logs/arthas-cache/result.log`；用 `interfaces\s+javax\.servlet\.Servlet\s*$`、`interfaces\s+javax\.servlet\.Filter\s*$` 等正则过滤。也可直接 `sc -d javax.servlet.Servlet\*`、`sc -d javax.servlet.Filter\*`、`sc -d javax.servlet.ServletRequestListener\*` 三连查；单次结果超过 100 条时 Arthas 不返回，需缩小包名或加 `-n 200`。
6. 对 JSP 注入型，`sc -d org.apache.jsp.<jsp名>` 可查看其 `code-source`，定位并删除攻击者上传的 JSP；对组件型，根据 scanner 结果 kill 或反向从 `StandardContext` 移除。
7. 若 attach 被防检测阻断，改用 Copagent 或 heap dump 离线分析；Copagent 运行 `java -jar cop.jar`，选择进程后会在当前目录生成 `result.txt` 与可疑 java 文件，人工反编译确认。

## PoC

```text
# java-memshell-scanner
http://target/tomcat-memshell-scanner.jsp

# Arthas
java -jar arthas-boot.jar
sc *.Servlet
sc *.Filter
sc *Listener
sc -d <可疑类名>
jad -c <classLoaderHash> <可疑类名>
options save-result true
# 日志：{user.home}/logs/arthas-cache/result.log
# 正则：interfaces\s+javax\.servlet\.Servlet\s*$

# Copagent（JDK 8）
java -jar cop.jar
```

## 变体与关联

- 变体：Agent 型内存马（transformer 改写字节码）用 `vmtool` 读取 `InstrumentationImpl` 的 transformer 列表并结合 `jad`/`dump` 还原，见 [[defense-detection-arthas-agent-memshell-detect-remove]]。
- 变体：attach 被阻断或需要离线取证时，见 [[defense-forensics-java-memshell-heapdump-bytecode]]。
- 原版 scanner 主要覆盖 servlet-api 型；社区更新版补充 Valve、WebSocket、Timer、Upgrade、Executor 等类型。
- 关联攻击卡：[[web-java-component-tomcat-standardcontext-servlet-memshell]]、[[web-java-component-tomcat-dynamic-filter-memshell]]、[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-valve-memshell]]。

## 检测与防御

- 检测特征：无磁盘 class 文件的 Wrapper/Filter/Listener；`JasperLoader` 加载的 `*$1` 匿名类；未在 `web.xml`/注解声明的 URL 映射；`filterName` 形如“类简名+时间戳”；`/*` 过滤且类名伪装成框架类；JSP 访问后出现新的内存组件。
- 防御：最小化 JSP 与动态注册能力，Web 目录只读；部署 RASP/Java Agent 监控 `StandardContext.addChild`/`addServletMapping`/`addFilterDef`/`addApplicationEventListener` 等调用；保留 Arthas/Copagent/scanner 作为应急工具并限制其访问权限；处置时删除入口 JSP、移除内存组件并修复根因，单纯重启只能暂时清除。
- 注意：scanner 本身是 JSP，上传与访问会留下日志和文件，排查时应使用受控路径并在结束后删除；Arthas attach 会在 `/tmp` 留下 `.attach_pid`/`.java_pid` 痕迹。
