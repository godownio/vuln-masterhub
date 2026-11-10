---
id: defense-detection-tomcat-lib-disguised-jar-filter-memshell-static-hunt
title: Tomcat lib 伪装 jar 静态排查：tomcat-i18n-bk.jar 内的 ServletContainerInitializer + Filter cmd 参数内存马
type: scenario
domain: defense
path: defense/detection
technique: tomcat-lib-disguised-jar-filter-memshell-static-hunt
tags:
- java
- tomcat
- memshell
- filter
- jar
- webshell
- detection
- incident-response
- awd
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:40:28+08:00'
  notes: 已对照原文与图07-14核对：ps 定位 /tomcat、webapps/ROOT/.shell.jsp 的 backdoor 参数 JSP、lib/tomcat-i18n-bk.jar 3330 字节 May 2 2023（其余 Apr 14）、jadx 见 MainFilterInitializer/ServletFilter getParameter("cmd")+Runtime.exec、?cmd=whoami 返回 tomcat 均一致；未复跑。
url: /docs/defense/detection/defense-detection-tomcat-lib-disguised-jar-filter-memshell-static-hunt/
draft: false
kb_aliases:
- tomcat-i18n-bk.jar
- Tomcat lib 后门 jar
- 伪装 i18n 的 Filter 内存马
- ServletContainerInitializer Filter 后门
- AWD 组件后门排查
---

## 一句话结论

攻击者可在 Tomcat 的 `lib/` 放入一个伪装成官方国际化包的恶意 jar（如 `tomcat-i18n-bk.jar`），其中 `ServletContainerInitializer` 在启动时注册一个 Filter，Filter 读取请求参数 `cmd` 并 `Runtime.exec` 回显；排查时按 jar 修改时间/大小与官方发行包比对，再用 jadx 反编译搜索 `Filter`、`getParameter("cmd")`、`Runtime.exec`，即可定位并清除。

## 原理

- Tomcat 启动时会扫描 `lib/` 下的 jar，并按 `META-INF/services/javax.servlet.ServletContainerInitializer`（或 `@HandlesTypes`）加载 `ServletContainerInitializer` 实现。攻击者把恶意 jar 放进 `lib/`，其中 `MainFilterInitializer` 的 `onStartup` 用 `ServletContext.addFilter`/`addMappingForUrlPatterns` 动态注册 Filter，不需要改 `web.xml`，也不落 JSP。
- 恶意 Filter 类（原文样本为 `org.apache.tomcat.ServletFilter`）在 `doFilter` 中读取 `servletRequest.getParameter("cmd")`；非空时执行 `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})`，把进程输出写入响应；为空时调用 `filterChain.doFilter` 放行，因此正常访问不受影响，隐蔽性强。
- 该 jar 常伪装成 Tomcat 官方 `tomcat-i18n-*.jar`（如 `tomcat-i18n-bk.jar`，`bk` 不在官方语言包列表），文件很小（原文 3330 字节）、修改时间晚于其他官方 jar（原文 May 2 2023，其余 Apr 14 2023）。用 `ls -la` 按时间/大小排序即可发现异常。
- 与运行时 Arthas/内存马扫描不同，这是"磁盘上的组件后门"：即使 JVM 刚重启，恶意 Filter 仍会被注册；只查 JSP 或只查内存中的可疑类会漏掉。清除必须删除 jar 并重启，否则下次启动又注册。
- 同一入口常伴随隐藏 webshell（原文 `webapps/ROOT/.shell.jsp`，以点开头的隐藏文件），JSP 通过 `request.getParameter("backdoor")` 执行命令；两者需一起清理。

## 触发条件

- 目标为 Tomcat（或其他会扫描 `lib/` 中 `ServletContainerInitializer` 的 Servlet 容器）。
- 攻击者已获得文件写入权限（上传、反序列化写文件、供应链替换等）并向 `lib/` 放入恶意 jar。
- 容器已重启或热加载使 `ServletContainerInitializer` 执行；之后任意访问带 `cmd` 参数的路径即可触发 Filter。
- 排查者有服务器文件读取/命令执行权限与反编译工具（jadx、IDEA、JD-GUI）。

## 利用步骤

1. 定位 Tomcat：`ps -aux | grep tomcat` 或 `ps -ef | grep java`，从 `-Dcatalina.home`、`-Djava.util.logging.config.file` 等参数确认安装目录。
2. 列出 `lib/` 并核对时间/大小：`ls -la /tomcat/lib/ | sort -k6,7`；重点看非官方命名（`tomcat-i18n-bk.jar`）、体积异常小、修改时间晚于其他官方 jar 的文件。
3. 与官方发行包对比：官方 `tomcat-i18n-*.jar` 语言列表固定（de/es/fr/ja/ko/ru/zh-CN 等），`bk` 等不在列表；也可比对 SHA-256/文件大小。
4. 反编译可疑 jar：`jadx tomcat-i18n-bk.jar`，检查是否含 `ServletContainerInitializer`/`MainFilterInitializer` 与 `implements Filter` 的类，搜索 `getParameter`、`Runtime.exec`、`/bin/sh`、`ProcessBuilder`。
5. 验证：请求 `/?cmd=whoami`（或任意路径带 `cmd`），若返回命令输出（原文返回 `tomcat`），确认 Filter 内存马生效。
6. 清理：删除恶意 jar、删除 `webapps/ROOT` 下隐藏 JSP（`ls -la` 查看 `.shell.jsp` 等点文件）、恢复被替换的 `index.jsp`/HTML，重启 Tomcat；复查 `lib/` 与 `webapps`，确认无残留。
7. 溯源：检查 jar 的写入时间与上传/反序列化/供应链入口，修复初始写入点。

## PoC

```bash
# 1. 定位 Tomcat 与 lib 目录
ps -aux | grep -E 'tomcat|java'
ls -la /tomcat/lib/ | sort -k6,7

# 2. 发现异常 jar（非官方语言包、体积小、时间新）
# -rw-rw-r-- 1 tomcat tomcat 3330 May  2 2023 tomcat-i18n-bk.jar

# 3. 反编译检查
jadx tomcat-i18n-bk.jar
# 关注 org.apache.tomcat.ServletFilter#doFilter：
# String cmd = servletRequest.getParameter("cmd");
# Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});

# 4. 触发验证
curl 'http://target:8080/?cmd=whoami'
# 返回 tomcat（或其他命令输出）

# 5. 清理
rm -f /tomcat/lib/tomcat-i18n-bk.jar
rm -f /tomcat/webapps/ROOT/.shell.jsp
# 恢复 index.jsp 与页面文件后重启 Tomcat
```

## 变体与关联

- 变体：jar 伪装成其他官方组件名（`catalina-*.jar`、`tomcat-util-*.jar`），或用 `META-INF/services` 注册 `ServletContainerInitializer` 而非注解；按类内容而非文件名判断。
- 变体：恶意代码也可能是 Listener/Valve/Filter 组合；排查时同时搜索 `implements Filter`、`implements ServletContextListener`、`implements Valve`。
- 关联：[[defense-detection-tomcat-memshell-scanner-arthas]]（运行时枚举 Filter/Servlet 并识别磁盘无对应 class 的内存马）、[[defense-detection-tomcat-filter-memshell-hotpatch-vmtool-remove]]（已确认 Filter 内存马后的不重启热拔除）、[[web-java-component-tomcat-dynamic-filter-memshell]]（Filter 内存马的攻击侧注册原理）。
- 边界：容器不扫描 `lib/` 的 `ServletContainerInitializer`、jar 未被加载、或排查者无文件读取/反编译权限时，需改用运行时 Arthas/内存马扫描。

## 检测与防御

- 检测：`lib/` 中出现非官方命名、体积异常、修改时间新的 jar；jar 内出现 `ServletContainerInitializer`/`Filter` 且含 `getParameter("cmd")`、`Runtime.exec`、`/bin/sh`；访问任意路径带 `cmd` 参数返回命令输出；`webapps` 下有点开头的隐藏 JSP。
- 防御：限制应用目录与 `lib/` 的写权限，Web 进程以低权限运行；对 `lib/` 做文件完整性监控（哈希/清单基线）与变更告警。
- 防御：修复上传、反序列化、表达式注入、供应链等初始写入入口；容器镜像/发布包做签名验签（见 JAR 重打包签名校验卡）。
- 加固：定期用 `ls -la`/哈希清单核对官方 jar；发现后删除并重启，同时排查 `webapps`、`conf`、`bin` 下的其他持久化。
