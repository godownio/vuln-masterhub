---
id: web-java-deser-fastjson-file-write-to-rce
title: Fastjson 任意文件写转 RCE：计划任务、JSP、JRE jar/classes、SPI 与 tomcat-docbase 落地点
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-file-write-to-rce
tags:
- java
- fastjson
- deserialization
- file-write
- rce
- jar
- jsp
- spi
- tomcat
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-04'
updated: '2026-11-04'
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-file-write-to-rce/
draft: false
kb_aliases:
- Fastjson 写文件 RCE
- fastjson 任意文件写 getshell
- 写 jar 覆盖 charsets.jar
- ascii jar
- tomcat-docbase 写 class
- jre classes SPI
---

## 一句话结论

Fastjson 高版本链常先拿到任意文件写；要把写文件升级为 RCE，需要按部署形态和权限选择落地点：root 下的 cron/sshkey、非纯 jar 部署的 JSP webshell、覆盖 JRE `lib` 下的 jar（如 `charsets.jar`）、写 JRE classes 或 classes+SPI、以及 Tomcat docbase class，其中 jar/classes 类方法基本只在 JDK8 下好用。

## 原理

任意文件写只证明能改磁盘，不等于能执行代码。要形成 RCE，必须让写入的文件被某个“之后会加载它”的组件消费：

- **计划任务 / SSH key**：写 `/etc/cron.d/*`、`/var/spool/cron/root`、`~/.ssh/authorized_keys`，由系统定时器或 sshd 执行；通常需要 root。
- **JSP webshell**：写到 Web 根目录，由容器编译执行；只适用于传统 WAR/目录部署，不适用于纯 jar（Spring Boot fat-jar 无 JSP 编译）。
- **覆盖 JRE lib jar**：JDK8 的 `jre/lib/charsets.jar` 等会被启动类加载器加载，替换为含恶意类的 jar，在下次启动/类加载时执行；不能写二进制时可用 ASCII jar 保持 zip 结构。
- **写 JRE classes**：把 class 写入 `jre/classes`（JDK8 扩展目录），需要目录存在且有入口点触发类加载。
- **classes + SPI**：写 class 与 `META-INF/services/<接口>`，由 ServiceLoader 在组件扫描时加载；同样依赖 JDK8 的扩展/类路径行为。
- **tomcat-docbase class**：写 Tomcat docbase 下的 class，由特定 WebappClassLoader 加载，基本限定在 Fastjson 利用场景。

这些路径都要求写入位置可预测、进程可读/可执行，且目标组件会在之后加载；JDK 版本、部署方式、权限决定可用性。

## 触发条件

- 已通过 Fastjson 链获得任意文件写（如 1.2.68 的 AutoCloseable/commons-io、1.2.80 的 jackson+io）；
- 知道目标部署形态（fat-jar/WAR/外部 Tomcat）、JDK 版本、运行用户权限；
- 写入路径可预测且未被只读挂载；
- 所选落地点有后续加载/执行时机（重启、类加载、请求、定时任务）。

## 利用步骤

1. 确认写文件原语与可写路径；读取 `/etc/passwd`、`/proc/self/cmdline`、`java.class.path` 等判断用户与部署形态。
2. 按场景选落地点：
   - root + Linux：写 cron 或 authorized_keys；
   - WAR/目录部署：写 JSP webshell；
   - JDK8：覆盖 `jre/lib/charsets.jar`（或写 `jre/classes`、SPI）；
   - Spring Boot/Tomcat：写 docbase class 或结合 ClassLoader 链；
3. 生成对应文件（jar 需保持 zip 结构；二进制写不了时用 ASCII jar）；
4. 触发加载：等待重启/类加载、访问 JSP、等待 cron、SSH 登录；
5. 验证命令执行并清理落地点。

## PoC

无统一 PoC；按落地点给出最小形式：

```text
# cron（root）
/etc/cron.d/pwn:  * * * * * root /bin/bash -c 'id > /tmp/pwn'

# ssh key
~/.ssh/authorized_keys: <attacker public key>

# JSP（WAR/目录部署）
webapps/ROOT/pwn.jsp: <% Runtime.getRuntime().exec(request.getParameter("c")); %>

# JDK8 覆盖 jar（概念）
copy evil.jar -> $JAVA_HOME/jre/lib/charsets.jar

# SPI
classes/evil/Impl.class + META-INF/services/<interface>=evil.Impl
```

## 变体与关联

- JDK8 限制：`jre/lib` jar 覆盖、`jre/classes`、SPI 扩展目录在 JDK9+ 的模块化后基本失效；新版本需换其他落地点。
- 纯 jar 部署无 JSP：优先考虑 jar 覆盖/classes/SPI/tomcat-docbase，或写内存马而非文件马。
- 写文件链来源：[[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]、[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]；不出网 jar 落地可参考 fd/jar:file 卡。
- 关联：[[web-java-deser-fastjson-fd-jar-no-egress-rce]]、[[web-java-deser-fastjson-file-protocol-no-egress-rce]]。

## 检测与防御

- 检测：Web 进程写入 `/etc/cron*`、`~/.ssh`、`jre/lib`、`jre/classes`、`META-INF/services`、Tomcat docbase；出现新 jar/class/JSP；异常重启后外连。
- 防御：Web 进程低权限、只读根文件系统、禁止写 JRE/系统目录；禁用不必要的 JSP/上传；升级 Fastjson 与依赖；运行时监控 `defineClass` 与类路径变化。
- 注意：文件写转 RCE 强依赖环境，不能仅凭“能写文件”判断已 getshell；需验证加载/执行时机。
