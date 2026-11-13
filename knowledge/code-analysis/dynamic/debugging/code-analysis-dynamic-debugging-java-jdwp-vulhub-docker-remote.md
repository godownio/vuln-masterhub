---
id: code-analysis-dynamic-debugging-java-jdwp-vulhub-docker-remote
title: Vulhub Java 漏洞环境 JDWP 远程调试：Dockerfile 追加 -agentlib:jdwp 暴露 5005，IDEA Remote JVM Debug 断点跟踪漏洞链
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: java-jdwp-docker-vulhub-remote-debug
aliases:
- Java 远程调试
- JDWP 调试
- IDEA Remote JVM Debug
- Vulhub 调试 Java 漏洞
- -agentlib:jdwp
- 5005 调试端口
tags:
- java
- jdwp
- remote-debugging
- docker
- vulhub
- idea
- dynamic-analysis
- vulnerability-research
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:54:16+08:00'
  notes: '已对照原文与5张图核对：图01 IDEA Remote JVM Debug（附加到远程 JVM/Socket/5005/agentlib 参数，JDK5-8）；图02 base/fastjson/1.2.24 下 src+Dockerfile+pom.xml；图03 docker-compose 启动日志 Listening for transport dt_socket at address: 5005；图04 断点命中 JSONController#getUser（user.setName 行）；图05 连接 192.168.3.129:5005 成功提示。卡片与攻击侧 pentest-initial-access-jdwp-exposed-jvm-debug-rce 的边界已在“变体与关联”写清（本卡为研究侧主动开启调试接入，攻击侧为暴露 JDWP 未授权 RCE，dedup 判 related/new 成立）。卡内 JDK9+ address=*:5005 与 JAVA_TOOL_OPTIONS 属补充的通用知识（原文只讲 JDK5-8），不影响原文事实。原文未标注组件版本，未设 affected_versions；severity low 与“调试技巧非漏洞”定位一致。dup-scan 无本卡 pair。未复跑 docker/IDEA 调试。'
---

## 一句话结论

对 Docker 化的 Java 漏洞环境（Vulhub 或自建镜像），在启动 JVM 的命令里追加 `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005` 并把 5005 端口映射出来，IDEA 用 Remote JVM Debug 的"附加到远程 JVM"模式连接，即可用与目标一致的本地源码下断点、单步跟踪漏洞触发链，无需额外安装调试组件。

## 原理

- **JDWP 是 JVM 间调试协议**：远程 JVM 以 `server=y` 在 `address=5005` 监听 dt_socket，本地 IDEA 作为调试客户端主动连接（Attach）；`suspend=n` 表示启动后不暂停等待调试器，`suspend=y` 则适合调试启动阶段。若反过来让远程 JVM 主动连 IDEA，则用 `server=n`（原文称"侦听远程 JVM"，类似正/反向连接）。
- **源码必须与目标字节码一致**：JDWP 断点按类名/行号解析，本地工程需与容器内 jar 的版本、依赖一致；否则断点落到错误行或无法命中。Vulhub 每个漏洞目录在 `base/<漏洞>/<版本>` 下同时提供源码、`Dockerfile` 与 `pom.xml`，便于保持版本一致。
- **改造点只在启动命令**：Vulhub 的 Dockerfile 通常会 `java -jar` 启动应用，在参数前插入 JDWP 参数即可；容器还需在 `docker-compose.yml` 中 publish 5005（或 `EXPOSE` + 映射）。
- **为什么先本地打包**：在容器内用 maven 重新打包 jar 速度慢，原文改为本地构建 jar 后 `COPY` 进镜像，或直接使用已打包源码+jar 的调试镜像项目；镜像构建一次后再次 `docker-compose up` 接近秒级。
- **调试效果**：容器日志出现 `Listening for transport dt_socket at address: 5005` 后，IDEA 连接成功；浏览器/请求触发漏洞时断点命中，可查看调用栈、参数与局部变量，定位 sink 与污染路径。

## 触发条件

- 目标应用以 JVM 运行且启动命令可控（能修改 Dockerfile/启动脚本或设置 `JAVA_TOOL_OPTIONS`）。
- 调试端与目标网络可达（本地 Docker、虚拟机或端口转发），且 5005 未被防火墙阻断。
- 本地拥有与目标一致的应用源码/依赖版本，IDEA 已配置对应模块 classpath。
- 仅用于授权的漏洞研究/本地实验环境。

## 利用步骤

1. 在漏洞目录（如 `base/fastjson/1.2.24`）查看 `Dockerfile`，找到 `java -jar` 启动命令。
2. 在 `java` 后插入 `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005`（JDK 9+ 容器内可写 `address=*:5005`；也可用环境变量 `JAVA_TOOL_OPTIONS`）。
3. 在 `docker-compose.yml` 增加 `5005:5005` 端口映射，`docker-compose up` 启动；确认日志出现 `Listening for transport dt_socket at address: 5005`。
4. IDEA 打开对应源码工程，`Run > Edit Configurations > Remote JVM Debug`，调试器模式选"附加到远程 JVM"，传输 `Socket`，Host 填目标 IP，Port 5005，模块类路径选源码模块；复制生成的命令行参数核对是否一致。
5. 浏览器/脚本发送触发漏洞的请求，在源码关键方法（如 controller、反序列化入口、sink）下断点，命中后查看调用栈与变量，逐步跟踪利用链。

## PoC

Dockerfile 启动参数（核心改动）：

```dockerfile
CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005", "-jar", "/app/app.jar"]
```

docker-compose 端口映射：

```yaml
services:
  vuln:
    build: .
    ports:
      - "8080:8080"
      - "5005:5005"
```

IDEA 远程 JVM 调试参数（JDK 5–8）：

```text
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```

启动后容器日志出现 `Listening for transport dt_socket at address: 5005`，IDEA 连接并在 `JSONController#getUser` 等断点处成功拦截请求。

## 变体与关联

- **等待调试器**：`suspend=y` 可调试启动初始化；`server=n` 为 IDEA 监听、远程 JVM 反连，适合目标只能出网的场景。
- **JDK 9+ 地址绑定**：容器内需 `address=*:5005` 才监听所有网卡，否则默认只绑 localhost。
- **不改镜像**：`JAVA_TOOL_OPTIONS=-agentlib:jdwp=...` 或 `docker run -e` 注入；K8s 可用 `kubectl port-forward` 把 5005 转到本地。
- **其他动态调试环境**：PHP 扩展 gdbserver 附加见 [[code-analysis-dynamic-debugging-php-extension-apache-gdbserver-zif-symbols]]；异构架构 QEMU+GDB 见 [[code-analysis-dynamic-debugging-heterogeneous-arch-qemu-gdb-multiarch]]。
- **同一参数的攻击面**：JDWP 若在生产/公网容器上开启并发布端口，即等价未授权 RCE，见 [[pentest-initial-access-jdwp-exposed-jvm-debug-rce]]；本卡只讲研究侧接入。
- **前置知识**：JDWP 协议与断点原理、漏洞环境搭建；本文只讲调试接入，不涉及具体漏洞利用。

## 检测与防御

- **防守检测**：监控 JVM 启动参数中的 `-agentlib:jdwp`/`jdwp:transport`、容器/主机对 5005 等调试端口的监听与外部连接；生产镜像禁止包含 JDWP 参数。
- **风险提示**：JDWP 没有认证与授权，任何能连接调试端口的人都能读取/修改目标 JVM 状态并执行代码，等同于远程代码执行；调试端口绝不能暴露到不可信网络。
- **研究注意**：只在本地/隔离的 Vulhub 或授权环境开启调试端口，调试结束关闭容器；不要把带 JDWP 的镜像推送到公共仓库或用于生产。
