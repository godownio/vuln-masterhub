---
id: web-java-classloader-jsp-runtime-dropper-write-jsp-av-evasion
title: JSP 运行时释放器：Base64 内嵌 JSP 写入 webroot 的临时落地免杀与自毁
type: scenario
domain: web
path: web/java/classloader
technique: jsp-runtime-dropper-write-jsp
aliases:
- JSP 动态写入免杀
- JSP dropper
- JSP 释放器
- 临时 JSP 落地
- Base64 内嵌 JSP
- getRealPath 写马
- 运行时生成 webshell
tags:
- java
- jsp
- webshell
- dropper
- av-evasion
- filesystem
- tomcat
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V686
  verified_at: '2026-11-13T16:07:37+08:00'
  notes: 已通读content.md并读取唯一图01：阿里云检测结果表，webshell 哈希48f62a017f513800c38c0814405a75e 判定 WHITE/正常，与原文'已过了阿里云的检测'及卡内'原文样本被阿里云判为WHITE/正常'一致。原文Base64内嵌JSP（解码后为自定义ClassLoader U.g→defineClass + AES-CBC key e45e329feb5d925b + BASE64Decoder 读请求行，冰蝎式马）经 Files.write(getRealPath("/")+className+".jsp") 落盘、重启消失、随机文件名、file.remove 自毁、集成环境getRealPath可能不可用等细节均与卡一致。已修正自毁方向：原文'在下面可以增加一个file.remove的方法，进行文件的删除，类似于启动后自毁'指生成的临时JSP使用后删除自身，卡内原写'删除投放器'已改为'生成的临时JSP首次使用后file.delete()删除自身'，并同步staging/knowledge的PoC注释（原PoC注释错删投放器）。版本：原文无受影响版本声明，未设affected_versions（正确）。WebSocket Endpoint 部分作者按dedup merge跳过（已有 web-java-classloader-websocket-endpoint-memshell 同注册链），合理。dedup除自身exact外，top候选 Nashorn/BCEL(0.907)、gzip+defineClass(0.899)、echo写马fallback(0.884)、JSP源码层trim/闭合绕过(0.886/0.893)、webroot discovery(0.875) 均非同链，无重复可删。未实机复现；frontmatter无sources/source_url。
---

## 一句话结论

在一个不含 `Runtime.exec`/`eval` 等明显 webshell 特征的 JSP 里内嵌 Base64 编码的完整 JSP 马，请求时解码并用 `Files.write(request.getServletContext().getRealPath("/") + "/name.jsp", bytes)` 写入 webroot，随后访问新文件即可获得功能完整的 webshell；初始投放文件在磁盘上只有 Base64 blob（原文样本被阿里云判为 WHITE/正常），临时 JSP 可在重启后消失，也可在首次使用后 `file.delete()` 删除自身实现“自毁”，缺点是会在文件系统与访问日志留下痕迹，集成/打包环境下 `getRealPath` 可能不可用。

## 原理

- **JSP 就是可执行投放器**：JSP 由容器编译成 Servlet 后执行，运行在 Web 应用进程中，拥有该进程对 webroot 的读写权限；`request.getServletContext().getRealPath("/")` 返回 webroot 的绝对路径（war 解包/目录部署时有效），`Files.write` 把字节数组写成新的 `.jsp` 文件。
- **为什么能免杀**：静态查杀通常匹配 webshell 的敏感结构（`Runtime.getRuntime().exec`、`ProcessBuilder`、`eval`、冰蝎/哥斯拉特征等）。投放器里只有 Base64 字符串和文件写入逻辑，恶意 JSP 文本在运行时才解码落盘，磁盘上的初始文件不具备完整 webshell 特征，因此可被判为正常（原文截图显示 webshell 哈希判定 WHITE/正常）。该效果依赖具体 AV 引擎与特征库，不是通用保证。
- **为什么落盘后能执行**：容器对 webroot 下的 `.jsp` 按普通 JSP 处理，首次访问时编译执行；写入的 payload 可以是任意 JSP 马（原文内嵌的是“自定义 ClassLoader + AES 解密请求行 + defineClass”的 JSP 马），因此功能不受投放器限制。
- **痕迹与生命周期**：文件系统会新增 `.jsp` 文件；访问日志会记录投放器与新 JSP 的请求；JSP 编译缓存（如 Tomcat `work` 目录）也会留下 class。重启后若 webroot 未被持久化（容器重建/只读镜像），临时文件消失；原文建议在生成的临时 JSP 中使用后 `file.delete()` 删除自身（“启动后自毁”），投放器本身也可在写完后清理以少留痕。
- **限制**：Spring Boot 等内嵌容器打包成 fat jar 时 `getRealPath` 可能返回 null 或临时目录；webroot 只读/无写权限时失败；部分容器禁止运行时写入 JSP 目录。

## 触发条件

- 已能上传/写入一个 JSP 文件，或已有一个可执行 JSP 入口（上传漏洞、文件写入、已有 webshell）。
- Web 应用以目录或解包 war 部署，`getRealPath("/")` 可用且 webroot 可写。
- 容器未禁用 JSP 编译，或写入目录是容器认可的 JSP 路径。
- 目标 AV/WAF 未对 JSP 运行时写文件行为做行为拦截（静态查杀可被 Base64 内嵌绕过）。

## 利用步骤

1. 准备最终 payload JSP（功能完整的 webshell），整体 Base64 编码后嵌入投放器 JSP 的字符串常量。
2. 上传/写入投放器 JSP 到目标可访问路径。
3. 访问投放器，触发解码与 `Files.write`，在同目录生成 `name.jsp`。
4. 访问新生成的 JSP，用约定的口令/协议执行命令。
5. 可选：随机化文件名；在生成的临时 JSP 中首次执行后 `file.delete()` 删除自身（原文所述“启动后自毁”）；结束前清理投放器与新 JSP。

## PoC

最小投放器（payload 为占位 Base64，实际替换为完整 JSP 文本）：

```jsp
<%@ page import="java.nio.file.*,java.util.Base64,java.io.File" %>
<%
    String className = "myshell";
    byte[] bytes = Base64.getDecoder().decode("PCVAcGFnZS ... 内嵌 JSP 的 Base64 ...");
    File root = new File(request.getServletContext().getRealPath("/"));
    root.mkdirs();
    Files.write(Paths.get(root.getAbsolutePath() + "/" + className + ".jsp"), bytes);
    // 可选自毁：在生成的 JSP 内执行后 new File(application.getRealPath(request.getServletPath())).delete();
%>
```

访问 `dropper.jsp` 后再访问 `/myshell.jsp` 即可；原文用该方法生成的 JSP 马被阿里云判定为 WHITE/正常。

## 变体与关联

- [[web-java-classloader-jsp-memory-servlet-webshell]]：JSP 内用自定义 ClassLoader 在内存注册 Servlet；本卡是落盘 JSP，二者可组合（内存马不留文件，释放器留临时文件）。
- [[web-java-classloader-gzip-base64-dnslog-jsp-webshell]]：JSP 内嵌 `base64(gzip(class))` 直接 defineClass；本卡是内嵌完整 JSP 文本落盘，再次请求才执行。
- [[web-java-classloader-websocket-endpoint-memshell]]：另一种“JSP 投放后注册内存马”的免落地形态。
- 变体：多层套娃（投放器内嵌投放器）；文件名随机化；写入 `upload`/`static` 等可执行目录；把 payload 换成冰蝎/哥斯拉 JSP 或 AES 自解密马；写完后删除投放器。
- 边界：文件系统与日志留痕；重启/容器重建可能清除；`getRealPath` 在 fat jar 部署下不可靠。

## 检测与防御

- 检测：webroot 出现运行期新增的 `.jsp` 文件（文件完整性监控/EDR 文件写入事件）；JSP 中出现 `Files.write`/`FileOutputStream` 写 `.jsp` 或 Base64 大字符串；访问日志中“先访问一个 JSP、随后出现的新 JSP 被立即访问”的模式；JSP 编译缓存出现无源码对应或源码只有 Base64 的 class。
- 防御：webroot 只读挂载；禁止应用进程写 JSP 目录；上传目录与可执行目录隔离；关闭不需要的 JSP 支持；RASP/WAF 监控 JSP 运行时写文件与动态 JSP 编译；AV 结合行为检测而非仅静态特征。
