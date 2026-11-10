---
id: web-generic-xxe-java-netdoc-file-directory-listing
title: Java XXE 用 netdoc/file 协议读取文件并列举目录
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-java-netdoc-file-directory-listing
aliases:
- netdoc 协议 XXE
- Java XXE 列目录
- netdoc 读文件
- file 协议列目录
- Java XXE 协议
tags:
- xxe
- java
- netdoc
- file-protocol
- file-read
- directory-listing
- protocol
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T05:53:42+08:00'
  notes: 已对照原文核对；图09 file:///d:/1.txt、图10 netdoc:/d:/1.txt 读文件结果 {XXE=XXE ATTACK}、图11 netdoc:///var/www/html/ 返回 pass.html/index.html/LCTF.php 等目录项与卡内 PoC 一致；协议支持表（图06）含 netdoc；原文未在 Java Web 目标上打通 OOB，仅本地演示
---

## 一句话结论

Java 解析器的 XXE 除了 `file://` 之外还支持 Java 私有的 `netdoc:` 协议：`netdoc:/path/file` 与 `file://` 一样读取文件内容，`netdoc:///目录/` 则会把目录项列表返回在响应里；先列目录定位文件，再逐个读取，是在 Java 目标上做 XXE 文件读取与信息收集的实用组合。

## 原理

- **Java 的 URL 协议表**：Java 内置协议包括 `http`、`https`、`ftp`、`file`、`jar`、`netdoc`、`mailto`、`gopher`（gopher 需额外开关）。XML 解析器把 SYSTEM 标识符交给 `URL`/`URI` 处理，因此这些协议都能出现在外部实体里。
- **netdoc 与 file 等价**：`netdoc:` 是 JDK 内部使用的文档协议（历史上 Javadoc 之类场景用），读取文件时与 `file:` 走同一套本地文件访问，所以 `<!ENTITY xxe SYSTEM "netdoc:/d:/1.txt">` 能把文件内容展开进 XML 文本节点。
- **目录列举**：对目录路径发起 `netdoc:///var/www/html/` 时，Java 返回目录项列表（文件名/子目录名），该列表可被实体展开进响应。攻击者据此确定 Web 根目录、配置文件与可读文件，再改为读取具体文件；原文同时提到 `file://` 对目录也可以列举（取决于 JDK 实现与版本）。
- **为什么有用**：盲猜路径成本高；先列目录能快速定位 `WEB-INF`、配置文件、备份、源码与密钥文件，把 XXE 从“读单个已知文件”扩展为“目录级信息收集”。
- **前提是回显**：目录列表与文件内容都作为实体值进入 XML 文档，需要应用把解析结果/错误信息回显，或配合外部 DTD 做 OOB。

## 触发条件

- Java 应用解析用户可控 XML，未禁用 DOCTYPE/外部实体。
- 解析结果或错误信息能把实体内容带回给攻击者（有回显），或可配合 OOB 外带。
- 进程对目标路径有读/列目录权限。

## 利用步骤

1. 用 `netdoc:/已知文件` 验证协议可用（如 Windows `netdoc:/d:/1.txt`、Linux `netdoc:/etc/passwd`）。
2. 把 SYSTEM 指向目标目录（如 `netdoc:///var/www/html/`），提交 XML，观察响应中的目录项列表。
3. 根据列表选择配置文件、源码、备份、密钥等目标，逐个改为 `netdoc:/完整路径` 读取。
4. 若 `netdoc` 被过滤，换 `file://`（目录列举能力视 JDK 而定）；仍不行时改用参数实体 + 外部 DTD 做 OOB。

## PoC

读取文件：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE XDSEC [
  <!ENTITY xxe SYSTEM "netdoc:/d:/1.txt">
]>
<XDSEC><XXE>&xxe;</XXE></XDSEC>
```

列举目录（响应中返回 `/var/www/html/` 下的文件名列表）：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "netdoc:///var/www/html/">
]>
<creds><user>&xxe;</user></creds>
```

## 变体与关联

- **协议变体**：`file:///etc/passwd` 读文件；`netdoc` 读文件/列目录；`jar:http://host/a.jar!/path` 会下载 zip 到临时文件、解压指定条目后删除临时文件（文件名未知、后缀 `.tmp`，利用价值低且可被用于 zip 炸弹，不推荐）。
- **无回显**：改用参数实体 + 外部 DTD 把内容拼进 URL 外带，见 [[web-generic-xxe-oob-exfil]]；Java 场景外带通道选择见本批 FTP 卡。
- **有回显文件读取基础**：[[web-generic-xxe-inband-file-read-default-insecure]]。
- **边界**：解析器禁用外部实体、进程无权限、路径不存在、或回显被截断时失败。

## 检测与防御

- **解析器加固**：禁用 DOCTYPE 与外部实体（`disallow-doctype-decl=true`、禁用 external-general/parameter entities）。
- **协议限制**：如业务必须解析 XML，可在解析前拒绝 SYSTEM 中的 `netdoc:`/`file:`/`jar:` 等非 HTTP 协议（但不能替代禁用外部实体）。
- **检测**：请求体中的 `netdoc:`/`file:` 关键字与目录路径；响应中出现目录项列表或敏感文件内容；Java 进程异常读取目录。
- **权限**：以低权限账户运行服务，限制可读目录与敏感文件 ACL。
