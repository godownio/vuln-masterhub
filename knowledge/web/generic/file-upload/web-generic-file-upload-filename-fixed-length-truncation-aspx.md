---
id: web-generic-file-upload-filename-fixed-length-truncation-aspx
title: 上传文件名固定长度截断绕过后缀校验：.aspx 放进保留前缀、末尾补 .txt 落盘为 ASPX
type: scenario
domain: web
path: web/generic/file-upload
technique: filename-fixed-length-truncation-extension-bypass
aliases:
- 文件名截断上传
- 文件名过长溢出
- 固定长度截断 aspx
- 上传后缀绕过
- IIS ASPX 上传
- 1sssssss.aspxaaaaaaaa.txt
tags:
- web
- file-upload
- extension-bypass
- truncation
- aspnet
- iis
- webshell
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T12:03:40+08:00'
  notes: 已对照原文与 61 张图核对（本卡相关图 10-15、50-51）：后台 /admin/file_upload.aspx 对 InputAffixFile 原始 filename 做后缀白名单，.aspx 被拒（图10 弹窗）；Burp 中 1.aspx.txt 与 1sssssss.aspx123123.txt 可上传（图11/50-51）；管理上传文件列表落盘名为 638545863914255191-6sssssss.aspx、638545762532922546-1sssssss.aspx 等，时间戳后保留 14 字符（图13）；访问 /upfile/affix/638545863914255191-6sssssss.aspx 成功（图14/97 行 URL）。卡片『校验名≠落盘名、固定 14 字符截断、.aspx 放在前缀、末尾补 .txt』成立；截断长度由落盘列表反推（原文未给保存代码），已在卡内标注。dedup 实跑 top1 为自身 exact，其余 related（extension-zero-check 无白名单、avatar 前端校验、eis 反斜杠截断、ccflow IIS web.config）均非同链；dup-scan 与 14448/16512/16521 的 pair 均 related，不合并。未验证点：未复现上传。
---

## 一句话结论

当上传接口“先按原始文件名校验扩展名、保存时却把文件名截断到固定长度”时，攻击者把 `1sssssss.aspxaaaaaaaa.txt` 这类文件名提交上去：校验阶段看到的是允许的 `.txt`，落盘阶段只保留前 14 个字符 `1sssssss.aspx`，文件因此以 `.aspx` 结尾并被 IIS 当脚本执行。

## 原理

- **校验与落盘使用不同的字符串**：上传页 `/admin/file_upload.aspx` 对 multipart 字段 `InputAffixFile` 的原始 `filename` 做扩展名白名单，`.txt`/`.jpg` 通过，`.aspx` 被拒绝并弹“该文件不允许上传！”。但保存时程序只取文件名的一个固定长度前缀，再拼上时间戳/编号作为最终文件名。
- **截断长度可观测**：多次上传后，“管理上传文件”列表中的落盘名形如 `638545863914255191-6sssssss.aspx`、`638545762532922546-1sssssss.aspx`，时间戳后保留的原文件名部分恰好 14 个字符。对照上传时的 `6sssssss.aspx123123.txt`，可确认服务器保留的是前 14 字符，`.txt` 被截掉。
- **双扩展名构造**：把可执行后缀放在前 14 个字符内、把允许的后缀放在末尾：`1sssssss.aspxaaaaaaaa.txt`。前 14 字符为 `1sssssss.aspx`（1 个字符 + 8 个 `s` + `.aspx`），原始扩展名 `.txt` 通过白名单；落盘名截断后以 `.aspx` 结尾，IIS 的 ASPX handler 会解析执行。
- **为什么不是普通双扩展名**：普通 `shell.aspx.txt` 在 IIS 上通常按 `.txt` 静态处理；本漏洞的关键是“落盘名被截断”，扩展名在保存阶段被改变，而不是依赖 IIS 解析顺序。
- **路径与访问**：文件落在 `/upfile/affix/`，落盘名包含时间戳/编号前缀，可从后台“管理上传文件”列表直接看到，或用目录扫描/报错路径推断；上传成功后通过 `/upfile/affix/<落盘名>` 访问。

## 触发条件

- 上传接口使用原始文件名做扩展名白名单，但保存时对文件名做固定长度截断（数据库列长度、`Substring`、文件名长度限制等）。
- 截断长度大于“可执行后缀 + 少量填充”的长度，且截断点落在攻击者可控字符范围内。
- Web 服务器会把落盘后的扩展名映射到脚本引擎（IIS + ASP.NET，`.aspx`/`.ashx`/`.asmx` 等），且上传目录允许执行脚本。
- 攻击者已能访问上传功能（本例为后台登录后的“文件上传”）。
- 落盘名/路径可枚举或可从后台列表获得。

## 利用步骤

1. 登录后台，进入“文件上传”，先上传 `.txt`/`.jpg` 确认允许的类型，再上传 `.aspx` 确认被拒绝（弹窗“该文件不允许上传！”）。
2. 用 Burp 拦截 multipart 请求，观察字段名（本例 `InputAffixFile`）与原始 `filename`。
3. 构造文件名：`1sssssss.aspx` + 填充字符 + `.txt`，使前 14 个字符正好以 `.aspx` 结尾；填充长度可按“固定长度 - 可执行后缀长度”调整。
4. 放行请求，响应 302 到 `file_upload_prs.aspx` 表示处理成功；到“管理上传文件”列表查看实际落盘名（时间戳/编号 + 截断后的前缀）。
5. 访问 `/upfile/affix/<落盘名>`，确认 ASPX 被解析（可用 `<%@ Page Language="C#" %><% Response.Write("test"); %>` 测试）。
6. 将测试内容替换为冰蝎/哥斯拉等免杀马或自定义 ASPX 代码，连接 webshell。

## PoC

```http
POST /admin/file_upload.aspx HTTP/1.1
Host: target:27689
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="__VIEWSTATE"
<viewstate>
------x
Content-Disposition: form-data; name="InputAffixFile"; filename="1sssssss.aspxaaaaaaaa.txt"
Content-Type: text/plain

<%@ Page Language="C#" %><% Response.Write("upload-test"); %>
------x--
```

```text
落盘结果（后台列表）：
638545863914255191-1sssssss.aspx

访问：
http://target:27689/upfile/affix/638545863914255191-1sssssss.aspx
→ 页面输出 upload-test，说明 ASPX 被解析
```

## 变体与关联

- 变体：截断长度不同（10/14/20 等），按落盘名反推；可执行后缀换成 `.asp`、`.ashx`、`.asmx`、`.config`（视 IIS handler 配置）。
- 变体：数据库列长度截断、`Path.GetFileNameWithoutExtension` 后再拼接、`Substring(0, N)`、文件名长度上限等不同实现，最终都是“校验名 ≠ 落盘名”。
- 变体：结合 NUL 字节、分号、空格、Unicode 截断；IIS 6 的 `/x.aspx/` PATH_INFO 解析也可作为二次利用。
- 关联：`[[web-generic-file-upload-ashx-method-dispatch-frontend-js-unauth-aspx]]`（ASHX 方法分发上传）、`[[web-java-component-tomcat-rfc2231-filename-char-truncation-jsp-upload]]`（文件名截断的 Java/Tomcat 版本）、`[[web-generic-file-upload-zip-entry-nul-windows-truncation]]`（ZIP 条目 NUL 截断）。
- 边界：若保存时使用的是随机名 + 原扩展名、或上传目录禁止脚本执行、或 IIS 未映射对应 handler，该链不成立；文章未给出后端保存代码，截断长度 14 由落盘列表反推。

## 检测与防御

- 检测：上传请求中的 `filename` 同时含可执行后缀与允许后缀（如 `.aspx...txt`）；落盘目录出现以 `.aspx/.ashx/.asmx` 结尾的新文件；后台列表出现时间戳/编号 + 可疑前缀的文件名。
- 修复：校验与保存必须使用同一个规范化后的文件名；保存时重新取扩展名并做白名单（不要截断后不再校验）；使用随机文件名 + 固定扩展名，原始文件名只存数据库。
- 加固：上传目录禁止脚本执行（IIS 请求筛选/处理程序映射移除脚本权限）；文件类型按内容（magic/解析）校验；上传接口加鉴权、审计与病毒扫描；对 `web.config` 等敏感文件禁止上传。
- 响应：发现可疑 ASPX 立即隔离主机、保留样本与访问日志，排查同目录其他 webshell 与后续命令执行痕迹。
