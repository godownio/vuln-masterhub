---
id: web-java-component-kkfileview-compress-zipslip-arbitrary-write
title: kkFileView 4.2.0–4.4.0-beta 压缩包预览 Zip Slip：zip 条目 ../ 拼接到 hack.zip_ 缓存目录后未校验，任意文件写入
type: scenario
domain: web
path: web/java/component
technique: kkfileview-compress-preview-zipslip-write
affected_versions: 4.2.0 - 4.4.0-beta
tags:
- web
- java
- kkfileview
- zip-slip
- path-traversal
- arbitrary-file-write
- spring-boot
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:10:10+08:00'
  notes: 已对照原文与 10 张截图核对：OnlinePreviewController#onlinePreview 的 base64 url 解码链路、CompressFilePreviewImpl#filePreviewHandle 调 DownloadUtils.downLoad+unRar、CompressFileReader#unRar 中 folderName/extractPath/str[0]/str1 与 FileOutputStream(extractPath+folderName+\_\+File.separator+str[0], append=true) 未校验路径、hack.zip_ 缓存目录、E:\AAA\flag 内容 test_Yu9、PoC zip 构造(必须含正常 test 条目)均有截图佐证；affected_versions 按原文标题与正文'4.2.0 到4.4.0-beta'保留 4.2.0 - 4.4.0-beta。原文写 cron/启动项仅为思路未演示，卡片已如实标注，skipped 成立；未被验证点：未在本机复跑
url: /docs/web/java/component/web-java-component-kkfileview-compress-zipslip-arbitrary-write/
draft: false
kb_aliases:
- kkFileView 任意文件上传
- kkFileView Zip Slip
- CompressFileReader unRar 路径穿越
- hack.zip_ 缓存目录
- kkFileView 压缩包预览 RCE
---

# 一句话结论

kkFileView 4.2.0–4.4.0-beta 的压缩包在线预览流程中，`cn.keking.service.CompressFileReader#unRar` 解压 zip 条目时把条目名直接拼接到 `extractPath + folderName + "_" + File.separator + str[0]` 后创建并写入文件，未对 `..` 做归一化或目录边界校验；攻击者上传含 `../../../../.../AAA/flag` 条目的 zip 并触发预览（`/onlinePreview?url=<base64(zip URL)>`），即可把任意内容写到 kkFileView 进程有权限的任意路径（案例写到 `E:\AAA\flag`）。Linux 高权限下可写 cron、Windows 高权限下可写启动项，进一步 RCE（文章仅给出思路，未演示）。

# 原理

- **入口链路**：`cn.keking.web.controller.OnlinePreviewController#onlinePreview` 接收 base64 编码的 `url`，`WebUtils.decodeUrl` 解码后由 `fileHandlerService.getFileAttribute(fileUrl, req)` 获取文件属性，`previewFactory.get(fileAttribute)` 按类型选到 `CompressFilePreviewImpl`，最后调用 `filePreview.filePreviewHandle(fileUrl, model, fileAttribute)`。
- **下载与解压**：`CompressFilePreviewImpl#filePreviewHandle` 先 `DownloadUtils.downLoad(fileAttribute, fileName)` 把目标文件下载到本地得到 `filePath`，再调用 `compressFileReader.unRar(filePath, filePassword, fileName)`。
- **漏洞点**：`unRar` 中
  - `folderName = paths.substring(paths.lastIndexOf(File.separator) + 1)`（如 `hack.zip`），
  - `extractPath = paths.substring(0, paths.lastIndexOf(File.separator))`；
  - 遍历 `inArchive.getSimpleInterface().getArchiveItems()`，对每个非目录条目取 `str[0] = RarUtils.getUtf8String(item.getPath())`，把 `\` 替换为 `File.separator`；
  - `str1 = str[0].substring(0, str[0].lastIndexOf(File.separator) + 1)`，`new File(extractPath, folderName + "_" + File.separator + str1).mkdirs()`；
  - `new FileOutputStream(extractPath + folderName + "_" + File.separator + str[0], true)` 写出条目数据。
- **为什么能穿越**：`str[0]` 完全来自压缩包条目名，最后写文件时只是字符串拼接 `extractPath + folderName + "_" + File.separator + str[0]`，没有 `getCanonicalPath()` 比较，也没有拒绝 `..`/绝对路径。`hack.zip_` 前缀拼在路径中间并不能阻止 `../` 逐级上跳，最终落在 `extractPath` 之外。
- **为什么 zip 里要有正常文件**：预览流程会先创建/使用 `hack.zip_` 缓存文件与目录，放一个正常条目（如 `test`）可让流程顺利走到解压与写出；恶意条目再随解压写出到穿越路径。
- **危害放大**：写入内容与目标路径都由攻击者控制。在高权限服务（root/SYSTEM）下，写 `/etc/cron.d/`、`/var/spool/cron/`、Windows 启动目录或计划任务文件即可获得命令执行；即便权限受限，也可覆盖配置/模板/脚本造成破坏。

# 触发条件

- 目标暴露 kkFileView 4.2.0–4.4.0-beta 的在线预览接口，且攻击者可上传或让其引用一个可控的 zip 文件（上传本地文件预览功能或任意可托管 URL）。
- kkFileView 进程对穿越目标路径有写权限，且写入内容可控。
- 预览时文件被识别为压缩包类型（zip/rar/7z 等走同一 `unRar` 解压逻辑）。

# 利用步骤

1. 制作恶意 `hack.zip`：包含一个正常条目 `test`，以及条目 `../../../../.../AAA/flag`，内容任意。
2. 通过 kkFileView 的“上传本地文件预览”上传 `hack.zip`，页面显示 `demo/hack.zip`。
3. 点击“预览”，浏览器请求 `GET /onlinePreview?url=<base64("http://<kkfileview>/demo/hack.zip")>`。
4. 服务端下载 zip 并用 `unRar` 解压：先创建 `hack.zip_` 目录，随后把 `AAA/flag` 写到穿越后的绝对路径（案例 `E:\AAA\flag`，内容为 `test_Yu9`）。
5. 到目标路径确认文件内容与权限，判断可利用面。
6. 高权限场景：Linux 写入 `/etc/cron.d/` 或用户 crontab 文件、Windows 写入启动目录/计划任务，构造定时或开机执行实现 RCE。

# PoC

```python
import zipfile

if __name__ == "__main__":
    binary1 = b'test'
    binary2 = b'test_Yu9'
    zipFile = zipfile.ZipFile("hack.zip", "a", zipfile.ZIP_DEFLATED)
    zipFile.writestr("test", binary1)
    zipFile.writestr("../../../../../../../../../../../../../../../../../../../AAA/flag", binary2)
    zipFile.close()
```

```http
GET /onlinePreview?url=aHR0cDovLzEyNy4wLjAuMTo0MDEyL2RlbW8vaGFjay56aXA= HTTP/1.1
Host: target:8012
```

# 变体与关联

- **通用 Zip Slip**：[[web-generic-file-upload-zip-slip-webshell-write]]（解压穿越写 Web 根 getshell）；[[code-analysis-vuln-discovery-default-insecure-archive-extract-api]]（跨语言不安全解压 API 清单与 sink 识别）。
- **kkFileView 其他入口**：`getCorsFile` 任意文件读取与 SSRF，见 [[web-java-component-kkfileview-getcorsfile-bashhistory-cache-artifact]]、[[web-java-component-kkfileview-getcorsfile-urlpath-ssrf-file-read]]。
- **压缩格式变体**：rar/7z/tar 等同样进入 `unRar`/七牛解压路径；条目名编码会用 `RarUtils.isMessyCode` 做 GBK 转换，构造时可测试不同编码；Windows 下条目中的 `\` 会被替换为平台分隔符。
- **写入位置变体**：除绝对穿越到 `E:\AAA` 外，可按部署路径计算 `../` 数量写到 Web 目录、cron、启动项、SSH authorized_keys 等。

# 检测与防御

- **修复**：升级 kkFileView 至 4.4.0-beta 之后的修复版本；限制预览文件来源与上传类型。
- **安全解压**：解压前对每个条目做 `getCanonicalPath()` 校验，确保最终路径位于目标目录内；拒绝绝对路径与含 `..` 的条目；使用带 Zip Slip 防护的解压库。
- **运行隔离**：kkFileView 以低权限账号运行，上传/缓存目录不可执行，与敏感目录隔离；容器化并只读挂载系统目录。
- **检测**：预览/上传的 zip 条目含 `../` 或绝对路径；`/onlinePreview` 的 `url` 指向攻击者可控压缩包；kkFileView 进程在缓存目录之外创建文件；cron、启动目录、authorized_keys 等敏感文件异常变更。
