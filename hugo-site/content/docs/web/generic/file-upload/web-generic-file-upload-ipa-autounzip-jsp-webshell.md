---
id: web-generic-file-upload-ipa-autounzip-jsp-webshell
title: 上传白名单放行 ipa：IPA 自解压把包内 JSP 释放到 Web 目录 getshell
type: scenario
domain: web
path: web/generic/file-upload
technique: ipa-autounzip-jsp-whitelist-bypass
tags:
- file-upload
- java
- spring
- multipart
- ipa
- zip
- extraction
- webshell
- whitelist-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V39
  verified_at: '2026-11-05T06:25:13+08:00'
  notes: 已对照原文25张图核对：MultipartResolver uploadTypes 白名单含 ipa/zip（图04）、uploadFile ios 分支落盘 basePath+upload\ios\+原名（图03/10）、IpaUtil.getPlistFile 将 .ipa 替换 .zip 并解压到去后缀目录（图06/07）、ZipUtils.unZip 直接 new File(destDir+entryName) 无条目扩展名校验（图07）、上传 111.ipa 后访问 upload/ios/111/11.jsp 返回 1+1=2（图11-13）。未验证点：PoC 未本机复跑；原文未标注产品与版本，已清除 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-ipa-autounzip-jsp-webshell/
draft: false
kb_aliases:
- IPA 自解压上传
- ipa 解压 getshell
- zip 白名单绕过后缀限制
- MultipartFile 解压写 JSP
- ipa 包内 JSP
- 压缩包释放 webshell
---

## 一句话结论

上传接口的全局白名单允许 `.ipa`（底层是 ZIP），服务端在解析 iOS 包时把 `.ipa` 改名为 `.zip` 并直接解压到 Web 根目录下的 `upload/ios/<文件名>/`，解压过程不检查条目扩展名；因此把 `11.jsp` 打进 IPA 上传，就会被释放成可访问、可解析的 JSP，绕过只检查上传文件后缀的白名单。

## 原理

- 上传入口 `POST .../upload.action` 接收 `MultipartFile file` 与 `type` 参数；Spring 的 `MultipartResolver` 配置了全局 `uploadTypes` 白名单：`jpg,jpeg,gif,xls,cyt,zip,bmp,png,apk,ipa,crt,plist,p12,txt`。`.ipa` 与 `.zip` 都在白名单内。
- `McuManageService.uploadFile` 先按 `type` 分支把文件写到 `basePath + "upload\\ios\\" + file.getOriginalFilename()`；随后 `parseIOSPackage(ipaFile)` 调用 `IpaUtil.getPlistFile(ipaPath)`。
- `getPlistFile` 把路径中的 `.ipa` 替换为 `.zip`，复制一份 ZIP，然后 `ZipUtils.unZip(zipPath, unZipDir)`，解压目录是去掉 `.zip` 后缀的路径；解压后再读取 plist。
- `ZipUtils.unZip` 遍历 `ZipEntry`，对每个条目执行 `new File(destDir + zipEntry.getName())` 并写出文件，**不检查条目扩展名，也不校验路径是否越界**。因此包内的 `11.jsp` 会原样落到 `upload/ios/<上传文件名>/11.jsp`。
- 由于解压目录位于 Web 应用根目录下，JSP 容器会正常解析该文件；上传时的白名单只看外层 `.ipa` 后缀，看不到包内的 `.jsp`。
- 该链的关键不是 ZIP 解析漏洞，而是“**检查对象（外层文件名）**”与“**实际落盘对象（压缩包内条目）**”不一致；任何允许上传压缩包并自动解压到 Web 目录的功能都有同样风险。

## 触发条件

- 存在允许 `.ipa`/`.zip` 等压缩包的上传接口，且上传目录位于 Web 根目录内。
- 服务端上传后会自动解压（iOS 包解析、批量导入、主题安装等），解压逻辑不校验条目扩展名与路径。
- 目标使用 JSP/Servlet 容器，解压目录可被请求并解析。
- 攻击者可访问上传接口并提交 multipart 请求（是否需要登录取决于业务，原文未明确）。

## 利用步骤

1. 创建一个 ZIP，放入 `11.jsp`（内容可为 `1+1=2` 或 webshell）。
2. 把 ZIP 后缀改为 `.ipa`，构造 multipart 上传请求，`type=ios`。
3. 服务端把文件写入 `upload/ios/111.ipa`，解析时复制为 `.zip` 并解压到 `upload/ios/111/`。
4. 访问 `.../upload/ios/111/11.jsp`，确认 JSP 被解析执行。
5. 若要稳定控制，把 JSP 内容换成命令执行/回连载荷；上传文件名可用随机名，路径按响应或目录规则推断。

## PoC

上传请求：

```http
POST /aaa/bbb/ccc/upload.action HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="type"

ios
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="111.ipa"
Content-Type: application/octet-stream

<1.ipa 的二进制内容>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

`1.ipa` 内部结构：

```text
11.jsp      (18 bytes，内容可为 <% out.print(1+1); %>)
admin.png   (0 bytes)
```

访问：

```http
GET /aaa/upload/ios/111/11.jsp HTTP/1.1
Host: target
```

响应 `1+1=2`，说明 JSP 已被容器解析执行。

## 变体与关联

- 变体：压缩包条目名使用 `../` 可进一步目录穿越（`ZipUtils.unZip` 未做规范化校验），把 JSP 写到其他 Web 目录；原文未演示，但代码层面成立。
- 变体：上传的 `originalFilename` 被直接拼进 `upload\\ios\\` 后，若文件名含 `../` 也可能目录穿越/覆盖；原文仅提到“还可以目录穿越文件覆盖”，未给出 PoC。
- 变体：其他允许的压缩格式（zip、apk、ipa）都可能承载 JSP；取决于服务端是否有对应解压逻辑。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（同属“解压写 Web 目录”，那条依赖 `../` 条目名，本条依赖白名单只检查外层后缀）。
- 关联：[[web-generic-file-upload-content-type-trust-bypass]]、[[web-generic-file-upload-magic-byte-gif-prefix-bypass]]（同为上传校验维度错位）。

## 检测与防御

- **检测**：上传目录中出现压缩包解压产生的 `.jsp/.jspx/.php` 等可执行文件；IPA/ZIP 上传后紧跟对同目录新文件的请求；上传文件名与解压目录名一致且内部含脚本文件。
- **检测**：检查 `ZipEntry` 名称是否含 `../`、绝对路径、脚本扩展名；监控 Web 根目录下 `upload/*` 目录的新增脚本文件。
- **修复**：解压前遍历条目，拒绝绝对路径、`..`、符号链接及非白名单扩展名；解压到 Web 根目录之外的独立目录，再用受控方式提供静态文件；上传后对 ZIP 内容做类型/扩展名扫描。
- **加固**：上传目录禁止脚本解析（Nginx/Apache/Tomcat 配置），文件重命名为随机名且不保留原扩展名；限制上传接口权限与文件大小；对 IPA/APK 解析使用沙箱。
