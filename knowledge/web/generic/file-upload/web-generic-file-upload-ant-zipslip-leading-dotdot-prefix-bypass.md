---
id: web-generic-file-upload-ant-zipslip-leading-dotdot-prefix-bypass
title: Apache Ant 1.9.11 ZipSlip：startsWith('../') 用 './../../' 绕过 + 上传 filename 目录穿越覆盖 Enjoy 模板
type: scenario
domain: web
path: web/generic/file-upload
technique: ant-zipslip-leading-dot-slash-dotdot-bypass
aliases:
- Apache Ant ZipSlip
- ant 1.9.11
- startsWith ../ 绕过
- ./../../ 目录穿越
- zip-tools
- 上传 filename 穿越
- 模板覆盖 Enjoy
- SpringBoot %2e%2e
tags:
- java
- spring
- file-upload
- zip
- zip-slip
- path-traversal
- filter-bypass
- template
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: Apache Ant 1.9.11（原文标注题目环境版本）
verification:
  verified_by: verifier-V154
  verified_at: '2026-11-06T07:36:21+08:00'
  notes: 已对照原文与14张图核对：UploadService 以 while(filename.startsWith("../")) 跳过条目、./../../template/admin/hello.html 绕过（图05/11）；AdminController 用 getOriginalFilename() 拼接 target_filepath，filename=../template/admin.zip 可穿越并把 zip 落到模板目录（图06/07）；UserInterceptor replaceAll("//","/") 后 contains("..")/contains("./") 且仅放行 /index（图03），/index/%2e%2e/admin/upload 在 SpringBoot <=2.3.0.RELEASE 生效（图04）；JFinalViewResolver+Enjoy 模板目录 /usr/src/app/template（图01）。未验证点：未本地复跑 zip/上传；Ant 1.9.11 仅为原文标注的题目环境版本，无官方受影响区间；图11/12 上传响应与卡内描述一致。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

Java 上传接口用 Apache Ant 1.9.11 的 `ZipFile` 解压，虽然后端会跳过以 `../` 开头的条目，但没有对路径做规范化；条目名写成 `./../../template/admin/hello.html` 不以 `../` 开头，文件系统解析 `.`/`..` 后仍然穿越到模板目录并覆盖 `hello.html`。同一接口还直接把 multipart 的 `filename` 拼进保存路径，`../template/admin.zip` 可以把压缩包本身写进模板目录再解压，两条路都能把任意模板写到 Enjoy 模板引擎的加载路径下。

## 原理

- **ZipSlip 的检查点**：`UploadService.extractAllForZipFile` 遍历 `ZipEntry` 时用 `while (filename.startsWith("../"))` 跳过以 `../` 开头的条目。这个检查只匹配字符串前缀，不做路径规范化，也不解析 `.`/`..`。
- **前缀绕过**：`./../../template/admin/hello.html` 的第一个字符是 `.`，后面是 `/`，不满足 `startsWith("../")`；但操作系统把 `./` 当作当前目录、`..` 当作父目录，最终落点与 `../../template/admin/hello.html` 相同。类似地 `..././`、`....//` 等变体也可绕过不同实现的前缀/单次替换检查。
- **上传文件名穿越**：`/admin/upload` 的 `filename = file.getOriginalFilename()` 只校验后缀 `.(zip)$`，随后 `target_filepath = this.path + "/" + filename`；把 filename 设为 `../template/admin.zip`，目标路径就变成 `/usr/src/app/upload/../template/admin.zip`，即模板目录下的 `admin.zip`。`target_unzip_path = target_filepath.replace(".zip","")` 得到 `/usr/src/app/template/admin`，解压后 `hello.html` 直接落在模板目录，不需要条目名穿越。
- **模板加载位置**：应用用 JFinalViewResolver + Enjoy，`template.path=/usr/src/app/template` 在 jar 包外，`engine.setDevMode(true)` 且使用 `FileSourceFactory`；模板文件被覆盖后，下一次请求会重新读取并渲染恶意模板。
- **访问绕过**：`UserInterceptor` 对 `request.getRequestURI()` 做 `replaceAll("//","/")` 后检查 `contains("..")`/`contains("./")`，只放行 `/index` 或 `/`；请求 `/index/%2e%2e/admin/upload` 不含字面量 `..`，以 `/index` 开头，能通过拦截器。SpringBoot <= 2.3.0.RELEASE 在后续路由阶段会解码 `%2e%2e` 并规范化路径，最终命中 `/admin/upload`；更高版本需重新验证该 trick。
- **危害升级**：ZipSlip 本身是任意文件写；当写入目标是模板目录时，就变成模板注入。配合 Enjoy 的 `springMacroRequestContext` 对象链（见关联卡）可进一步 RCE；即使不 RCE，也可用模板包含读取 flag。

## 触发条件

- `/admin/upload` 等解压接口可达（可能需要 `%2e%2e` 绕过拦截器或已登录管理员）。
- 后端使用 Apache Ant 1.9.11 的 `ZipFile`/`ZipEntry`（或同类只做 `startsWith("../")` 检查的实现），未做 `getCanonicalPath`/`normalize` 与目标目录前缀校验。
- 上传目录与模板目录在同一文件系统上，且模板目录对 Web 进程可写。
- 上传 filename 未过滤 `../`，只校验扩展名/类型。
- 模板引擎从磁盘加载模板（Enjoy/JFinalViewResolver `FileSourceFactory`、devMode 或模板缓存失效），覆盖后会被渲染。

## 利用步骤

1. 用 `/index/%2e%2e/admin/upload` 访问上传路由，确认 `%2e%2e` 能绕过拦截器（SpringBoot <= 2.3.0.RELEASE）。
2. 制作恶意 zip：条目名 `./../../template/admin/hello.html`，内容为 Enjoy 模板 payload（如 `#include("../../flag")` 或后续 SSTI 链）。
3. 上传 zip，观察响应中的“解压后的文件”路径，确认模板被覆盖。
4. 备用路径：把上传 filename 设为 `../template/admin.zip`，zip 条目用普通 `hello.html`；服务端会把压缩包写到模板目录并解压到 `/usr/src/app/template/admin/`。
5. 访问 `/index/%2e%2e/admin/hello` 触发模板渲染；若 payload 是 SSTI，则执行命令/内存马；若 payload 是 `#include`，则读取目标文件。
6. 需要持久化时再上传内存马 class 并通过模板注入加载。

## PoC

用 Spring Integration Zip 构造带自定义条目名的压缩包（原文方式）：

```java
final ZipTransformer zipTransformer = new ZipTransformer();
zipTransformer.setWorkDirectory(new File(workDir));
zipTransformer.setBeanFactory(mock(BeanFactory.class));
zipTransformer.afterPropertiesSet();
zipTransformer.setUseFileAttributes(false);       // 允许自定义 ZIP_ENTRY_FILE_NAME

final File testFile = new File(evilPath);          // 恶意 hello.html
final String zipEntryFileName = "./../../template/admin/hello.html";
final Message<File> message = MessageBuilder.withPayload(testFile)
        .setHeader(ZipHeaders.ZIP_ENTRY_FILE_NAME, zipEntryFileName)
        .build();
zipTransformer.transform(message);
```

上传请求（`%2e%2e` 绕过拦截器）：

```python
import requests
upload_url = "http://<target>/index/%2e%2e/admin/upload"
with open("evil.zip", "rb") as f:
    requests.post(upload_url, files={"file": ("evil.zip", f)})
```

filename 穿越变体：

```http
POST /index/%2e%2e/admin/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=...

--...
Content-Disposition: form-data; name="file"; filename="../template/admin.zip"
Content-Type: application/zip

<zip 内容：hello.html>
--...
```

原文实测上传后响应回显 `./../../template/admin/hello.html` 与解压成功；本卡不执行 PoC。

## 变体与关联

- **前缀变体**：`./../../`、`....//`、`..././`、`..%2f`、反斜杠 `..\`；不同检查（startsWith、replace 一次、contains）对应不同绕法。
- **filename 穿越**：除 `../template/admin.zip` 外，还可用绝对路径、Windows 盘符、多级目录；关键是后端是否用 `getOriginalFilename()` 直接拼接。
- **其他归档格式**：tar 条目 `../`、符号链接/硬链接条目也能造成同样效果；参见关联的 Zip Slip/tar 卡片。
- **访问绕过**：`%2e%2e` 是 SpringBoot <=2.3.0.RELEASE 的路径规范化差异；更高版本可尝试 `;`、编码斜杠、`/index/..%2fadmin` 等，需按版本验证。
- **后利用**：模板覆盖后可走 Enjoy `springMacroRequestContext` → Spring Bean/ClassLoader → SpEL → 内存马（见 [[web-java-framework-spring-enjoy-template-springmacrocontext-spel-memshell]]）；也可用 `#include("../../flag")` 直接读文件。
- 关联：[[web-generic-file-upload-zipslip-template-overwrite-context-variable-leak]]、[[web-generic-file-upload-template-batchimport-zipslip-arbitrary-write]]、[[web-generic-file-upload-single-replace-dotdot-bypass]]、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]。

## 检测与防御

- **路径规范化**：解压前对每个条目名做 `Path.normalize()`/`getCanonicalPath()`，并校验结果仍位于目标目录内；拒绝绝对路径、`..`、符号链接/硬链接条目。不要只做 `startsWith("../")`。
- **上传文件名**：不要用 `getOriginalFilename()` 直接拼接保存路径；使用服务端生成的随机文件名 + 固定扩展名，保存目录固定。
- **模板目录**：模板目录对 Web 进程只读，上传/解压目录与模板目录隔离；不要 `setDevMode(true)` 或频繁重载不可信目录。
- **组件**：升级 Apache Ant/解压库到修复版本；使用官方安全解压 API；限制归档条目数量/大小/嵌套深度。
- **访问控制**：拦截器应基于 Spring 规范化后的路径（`HandlerMapping`/`RequestPath`）判断，而不是原始 `getRequestURI()`；升级 SpringBoot 到 >2.3.0.RELEASE 并启用 `StrictHttpFirewall`。
- **检测**：上传 ZIP 中出现 `./../`、`....//`、绝对路径条目；响应回显的解压路径跳出上传目录；模板文件被上传接口修改；`/index/%2e%2e/admin/*` 等编码路径访问日志。
