---
id: web-generic-file-inclusion-java-new-file-root-path-traversal-read
title: Java new File(root, path) + FileUtils.readFileToString 路径穿越读取任意文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: java-new-file-relative-path-traversal-read
aliases:
- new File(root, path) 路径穿越
- FileUtils.readFileToString 任意文件读取
- getFileText 穿越
- Java 文件读取接口穿越
- ../../db.conf 读取
- 相对路径拼接文件读取
tags:
- java
- path-traversal
- arbitrary-file-read
- file-read
- spring-mvc
- hibernate
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:11:30+08:00'
  notes: 已对照原文与图23-26核对：getFile 用 new File(root,path)、getFileText 用 FileUtils.readFileToString，controller /file/text 将内容放入 ResponseData；图26 回显 db.conf 多数据库凭据。原文请求带会话Cookie、未说明鉴权状态，卡内已注明不能默认未授权。原文未给产品/版本，无 versions。
---

## 一句话结论

Java 服务把请求参数 `path` 直接交给 `new File(root, path)`，再把结果传给 `FileUtils.readFileToString()` 时，`path` 中的 `../` 或绝对路径会把读取点带出 `root`；攻击者可读取应用配置、数据库口令、密钥等任意进程可读文件，并把内容直接回显在接口响应里。

## 原理

- `new File(File parent, String child)` 的语义是：若 `child` 是绝对路径，`parent` 被忽略；否则在 `parent` 后拼接 `child`。它只做字符串组合，不做规范化，也不检查结果是否仍在 `root` 内。
- 文件系统在打开文件时才解析 `.`、`..` 与符号链接；因此 `new File(root, "../../../../local/db.conf")` 最终指向 `root` 之外的路径。
- `FileUtils.readFileToString(file, ENCODING)`（Apache Commons IO）按给定文件读取全部内容，没有路径约束；控制器再把返回的字符串放进 `ResponseData.successData(...)`，形成有回显的任意文件读取。
- 很多实现误以为“`root` 是服务端常量，`new File(root, path)` 就安全”，但相对路径中的 `..` 与绝对路径都能逃逸；必须 `getCanonicalPath()`/`toRealPath()` 后校验结果仍以 `root` 为前缀，或改用文件 ID 映射。
- 同类危险 sink 包括 `Files.readAllBytes`、`Files.newInputStream`、`FileInputStream`、`readFileToString`、`IOUtils.toString` 等，只要路径来自用户且未做规范化包含校验。

## 触发条件

- 存在接受文件路径参数的读取接口（下载、预览、模板/资源读取、日志查看等）。
- 路径经 `new File(root, path)`、字符串拼接或 `Paths.get(root, path)` 进入文件读取 API，未做 canonical 包含校验。
- 接口可达；原文请求带会话 Cookie，鉴权状态未单独说明，不能默认未授权。
- 目标文件对应用进程可读；`root` 的实际层级决定 `../` 数量。
- 响应会返回文件内容或可观测的错误差异。

## 利用步骤

1. 找到接收 `path`、`file`、`fileName`、`resource` 等参数的读取接口，观察响应是否返回文件内容。
2. 先传 `path=test.txt` 确认基准目录，再逐步增加 `../`：`../`、`../../`、`../../../`，直到读到已知系统文件（如 `/etc/passwd`、`/local/db.conf`）。
3. 读取应用配置、数据库连接串、密钥、源码；Windows 下可试 `..\\..\\`、绝对路径、盘符。
4. 若接口对 `..` 有字符过滤，尝试 URL 编码、双重编码、`....//`、绝对路径、符号链接等变体。
5. 用读到的数据库口令、云凭据、SSH key 进一步横向；不要把“读到文件”直接等同于 RCE。

## PoC

```http
GET /api/portal/file/text?realmId=00000000-0000-0000-0000-000000000010&type=1&platform=1&path=../../../../../../local/db.conf HTTP/1.1
Host: target
X-Requested-With: XMLHttpRequest
Accept: */*
Cookie: <会话>
```

```text
预期响应（节选语义）：
{
  "success": true,
  "data": "# MySQL config ... url=jdbc:mysql://... user=root password=...\n
           # PostgreSQL config ...\n
           # SQL Server config ..."
}
```

```java
// 等价脆弱代码
File root = getPageRoot(portalRealmId, type, platform);
File file = new File(root, path);              // path 用户可控，无规范化/包含校验
return FileUtils.readFileToString(file, ENCODING);
```

## 变体与关联

- 变体（绝对路径）：`path=/etc/passwd` 直接忽略 `root`；Java `File` 在 Unix 上按绝对路径解析。
- 变体（编码/过滤绕过）：`%2e%2e%2f`、双重编码、`..%5c`、`....//`、Unicode 归一化；取决于框架是否提前解码与过滤顺序。
- 变体（Windows）：`..\\..\\`、`C:\\Windows\\win.ini`、短文件名、UNC 路径。
- 变体（sink 不同）：`Files.readAllBytes`、`FileInputStream`、`readFileToString`、模板加载、日志查看；原理相同。
- 关联：[[web-java-framework-ruoyi-download-resource-path-traversal]]（Java 下载接口穿越的产品实例）、[[web-generic-file-inclusion-python-os-path-join-absolute-traversal]]（跨语言的同类 `join` 语义陷阱）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（编码绕过变体）。
- 边界：若代码先 `getCanonicalPath()` 并校验 `startsWith(root + File.separator)`，或使用文件 ID 到真实路径的映射，则本原语失效；容器部署会把可读范围限制在容器文件系统内，但仍可读容器内配置与凭据。

## 检测与防御

- 修复：读取前对目标 `getCanonicalPath()`（或 `toRealPath()`），与 `root` 的 canonical 路径做前缀比较；拒绝绝对路径、`..`、符号链接；更彻底的做法是接口只接受文件 ID，由服务端查表得到路径。
- 加固：文件读取接口统一封装安全 API；`root` 使用不可绕过的 `Path.normalize()` + `startsWith` 校验；对 `path` 参数做长度与字符白名单。
- 权限：应用进程最小权限，配置文件与密钥目录不放在 Web 进程可读范围；数据库账号最小权限。
- 检测：请求参数含 `../`、`..\\`、`%2e%2e`、绝对路径、盘符；响应体出现 `/etc/passwd`、`db.conf`、`password=`、私钥头等特征；同一会话短时间内读取多个不同目录文件；文件读取接口的响应大小异常。
- 审计：搜索 `new File(`、`Paths.get(`、`readFileToString`、`readAllBytes`、`FileInputStream`，回溯参数是否来自 Controller 且未经过 canonical 校验。
