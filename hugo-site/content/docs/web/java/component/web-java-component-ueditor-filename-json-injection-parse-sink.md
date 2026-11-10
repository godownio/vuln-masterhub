---
id: web-java-component-ueditor-filename-json-injection-parse-sink
title: UEditor Java 上传文件名 JSON 注入：BaseState 字符串拼接污染下游 JSON 解析与 fastjson
type: scenario
domain: web
path: web/java/component
technique: ueditor-java-filename-json-injection-parse-sink
tags:
- java
- ueditor
- json-injection
- filename
- fastjson
- autotype
- file-upload
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:22:17+08:00'
  notes: 已对照原文与图片核对：BaseState#toString 的字符串拼接 sink、ActionEnter UPLOAD_FILE→Uploader.doExec→BinaryUploader.save、originFileName 仅按最后 . 后缀校验白名单、putInfo(original) 回显原文件名、调试器 state.infoMap 出现 original=flag","vulnerable":"hacked","a":".txt 均与原文一致；下游 fastjson parseObject 污染与 UploadServiceImpl 截图一致。未验证点：原文 filename 中带 @type 的 fastjson payload 语法细节未展开，卡片按注入字段描述并指向既有 fastjson 卡；未复跑。UEditor 未给受影响版本，affected_versions 已 --clear。
url: /docs/web/java/component/web-java-component-ueditor-filename-json-injection-parse-sink/
draft: false
kb_aliases:
- UEditor JSON 注入
- BaseState toString 拼接
- filename JSON 注入
- ueditor 文件名注入
- BinaryUploader originFileName
- ueditor fastjson
---

## 一句话结论

UEditor Java 的 `BaseState#toString()` 用字符串 `+` 手工拼接返回的 JSON，其中 `original` 等字段来自上传文件的原文件名；把 multipart filename 构造成 `flag","vulnerable":"hacked","a":".txt` 既能通过 `.txt` 后缀白名单，又把额外的 JSON 字段注入到返回字符串里；下游若用 fastjson 等库解析该字符串，注入的 `@type`/业务字段会被当作真实数据，可能导致 autotype 反序列化或覆盖关键属性。

## 原理

- **拼接式 JSON 生成**：`BaseState#toString()` 遍历 `infoMap`，执行 `builder.append("\"" + key + "\": \"" + value + "\"")` 生成 JSON，全程没有转义。`value` 来自上传流程存入的 `original`（原始文件名）、`url`、`title` 等字段。
- **文件名进入 infoMap**：`ActionEnter#invoke` 在 `UPLOAD_FILE` 时调用 `Uploader#doExec`，后者调用 `BinaryUploader#save`。`BinaryUploader#save` 中：
  ```java
  String originFileName = fileStream.getName();          // multipart filename
  String suffix = FileType.getSuffixByFilename(originFileName);
  originFileName = originFileName.substring(0, originFileName.length() - suffix.length());
  // validType(suffix, allowFiles) 只检查后缀
  storageState.putInfo("original", originFileName + suffix);
  ```
  后缀取最后一个 `.` 之后的部分，白名单只校验它；因此 `flag","vulnerable":"hacked","a":".txt` 的 suffix 是 `.txt`（通过），而 `originFileName` 保留了前半段注入字符。
- **注入后的 JSON**：`putInfo("original", ...)` 得到的值进入拼接模板后变成
  `"original": "flag","vulnerable":"hacked","a":".txt",`
  即合法的额外键 `vulnerable`（值 `hacked`）与 `a`（值 `.txt`）被插入 JSON 对象。
- **下游危害取决于解析方**：若开发者按官方用法直接返回字符串，没有解析，则不构成漏洞；若为了增删字段而 `JSON.parseObject(json)`（常见 fastjson）或自定义解析，则注入的字段会进入解析结果：
  - 注入 `@type` 相关字段，配合目标 fastjson 版本的 autotype/expectClass 条件，触发反序列化 gadget（例如 commons-io 文件写）；
  - 注入与业务同名的字段（如 `filepath`、`url`、`title`），覆盖后续文件操作使用的属性，造成任意文件写/覆盖；
  - 注入嵌套对象改变类型，使下游逻辑进入非预期分支。
- **为什么选择 filename**：multipart 的 filename 是少数能同时控制“后缀校验输入”和“返回 JSON 字段内容”的位置；UEditor 把原文件名回显到 `original`，拼接时不转义，形成注入面。

## 触发条件

- 使用 UEditor Java 版本（`ActionEnter`/`BaseState` 拼接实现），且上传动作 `UPLOAD_FILE` 可达。
- `fileAllowFiles` 中存在一个可用的后缀（如 `.txt`、`.png`），攻击者能在 filename 中放入该后缀并注入引号/逗号等字符。
- 应用在 `new ActionEnter(request, rootPath).exec()` 之后解析返回的 JSON（fastjson/Jackson/自定义），且解析结果影响后续敏感操作。
- 目标 fastjson 版本/配置存在可利用的 autotype 条件，或下游有可被覆盖的属性（filepath 等）。

## 利用步骤

1. 确认 `/ueditor?action=uploadfile`（或对应配置的上传路由）可用，且有权限（部分 CMS 要求先登录 admin）。
2. 用原始 multipart 请求（便于控制 filename 字节）上传任意文件，filename 设为：
   ```text
   flag","vulnerable":"hacked","a":".txt
   ```
3. 观察返回 JSON 是否含有注入的 `"vulnerable":"hacked"` 与 `"a":".txt"` 字段，确认注入生效。
4. 根据下游解析逻辑构造利用：
   - 目标解析后用 fastjson 且存在 autotype 条件：在 filename 中注入带 `@type` 的对象/字段，按 fastjson 版本套用文件写 gadget；
   - 下游用注入字段做文件路径/URL：把 `filepath` 等属性覆盖为攻击者想要的值，再触发文件操作。
5. 验证危害（文件写入/命令执行/属性覆盖），必要时组合后续模板写入或反序列化链。

## PoC

```http
POST /ueditor?action=uploadfile HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="flag","vulnerable":"hacked","a":".txt"
Content-Type: text/plain

test
------x--
```

```json
// UEditor 返回的字符串（注入后大致形态）
{"state": "SUCCESS","original": "flag","vulnerable":"hacked","a":".txt","size": "4", ... }
```

说明：注入后的返回字段与调试器截图一致；下游 fastjson 利用需按目标版本/依赖选择 gadget，本文靶场最终用 fastjson + commons-io 文件写覆盖 Beetl 模板。未在本机复跑。

## 变体与关联

- **下游 fastjson 入口**：UEditor `config.json` 被 `parseObject` 解析的入口见 [[web-java-deser-fastjson-ueditor-config-json-file-sink]]；本卡是另一个 source（上传 filename → BaseState 返回串）。
- **fastjson 文件写 gadget**：commons-io `TeeInputStream`/`WriterOutputStream` 等任意文件写链见 [[web-java-deser-fastjson-1268-autocloseable-expectclass-file-rw]]；文件写升级 RCE 的落地点见 [[web-java-deser-fastjson-file-write-to-rce]]。
- **Beetl 模板**：靶场把文件写落到 beetl 模板，再通过白名单绕过 RCE，见 [[web-generic-ssti-beetl-custom-whitelist-static-test-mutation]]。
- **其他 UEditor 问题**：`filePathFormat` 路径穿越见 [[web-generic-file-upload-ueditor-filepathformat-traversal]]；.NET 版 catchimage/上传问题见 web/generic/file-upload 下相关卡。
- **边界**：应用不解析 UEditor 返回串、filename 被框架提前规范化/拒绝引号、后缀白名单无可用类型、下游 JSON 库不支持 autotype 且无可覆盖属性时，本链不成立。

## 检测与防御

- **组件**：升级/替换 UEditor（已停止维护）；不要直接使用 `ActionEnter.exec()` 的字符串作为可信 JSON；如需增删字段，用安全的 JSON 库解析并重新序列化（而不是拼接）。
- **输入**：对 multipart filename 做严格白名单（只允许字母数字、点、下划线、短横线），拒绝引号、逗号、花括号、反斜杠；校验完整文件名而非仅后缀。
- **下游**：fastjson 关闭 autotype/SafeMode、升级到安全版本；对解析后的字段做类型与范围校验，文件路径使用固定目录 + 白名单。
- **检测**：上传请求 filename 中出现 `"`、`,`、`{`、`}`、`@type` 等 JSON 元字符；UEditor 返回串中出现非预期字段（`vulnerable`、`@type`）；随后 fastjson/文件操作异常。
