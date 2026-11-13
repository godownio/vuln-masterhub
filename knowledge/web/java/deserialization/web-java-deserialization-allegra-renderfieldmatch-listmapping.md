---
id: web-java-deserialization-allegra-renderfieldmatch-listmapping
title: Allegra renderFieldMatch 反序列化：ExcelFieldMatchBL 读取 listmapping 直接 ObjectInputStream.readObject（CVE-2024-22505）
type: scenario
domain: web
path: web/java/deserialization
technique: allegra-renderfieldmatch-listmapping-deserialization
aliases:
- CVE-2024-22505
- Allegra 反序列化
- ExcelFieldMatchBL renderFieldMatch
- listmapping 反序列化
- excelFieldMatch.action
- trackdata/excelImport
tags:
- java
- struts
- allegra
- trackplus
- deserialization
- objectinputstream
- rce
- cve-2024-22505
cve:
- CVE-2024-22505
affected_versions: Allegra < 7.5.1（原文明确）
severity: critical
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:19:13+08:00'
  notes: 已对照原文13184与截图核对：正文影响版本Allegra<7.5.1明确；img01 ZDI-24-106确认CVE-2024-22505=renderFieldMatch Deserialization of Untrusted Data RCE(9.8)；正文代码显示ExcelFieldMatchBL#renderFieldMatch对excelMappingsDirectory/getMappingFileName(entity)的FileInputStream直接ObjectInputStream.readObject并强转Map，路由/excelFieldMatch.action?fileName=1.xlsx&entity=list，需先经跨目录上传把文件放到Allegra/trackdata/excelImport/1/listmapping，卡与之一致。原文未给gadget与完整PoC，卡confidence medium且注明前置，适当。dedup候选JEXL/Camel/Datart等为不同入口sink，非同链。
---

## 一句话结论

Allegra 的 `/excelFieldMatch.action?fileName=1.xlsx&entity=list` 会进入 `ExcelFieldMatchBL#renderFieldMatch`，其中对 `excelMappingsDirectory/getMappingFileName(entity)` 指向的文件直接 `new ObjectInputStream(fis).readObject()`，没有类过滤/白名单；攻击者先用任意文件上传（CVE-2024-22510）把恶意序列化数据写到 `Allegra/trackdata/excelImport/<id>/listmapping`，再触发该接口即可反序列化执行代码（CVE-2024-22505，影响 < 7.5.1）。

## 原理

- **入口**：`renderFieldMatch(excelMappingsDirectory, fileName, entity, selectedSheet, personID, locale)` 由 `excelFieldMatch.action` 调用；`entity` 参数决定 `getMappingFileName(entity)`，示例 `entity=list` 对应 `listmapping`。
- **危险 sink**：代码先 `new File(excelMappingsDirectory, getMappingFileName(entity))` 打开 `FileInputStream`，再 `new ObjectInputStream(fis).readObject()` 并把结果强转为 `Map`。这里没有 `ObjectInputFilter`、类白名单或 `resolveClass` 限制，只要文件内容是可反序列化的 gadget 字节流就会在 `readObject` 阶段执行。
- **为什么需要先上传**：正常业务会把导入表格的映射序列化到 `listmapping`；攻击者无法直接写该文件，但可通过同产品的路径穿越上传（CVE-2024-22510 的 `fileToReplace` 可穿越到 `trackdata/excelImport/...`）或 zipslip（CVE-2024-22504）把恶意序列化文件落到预期路径。上传文件名后缀处理（`removeExtension + "." + ext`）可能追加后缀，需按目标文件系统调整参数或改用 zipslip 精确落盘。
- **利用条件**：目标 classpath 存在可利用反序列化 gadget（如 commons-collections 等），且 `listmapping` 文件内容能被 `readObject` 完整读取；页面路由可达、触发时不需要额外权限（原文未强调认证）。
- **危害**：反序列化在应用进程内执行，可直接 RCE；若 gadget 不可用，也可造成拒绝服务/类型混淆等，但本卡按 RCE 场景记录。

## 触发条件

- Allegra < 7.5.1，`/excelFieldMatch.action` 可达。
- 攻击者能先把恶意序列化字节写到 `trackdata/excelImport/<id>/listmapping`（借助 CVE-2024-22510/CVE-2024-22504 或其他文件写入原语）。
- 目标 classpath 存在可用 gadget，JDK/依赖未启用反序列化过滤器。
- `entity` 值与落盘目录/文件名匹配（示例 `entity=list`，目录 `trackdata/excelImport/1/`）。

## 利用步骤

1. 用文件读取（CVE-2024-22507）确认应用路径与配置，必要时伪造 JWT。
2. 生成恶意序列化字节流（gadget 链，需匹配目标 classpath）；先在本地用同版本依赖验证 `readObject` 触发。
3. 通过 `branding!uploadFile.action` 的 `fileToReplace` 路径穿越（或 zipslip）把字节流写到 `trackdata/excelImport/1/listmapping`。
4. 请求 `/excelFieldMatch.action?fileName=1.xlsx&entity=list` 触发 `renderFieldMatch` 读取 listmapping 并反序列化。
5. 观察命令执行/外连/文件落地；清理写入文件。

## PoC

触发请求（原文路由）：

```http
GET /allegra/excelFieldMatch.action?fileName=1.xlsx&entity=list HTTP/1.1
Host: target
```

sink 代码（原文）：

```java
FileInputStream fis = new FileInputStream(new File(excelMappingsDirectory, getMappingFileName(entity)));
ObjectInputStream objectInputStream = new ObjectInputStream(fis);
columNameToFieldIDMap = (Map) objectInputStream.readObject();
```

恶意序列化文件写入（借助上传卡，`fileToReplace` 指向 `../trackdata/excelImport/1/listmapping`；后缀处理需按环境调整）：

```http
POST /allegra/branding!uploadFile.action?uploadedFileName=<no-ext>&fileToReplace=../trackdata/excelImport/1/listmapping HTTP/1.1
Content-Type: multipart/form-data; boundary=...
```

## 变体与关联

- **同系列反序列化**：ZDI 公告中的 `loadFieldMatch` 反序列化（CVE-2024-22506，9.8）是同类 sink，可能入口不同，可一并测试。
- **落盘原语**：CVE-2024-22510 上传（[[web-java-component-allegra-branding-uploadfile-path-traversal]]）、CVE-2024-22504 zipslip（[[web-java-component-allegra-import-allegra-format-zipslip]]）。
- **信息前置**：CVE-2024-22507 文件读取（[[web-java-component-allegra-download-attachment-filename-traversal-jwt-key]]）用于获取 JWT/路径配置。
- **同类 Java 反序列化**：[[web-java-deserialization-activemq-openwire-throwable-constructor-rce]]、[[web-java-deser-spring-kafka-errorhandlingdeserializer-header-cve-2023-34040]]。

## 检测与防御

- **检测（Web/应用）**：`excelFieldMatch.action` 的 `entity`/`fileName` 异常；`trackdata/excelImport/` 下 listmapping 文件被非业务写入/修改；`ObjectInputStream.readObject` 加载非预期类；反序列化 gadget 特征类（`InvokerTransformer`、`TemplatesImpl` 等）出现在 JVM。
- **检测（文件）**：`trackdata/excelImport/` 目录新增/修改文件；上传接口写入该目录的日志。
- **防御**：升级到 7.5.1+；彻底避免 Java 原生序列化，改用 JSON/带 schema 的格式；如必须反序列化，使用 `ObjectInputFilter` 类白名单并限制深度/数组长度；修复上传路径穿越；运行低权限账户并限制应用目录写权限。
