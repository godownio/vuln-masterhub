---
id: web-java-component-finereport-largedataset-export-excel-formula-sqli
title: 帆软 FineReport largedataset/export/excel 的 functionParams 注入 Formula：evalValue 执行 SQL() 函数
type: scenario
domain: web
path: web/java/component
technique: finereport-largedataset-export-formula-sqli
aliases:
- 帆软 export/excel SQL 注入
- FineReport largedataset export excel 注入
- functionParams Formula 注入
- LargeDatasetExcelExportHandler dealParam
- evalValue SQL 函数
- FRParser SQL 注入
tags:
- java
- finereport
- sqli
- formula-injection
- expression
- sqlite
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:55:36+08:00'
  notes: 已对照原文及11张图核对：图01确认/report/v9/largedataset/export/excel GET路由与NXController.largedsExcelExportV9；图02-06确认__parameters__/params XML/functionParams三参数及getEntity/dealParam；图07/08确认Formula分支与占位符分支均走Calculator.evalValue，断点var20=sql('FRDemo',DECODE('%ef%bb%bfattach database ctc.jsp as psox'),1,1)；图09确认FRParser支持com.fr.function；图10/11确认JDBCSecurityChecker removeSpecialCharacters与attach/insert/merge/xp_dirtree关键词检查。核对时清除affected_versions：原文只说明分析所用fine-report-engine-11.0.jar，未标注受影响版本/区间，按brief不猜。未验证点：原文未给出完整HTTP请求/响应，SQLite写JSP未跑通；未本机复跑。
---

## 一句话结论

FineReport（fine-report-engine-11.0.jar）的 `/report/v9/largedataset/export/excel` 由 `LargeDatasetExcelExportHandler.dealParam` 处理 `functionParams`，当参数值被构造成 `Formula` 时会直接调用 `Calculator.evalValue()`；FineReport 表达式支持内置 `SQL()` 函数，因此攻击者可让服务端执行任意 SQL（原文在调试器中断到 `SQL.run` → JDBC 查询栈），并尝试用 SQLite `ATTACH DATABASE` 写 JSP。

## 原理

- 路由：`com.fr.nx.app.web.controller.NXController.largedsExcelExportV9`，`@RequestMapping("/report/v9/largedataset/export/excel", method=GET)`，调用 `LargeDatasetExcelExportHandler.HANDLER.handle`。
- 参数：`__parameters__`（JSON，可通过 GET/header 传入）、`params`（XML，反序列化为 `LargeDatasetExcelExportJavaScript`，可用 `GeneralXMLTools.writeXmllableAsString` 生成）、`functionParams`（JSON，`getParamsMap` 解析）。
- `dealParam` 遍历模板参数：
  ```java
  if (var17.getValue() instanceof Formula) {
      Object var24 = var2.evalValue(String.valueOf(var17.getValue()));
      var13.put(var17.getName(), var24);
  } else if (var19 != null) { // JSON 对象
      String var20 = String.valueOf(var17.getValue());
      for (Map.Entry var23 : var21.entrySet()) {
          var20 = var20.replaceAll("\\$" + var23.getKey(), "\"" + var23.getValue() + "\"");
      }
      Object var26 = var2.evalValue(var20);
  }
  ```
  参数值若被解析为 `Formula`，或通过 `$key` 占位符替换后仍含表达式，就会进入 `Calculator.evalValue`。
- `Calculator.evalValue` → `Expression.eval` → `FunctionCall.eval` → `AbstractFunction.evalExpression` → `SQL.run` → `AbstractDBDataModel` → JDBC `executeQuery`。`FRParser` 支持 `com.fr.function` 包下的函数，其中 `SQL(connectionName, sql, columnIndex, rowIndex)` 会在指定数据源上执行 SQL。
- 原文调试器把 `var20` 断为：
  ```text
  sql('FRDemo',DECODE('%ef%bb%bfattach database ctc.jsp as psox'),1,1)
  ```
  `FRDemo` 是自带 SQLite 测试库；`DECODE` 用于把编码后的特殊字符带进表达式；SQL 执行栈确认语句到达数据库层。原文最后停在“SQLite 如何 Getshell”，说明 SQL 执行已确认，但写 JSP 的完整链未在文中跑通。
- FineReport 的 SQL 防护位于 `JDBCSecurityChecker`：`removeSpecialCharacters` 先去除引号/注释内容并小写化，再按 `\bxp_dirtree\b`、`\binsert\b`、`\bmerge\b`、`\battach\b` 等关键词匹配；原文截图显示 `"attach database ctc.jsp as psox"` 会被 `attach` 规则命中，因此需要额外绕过（如 U+FEFF 前缀/编码技巧，参见同产品其他入口的卡）。

## 触发条件

- 目标为 FineReport 11.0（原文分析 `fine-report-engine-11.0.jar`），`/report/v9/largedataset/export/excel` 路由可达。
- 攻击者能构造 `params` XML 与 `functionParams` JSON，使参数值被解析为 `Formula` 或含 `$` 占位符表达式。
- 目标存在可用的数据源连接（默认 `FRDemo` SQLite）或至少一个可执行 SQL 的连接。
- 需要有效会话/权限（原文未明确匿名可达，分析以登录后路由为主，使用时需验证）。
- SQL 执行受 `JDBCSecurityChecker` 关键词过滤约束；`ATTACH`/`INSERT` 等关键词需绕过。

## 利用步骤

1. 确认 `/report/v9/largedataset/export/excel` 可达，准备 `__parameters__` JSON、`params` XML、`functionParams` JSON 三组参数。
2. 用 `GeneralXMLTools.writeXmllableAsString` 生成 `params` XML（`LargeDatasetExcelExportJavaScript` 的 XML 表示），设置一个参数，使其值为 `Formula` 类型或含 `$name` 占位符。
3. 在 `functionParams` JSON 中给该参数提供值，如 `sql('FRDemo','SELECT 1',1,1)`，触发 `dealParam` 的 `evalValue`。
4. 观察响应/延时确认 SQL 执行；原文在调试器中确认 `SQL.run` 与 JDBC `executeQuery` 栈。
5. 尝试 SQLite 写文件：先用 `ATTACH DATABASE '../webapps/webroot/xxx.jsp' AS x`，再 `CREATE TABLE`/`INSERT` 写入 JSP 内容；注意绕过 `JDBCSecurityChecker` 的 `attach`/`insert` 关键词过滤（同产品其他入口使用 U+FEFF 前缀与 DECODE 编码）。
6. 写入后访问 JSP；若容器未初始化 Jasper，可先访问 FineReport 的 JasperInitializer 触发加载。

## PoC

参数与断点值（原文）：

```text
var20 = sql('FRDemo',DECODE('%ef%bb%bfattach database ctc.jsp as psox'),1,1)
```

调用栈（节选）：

```text
com.fr.function.SQL.run
com.fr.script.AbstractFunction.evalExpression
com.fr.parser.FunctionCall.eval
com.fr.script.Calculator.evalValue
com.fr.nx.app.web.v9.handler.handler.largeds.LargeDatasetExcelExportHandler.dealParam
com.fr.nx.app.web.controller.NXController.largedsExcelExportV9
```

原文未给出完整 HTTP 请求/响应，PoC 为调试器中的参数值与调用栈；SQLite 写 JSP 的最终利用未在文中完成。

## 变体与关联

- 变体：`Formula` 分支直接 `evalValue`；JSON 对象分支通过 `$key` 替换后 `evalValue`，两者都可注入。
- 变体：除 `SQL()` 外，`FRParser` 还支持 `com.fr.function` 下其他函数，可结合文件/网络/命令类函数扩大影响。
- 关联：[[web-java-component-finereport-print-ie-pdf-sqli-webshell]]、[[web-java-component-finereport-view-reportserver-template-sqli-webshell]]（同产品其他入口的 `${sql()}` → SQLite 写 JSP 链，含 U+FEFF 绕过与 Jasper 触发技巧）。
- 关联：FineReport 默认口令卡可作为获取登录会话的入口。

## 检测与防御

- 检测：`/report/v9/largedataset/export/excel` 请求中出现 `functionParams` 含 `Formula`、`$` 占位符、`sql(`、`DECODE(`、`attach`、`xp_dirtree` 等特征；响应时间异常或导出内容异常。
- 防御：升级 FineReport 修复版本；禁止不可信输入进入 `Calculator.evalValue`，对 `functionParams` 做类型/白名单校验。
- 防御：强化 `JDBCSecurityChecker` 关键词与编码归一化（先解码再匹配），限制数据源账号权限，禁用不必要的 SQLite 测试库 `FRDemo`。
- 防御：Web 目录禁止运行时可写；监控 JSP 文件变更与 Jasper 初始化请求。
