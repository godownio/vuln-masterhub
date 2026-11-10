---
id: web-java-component-landray-ekp-dataxml-sbean-beanshell-rce
title: 蓝凌 EKP dataxml.jsp 的 s_bean=sysFormulaSimulateByJS：script 参数经 BeanShell 解释器执行命令
type: scenario
domain: web
path: web/java/component
technique: landray-ekp-dataxml-sbean-beanshell-script-exec
aliases:
- 蓝凌 EKP dataxml.jsp RCE
- Landray EKP dataxml
- sysFormulaSimulateByJS
- EKP s_bean 命令执行
- FormulaParserByJS parseValueScript
- 蓝凌 EKP 后台 RCE
tags:
- java
- landray
- ekp
- oa
- dataxml
- beanshell
- bsh
- expression-injection
- rce
- jsp
cve: []
severity: critical
confidence: high
status: verified
affected_versions: V16
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:37:41+08:00'
  notes: 已对照原文（content.md 与图01-03）核对：dataxml.jsp 的 s_bean split(';')→ctx.getBean→IXMLDataBean.getDataList（图01）、SysFormulaSimulateByJS#getDataList→formulaSimula 取 script 参数→parseValueScript（图02）、isContainUnicode+敏感词黑名单后 interpreter.eval(m_script)（图03）均与卡内描述和原文 PoC 一致。与原 beanshell-interpreter-eval 卡产品/入口/过滤链不同，dedup 为 related 非同一链；dup-scan 与同篇 replaceExtend 卡 pair 为 related（同一前台链的上下半段，技术原子不同，并列保留）。未验证点：未复跑原文 PoC（calc.exe 无回显）。
---

## 一句话结论

蓝凌 EKP 的 `/sys/common/dataxml.jsp` 用 `s_bean` 参数（分号分隔的 Spring bean 名）从容器取 bean 并逐个调用其 `getDataList(request)`；`sysFormulaSimulateByJS` 这个 bean 的实现类 `SysFormulaSimulateByJS#getDataList` 会取请求里的 `script` 参数，交给 `FormulaParserByJS#parseValueScript` 做 unicode 与敏感词黑名单检查后，直接用 BeanShell `interpreter.eval()` 求值。黑名单只过滤少数字符串且未禁用 `Runtime.exec`/`ProcessBuilder`，所以 `script` 里写 `java.lang.Runtime.getRuntime().exec(...)` 即可以应用进程身份执行系统命令。

## 原理

- **入口分发**：`dataxml.jsp` 中 `String[] beanList = request.getParameter("s_bean").split(";")`，循环 `Object tempBean = ctx.getBean(beanList[i])`，强转 `IXMLDataBean` 后调用 `treeBean.getDataList(requestInfo)`；即 `s_bean` 是 Spring bean 名选择器，用户可指定实现了 `IXMLDataBean` 的任意 bean，并把原始请求传进去。
- **sink 组件**：`SysFormulaSimulateByJS` 实现了 `IXMLDataBean`，其 `getDataList` 在 `requestType` 非 `getFdHandlerRoleInfoIds` 时调用 `this.formulaSimula(requestContext)`；`formulaSimula` 读取 `script` 参数与其余参数，构造 `FormulaParserByJS` 并调用 `parseValueScript(script, type)`。
- **过滤逻辑**：`parseValueScript` 先把 `importPart + preparePart + leftScript + rightScript` 拼成 `m_script`，只做两类检查：`isContainUnicode(script)`（含 unicode 转义就抛 `sys-formula:error.containUnicode`），以及从 `SysCommonSensitiveConfig#getFormulaDeserializeBlacklist()` 读出的敏感词黑名单按 `;` 分割后做 `contains` 匹配，命中即抛 `BlackException`。
- **为什么能执行命令**：检查通过后执行 `interpreter.eval(m_script)`，这里的 `interpreter` 是 BeanShell 解释器，脚本在 Web 容器 JVM 内求值，可直接引用 `java.lang.Runtime`。黑名单是“敏感词/unicode 过滤”而不是沙箱：class 白名单、SecurityManager、进程创建限制都没有，`Runtime.exec` 与 `ProcessBuilder` 不在默认黑名单里，因此等价于一个 Java 脚本执行入口。
- **为什么原文 PoC 要写 `Function/**/`**：用注释把敏感方法名拆开，绕过按字符串 `contains` 匹配的黑名单（例如对 `Runtime` 或 `exec` 一类关键字的拦截），属于同一黑名单机制下的轻量绕过技巧。
- **接口位置**：`dataxml.jsp` 属于后台接口；后续版本在 `WEB-INF/KmssConfig/sys/authentication/spring.xml` 增加 `anonymousPaths` 白名单后，匿名用户只能访问白名单内的路径，该接口需要登录会话。原文的完整前台链是先用 `SysUiComponent#replaceExtend` 把 `/sys/common`（含 `dataxml.jsp`）目录复制到匿名可访问目录，再匿名访问副本触发本 sink（见关联卡）。

## 触发条件

- 目标为蓝凌 EKP（原文影响版本标记 `version = V16`），`/sys/common/dataxml.jsp` 可访问：已登录后台会话，或该目录副本经目录复制/文件上传被放到匿名可访问位置。
- 请求带 `s_bean=sysFormulaSimulateByJS` 且 `script` 非空；bean 名需与目标版本的 Spring 配置一致。
- `script` 内容不能命中部署自定义的 unicode/敏感词黑名单（默认未禁 `Runtime`/`ProcessBuilder`，可用注释拆词规避按字符串匹配的词）。
- 应用进程允许创建子进程（未被容器安全策略/主机策略禁止）。

## 利用步骤

1. 确认 `dataxml.jsp` 可达（后台或匿名副本），先用无害表达式验证 `script` 参数是否被求值。
2. 构造 BeanShell 脚本获取 `java.lang.Runtime` 并 `exec` 系统命令；需要回显时把命令输出读回并拼进返回值/异常信息，否则用带外确认（DNS/HTTP）或写文件验证。
3. 发送请求，观察响应中的 `dataList`/错误信息确认执行结果。
4. 若目标为前台场景，先完成 `replaceExtend` 目录复制，拿到匿名可访问的 `dataxml.jsp` 副本 URL 后重复上述请求。

## PoC

原文给出的最小 PoC（Windows 下弹计算器验证，无回显）：

```http
POST /ekp/sys/common/dataxml.jsp HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: <n>

s_bean=sysFormulaSimulateByJS&script=var x = Function/**/('return(java.lang.Runtime.getRuntime())')();x.exec("calc.exe");var a = mainOutput();function mainOutput() {};
```

- `Function/**/('return(java.lang.Runtime.getRuntime())')()` 拿到 Runtime 实例（注释拆词规避字符串黑名单），`exec` 执行命令。
- 该脚本无命令回显，实战中需自行改写为读取 `Process#getInputStream` 并输出。

## 变体与关联

- 同类 bsh 打法的其它实现 `IXMLDataBean` 的 bean 也可作为入口（原文称“这种利用 bsh 的打法还有许多接口可用”，细节见外部 LandrayEkpAudit 清单），不逐个展开。
- 旧打法：`custom.jsp` 通过 `var={"body":{"file":"/sys/common/dataxml.jsp"}}` 让服务端请求 `dataxml.jsp`，把 `s_bean`/`script` 一起带过去（SSRF 打本机后台接口）；原文明确该版本“已经无法利用”，不单独成卡。
- 前台化绕过：V16 的 `SysUiComponent#replaceExtend` 未鉴权目录复制，把本接口目录搬到匿名路径，见关联卡。
- 与用友 U8C `BshServlet` 等 BeanShell 暴露点同属“BeanShell 解释器对外可达导致 RCE”一族，区别是本例通过公式组件间接调用、且有可配置敏感词黑名单。

## 检测与防御

- 升级到修复版本；对 `/sys/common/dataxml.jsp` 及其副本做访问控制，禁止匿名访问，后台接口只对必要角色开放。
- 把 `Runtime`、`ProcessBuilder`、`exec`、`Function`、`getRuntime` 等纳入 `FormulaDeserializeBlacklist` 只是一层弱缓解；根本修复应禁止用 BeanShell/公式解释器求值不可信请求参数，或改用无能力沙箱/白名单表达式引擎。
- 检测：审计 `dataxml.jsp` 请求中的 `s_bean=sysFormulaSimulateByJS`、`script` 含 `Runtime`/`getRuntime`/`ProcessBuilder`/`exec`/`Function` 的流量；关注 `s_bean` 使用分号串联多个 bean、`script` 含 Java 语法的异常请求。
- 排查：检查 Web 目录中非预期的 `dataxml.jsp` 副本与 `sys/portal/template/ui_component/` 下异常 JSP，结合进程创建日志定位命令执行。
