---
id: web-generic-file-upload-jar-meta-inf-resources-jsp-carrier
title: 上传 JAR 利用 Servlet 3.0 META-INF/resources 直接访问：jar 内 JSP 作为静态资源被容器映射执行
type: scenario
domain: web
path: web/generic/file-upload
technique: jar-meta-inf-resources-jsp-webshell-carrier
aliases:
- META-INF/resources
- jar 上传 getshell
- Servlet 3.0 资源映射
- evil.jar webshell
- 非常规后缀 jspx/war/jar
- jar 内 JSP
tags:
- web
- file-upload
- jar
- servlet3
- tomcat
- webshell
- waf-bypass
- archive
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:33:42+08:00'
  notes: 已对照幻灯片17核对：WEB-INF/lib/evil.jar 内含 META-INF/resources/evil.jsp，项目反编译出 evil_jsp.class（JSP 被编译）及 Servlet3.0 META-INF/resources 资源映射说明，均与卡片一致；jar 需进入 classpath/app 加载是正确边界。未验证点：未在真实 Tomcat 上传落盘执行，URL 映射依容器/应用配置（卡内已注明）。
---

## 一句话结论

Servlet 3.0 规定 classpath 中 JAR 的 `META-INF/resources/` 目录参与 Web 静态资源映射：上传一个内含 `META-INF/resources/evil.jsp` 的 jar，只要它能进入应用的 classpath（典型是 `WEB-INF/lib`），访问对应 URL 时容器会从 jar 中取出该 JSP 并交给 JSP 引擎编译执行——上传的是 `.jar` 而不是 `.jsp`，后缀黑名单与按扩展名的内容检测容易直接放行。war/jspx/xml 等非常规后缀也可作为替代载体（war 自动部署、xml 配置注入等）。

## 原理

- **Servlet 3.0 的 JAR 资源规则**：Web 应用除 `WEB-INF/classes`、`WEB-INF/lib` 的类加载外，容器还会把 classpath 中 JAR 的 `META-INF/resources/` 目录当作 Web 资源的“额外根”。请求某路径时，若应用的物理目录不存在该文件，容器会到 JAR 的 `META-INF/resources/` 里查找；命中后按静态资源返回，若资源是 JSP 则按 JSP 处理（编译执行）。
- **为什么 jar 是好的载体**：常见上传黑名单针对 `.jsp`、`.jspx`、`.php`、`.asp` 等脚本后缀，`.jar` 是正常开发构件，通常不在名单内；jar 是 zip 容器，很多 WAF 只按外层扩展名/文本内容检测，不会递归解压检查内部 `.jsp`。幻灯片中的 `evil.jar` 里就是 `META-INF/resources/evil.jsp`，且反编译出了 `evil_jsp.class`，证明 JSP 被容器编译。
- **落地条件**：上传的 jar 必须进入应用的 classpath/被容器加载——常见路径包括：上传目录可穿越到 `WEB-INF/lib`、插件/主题/组件安装功能把 jar 放进 lib、war 包内嵌 jar、或服务器扫描上传目录加载 jar。只上传到任意 Web 目录通常不会触发，需要找到“jar 会被加载”的落点。
- **替代载体**：`war`（Tomcat autoDeploy 自动部署，可放 `WEB-INF/web.xml`/Listener 或 JSP）、`jspx`（直接作为 JSP XML 语法执行）、`xml`（写 `META-INF/context.xml` 触发 Digester/JNDI）——当 `.jsp` 被严格拦截时，这些“非常规后缀 + 容器特性”的组合提供了其它入口。
- **为什么有效**：安全策略通常围绕“文件后缀/文件内容”设计，而利用点是“容器对 classpath/JAR 内资源的特殊映射”；检测器看不到 jar 内部的 JSP，后端却会在访问 URL 时执行它。

## 触发条件

- 上传接口允许 `.jar`/`.war`/`.xml`/`.jspx` 等非常规后缀，或黑名单不全；
- 存在让上传文件进入 classpath/被容器加载的路径（`WEB-INF/lib` 可写、插件安装、war 自动部署、上传目录被扫描加载）；
- 容器为 Servlet 3.0+（Tomcat 7+ 等），且未禁用 JAR 内资源/JSP 映射；
- 上传目录/部署目录对应用进程可写，访问路径可到达对应资源。

## 利用步骤

1. 构造恶意 jar：在 `META-INF/resources/` 下放 JSP（如 `evil.jsp`，执行命令/回显），可按需加入类文件。
2. 寻找可写 classpath 的落点：优先尝试路径穿越写 `WEB-INF/lib/evil.jar`、插件/主题上传、war 内嵌 jar；或上传 war 让容器自动部署。
3. 上传后访问 `http://target/<应用>/<路径>/evil.jsp`（具体 URL 取决于资源路径与容器映射），确认 JSP 被编译执行。
4. 若 `.jar` 被拦截，改用 `.war`（自动部署 + Listener/webshell）、`.jspx`（JSP XML 语法）或 `.xml`（context.xml/Digester JNDI）等载体。
5. 清理/持久化按目标环境处理，记录落点与 URL 作为证据。

## PoC

```text
evil.jar
├── META-INF/
│   └── resources/
│       └── evil.jsp        # <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
└── （可选）classes...
```

```bash
# 打包（示意）
mkdir -p build/META-INF/resources
cp evil.jsp build/META-INF/resources/
jar cf evil.jar -C build .
# 上传 evil.jar 到 WEB-INF/lib（或插件目录）后访问：
# GET /<app>/<resource-path>/evil.jsp?cmd=whoami
```

幻灯片展示了 `WEB-INF/lib/evil.jar` 内的 `META-INF/resources/evil.jsp` 及反编译出的 `evil_jsp.class`；以上为按该结构整理的骨架，未在真实目标执行。URL 映射与落点需按容器/应用配置实测。

## 变体与关联

- 变体：war 自动部署（`WEB-INF/web.xml` 注册 Listener/Filter/Servlet，或直接放 JSP），见 [[web-java-component-tomcat-war-listener-contextinitialized-deploy-rce]]。
- 变体：写 `META-INF/context.xml`/`conf/Catalina/...` 触发 Digester setter JNDI，见 [[web-java-component-tomcat-xml-digester-setter-jndi]] 与 [[web-java-component-tomcat-digester-xml-placeholder-encoding-waf-bypass]]。
- 变体：上传 jar 到可写目录后由 URLClassLoader/反序列化加载，见 [[web-java-classloader-urlclassloader-addurl-uploaded-jar-deser-rce]]。
- 关联：[[web-generic-file-upload-multipart-filename-jsp-tomcat-webshell]]（直接上传 JSP 的基线场景）；非常规后缀（jspx/war/xml/jar）也可用于黑名单不全的上传点。
- 边界：jar 必须进入 classpath 才会生效；容器禁用 JAR 资源映射/禁用 JSP 时失效；war 自动部署需 `autoDeploy` 开启且部署目录可写。

## 检测与防御

- 检测（WAF）：对上传的压缩包递归解包检查（jar/war/zip 内的 `.jsp`、`web.xml`、`META-INF/context.xml`）；对 `.jar`/`.war`/`.xml`/`.jspx` 上传本身做业务白名单审批。
- 检测（主机）：`WEB-INF/lib`、部署目录出现新增 jar/war；jar 内含 `META-INF/resources/*.jsp`；容器 work 目录出现对应 JSP 编译产物；访问后产生子进程。
- 防御：上传功能只允许业务必需的类型并在服务端解包校验；上传文件存到 Web 根之外、不可执行、不可进入 classpath；关闭不必要的 `autoDeploy`；对 `WEB-INF/lib`、部署目录做完整性监控。
