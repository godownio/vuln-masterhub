---
title: Tomcat
weight: 1
---

# Tomcat

## 这层是什么

Tomcat 漏洞、Session 与文件处理。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [Axis2 1.7.x 高版本 AAR getshell：`;/` 路径参数绕过隐藏后台 + admin/axis2 弱口令 + 改 services.xml MEP 命名空间修复 info() 报错](web-java-component-tomcat-axis2-17x-services-xml-mep-namespace-aar-rce/) | verified | high | 2026-11-13 |
| [InvokerServlet 暴露未映射 BshServlet：/servlet/bsh.servlet.BshServlet 的 bsh.script 直接执行命令](web-java-component-tomcat-invoker-servlet-bshservlet-beanshell-rce/) | verified | high | 2026-11-09 |
| [InvokerServlet 直调 AxisAdminServlet：首斜杠/尾斜杠解析差异让未映射 Axis2 控制台完成登录与 aar 部署 RCE](web-java-component-tomcat-invoker-servlet-axisadmin-aar-upload-rce/) | verified | high | 2026-11-09 |
| [Java 备份/恢复链路：jtar 写 tar 头时 char 截断成 byte，中文后缀被压成 .jsp 落进 WEB-INF/views](web-java-component-tomcat-jtar-tar-name-byte-truncation-jsp-upload/) | verified | medium | 2026-11-08 |
| [jshERP v3.6 补丁绕过：原始 URI 前缀白名单 + Tomcat 分号路径参数归一化差异，未授权建管理员后 pf4j 插件 RCE](web-java-component-jsherp-filter-prefix-normalization-plugin-rce/) | verified | high | 2026-11-05 |
| [Listener 内存马调用 request.getParameter 提前耗尽 CoyoteInputStream：Jersey MultivaluedMap 收不到表单参数，改用 URI/User-Agent 做 gate](web-java-component-tomcat-listener-memshell-getparameter-body-consumed/) | verified | high | 2026-11-08 |
| [Tomcat 8.5.78+ WebappClassLoaderBase#getResources() 恒返回 null：TCCL 取 StandardContext 的内存马注入路径失效与版本边界](web-java-component-tomcat-webappclassloader-getresources-null-context/) | verified | high | 2026-11-12 |
| [Tomcat 9.0.97 CVE-2024-50379 大小写文件系统条件竞争：上传 JSP 被当脚本编译 getshell](web-java-component-tomcat-cve-2024-50379-case-race-rce/) | verified | high | 2026-11-05 |
| [Tomcat Adapter 内存马：替换 AbstractProcessor.adapter 的 CoyoteAdapter](web-java-component-tomcat-adapter-memshell/) | verified | high | 2026-11-05 |
| [Tomcat AJP（CVE-2020-1938）：javax.servlet.include.* 属性注入让 JspServlet 把任意文件编译执行](web-java-component-tomcat-cve-2020-1938-ajp-include-attribute-jsp-rce/) | verified | high | 2026-11-09 |
| [Tomcat ConnectionHandler.proto 内存马：反射替换 Http11NioProtocol 为恶意子类，重写 getClientCertProvider 在 Processor 处理前执行命令](web-java-component-tomcat-connectionhandler-proto-getclientcertprovider-memshell/) | verified | medium | 2026-11-13 |
| [Tomcat CVE-2017-12615：PUT 方法 + `/1.jsp/` 后缀绕过写入 JSP WebShell](web-java-component-tomcat-cve-2017-12615-put-jsp-upload/) | verified | high | 2026-11-05 |
| [Tomcat CVE-2023-41080：ROOT 应用 FORM 认证把 //host 存入 savedRequestURL，登录后 303 Location 协议相对 URL 开放重定向](web-java-component-tomcat-cve-2023-41080-formauth-open-redirect/) | verified | high | 2026-11-10 |
| [Tomcat CVE-2025-24813 部分 PUT 临时文件名碰撞读取敏感上传文件](web-java-component-tomcat-cve-2025-24813-partial-put-tempfile-collision-disclosure/) | draft | high | 2026-11-08 |
| [Tomcat CVE-2025-24813：部分 PUT 写入 .session 临时文件 + JSESSIONID 触发 PersistentManager 反序列化 RCE](web-java-component-tomcat-cve-2025-24813-partial-put-session-deserialization-rce/) | verified | high | 2026-11-07 |
| [Tomcat Digester XML 注入绕过 WAF：XML 编码/实体/CDATA 混淆与 ${a:-c}om 属性占位符拆分 className](web-java-component-tomcat-digester-xml-placeholder-encoding-waf-bypass/) | verified | medium | 2026-11-10 |
| [Tomcat Digester 运行时 JSP webshell：自定义规则 + base64 XML 触发 setter JNDI](web-java-component-tomcat-digester-jsp-runtime-webshell/) | verified | high | 2026-11-05 |
| [Tomcat Executor 内存马：替换 NioEndpoint 线程池解析原始请求](web-java-component-tomcat-executor-memshell/) | verified | high | 2026-11-05 |
| [Tomcat Filter 内存马劫持前端 JS：302 重定向到攻击者脚本，窃取登录明文密码与二因素 token](web-java-component-tomcat-filter-memshell-js-hijack-credential-theft/) | verified | medium | 2026-11-07 |
| [Tomcat Handler 内存马：替换 NioEndpoint.handler，在 HTTP 解析前 read/unRead 窥探原始请求并 finishResponse 回显](web-java-component-tomcat-handler-memshell/) | verified | high | 2026-11-10 |
| [Tomcat InvokerServlet 类名路由：/servlet/<全限定类名> 直接调用未映射 Servlet（Tomcat ≤6）](web-java-component-tomcat-invoker-servlet-class-name-routing/) | verified | high | 2026-11-09 |
| [Tomcat Listener 内存马：StandardContext.addApplicationEventListener 注入请求监听器](web-java-component-tomcat-listener-memshell/) | verified | high | 2026-11-05 |
| [Tomcat Manager 弱口令（HTTP Basic base64 变形）+ WAR 部署 getshell](web-java-component-tomcat-manager-basic-weak-auth-war-deploy/) | verified | high | 2026-11-08 |
| [Tomcat multipart 未完成请求保持临时文件 fd 打开](web-java-component-tomcat-multipart-tempfile-fd/) | verified | medium | 2026-11-04 |
| [Tomcat RFC2231 文件名高位截断：filename*=UTF-8''sh.陪sp 绕过扩展名黑名单落盘 JSP](web-java-component-tomcat-rfc2231-filename-char-truncation-jsp-upload/) | verified | high | 2026-11-05 |
| [Tomcat server.xml 中 appBase 为空导致 Web 根目录回退到 CATALINA_HOME](web-java-component-tomcat-appbase-empty-webroot-mapping/) | verified | high | 2026-11-07 |
| [Tomcat Servlet 内存马：反射 StandardContext 创建 Wrapper 并注册 ServletMapping](web-java-component-tomcat-standardcontext-servlet-memshell/) | verified | high | 2026-11-05 |
| [Tomcat Tribes EncryptInterceptor 解密失败仍转发导致未授权反序列化 RCE（CVE-2026-34486）](web-java-component-tomcat-tribes-encryptinterceptor-deserialization-rce/) | verified | high | 2026-11-05 |
| [Tomcat Upgrade 内存马：向 httpUpgradeProtocols 注册恶意 UpgradeProtocol](web-java-component-tomcat-upgrade-memshell/) | verified | high | 2026-11-05 |
| [Tomcat Valve 内存马：StandardContext Pipeline 注入恶意 Valve](web-java-component-tomcat-valve-memshell/) | verified | high | 2026-11-05 |
| [Tomcat WAR 文件名 # 映射多级上下文（foo#bar.war → /foo/bar/）：manager#app.war 把 WebShell 部署进 Nginx 仅代理的 /manager/* 路径](web-java-component-tomcat-war-hash-context-mapping-proxy-bypass/) | verified | high | 2026-11-08 |
| [Tomcat WAR 部署期自动执行：web.xml 注册 ServletContextListener 的 contextInitialized 直接 Runtime.exec，绕过只放行 /manager/* 的反代与删 JSP 的 WAF](web-java-component-tomcat-war-listener-contextinitialized-deploy-rce/) | draft | medium | 2026-11-08 |
| [Tomcat XML 配置经 Digester 自动调用 setter 触发 JNDI 注入](web-java-component-tomcat-xml-digester-setter-jndi/) | verified | high | 2026-11-05 |
| [Tomcat 上传覆盖 WEB-INF/web.xml：jsp-file 将上传的 .xml 映射为 JSP 并 getshell](web-java-component-tomcat-webxml-overwrite-jsp-file-webshell/) | verified | high | 2026-11-08 |
| [Tomcat 上传路径穿越覆盖 conf/web.xml：把 *.xml 映射到 JspServlet，上传含 JSP 代码的 .xml 直接 getshell](web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell/) | verified | high | 2026-11-08 |
| [Tomcat 分号路径参数绕过对 conf 与 .log 的访问拦截](web-java-component-tomcat-semicolon-path-param-access-bypass/) | verified | high | 2026-11-07 |
| [Tomcat 动态注册 Filter 内存马：StandardContext.addFilterDef/addFilterMapBefore/filterStart](web-java-component-tomcat-dynamic-filter-memshell/) | verified | high | 2026-11-05 |
| [Tomcat 访问日志泄露 GET 请求中的 token 并重放登录后台](web-java-component-tomcat-accesslog-token-leak-backend-login/) | verified | high | 2026-11-07 |
| [不出网 Tomcat 内存马 500 失败时用命令执行定位 webroot 后 echo 逐行写 JSP 落地 Webshell，再上传 suo5 搭 HTTP 代理隧道](web-java-component-tomcat-nooutbound-echo-jsp-webshell-memshell-fallback-suo5/) | verified | high | 2026-11-08 |
| [哥斯拉 FilterShell：Tomcat 动态 Filter 内存马（Cookie 触发 + noLog）](web-java-component-tomcat-godzilla-filtershell-memshell/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
