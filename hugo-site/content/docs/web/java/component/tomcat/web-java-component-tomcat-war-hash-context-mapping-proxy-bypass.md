---
id: web-java-component-tomcat-war-hash-context-mapping-proxy-bypass
title: 'Tomcat WAR 文件名 # 映射多级上下文（foo#bar.war → /foo/bar/）：manager#app.war 把 WebShell 部署进 Nginx 仅代理的 /manager/* 路径'
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-war-hash-context-path-mapping
tags:
- tomcat
- war
- nginx
- reverse-proxy
- context-path
- manager
- webshell
- memshell
- weak-password
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-8
  verified_at: '2026-11-08T01:14:36+08:00'
  notes: '已对照原文核对：# 多级上下文映射有图04 Tomcat 官方文档（foo#bar.war 上下文路径为 /foo/bar）佐证；图03 JSP 文件实时监控器日志显示 ./test/1.jsp、./my#app/1.jsp、./manager#app/1.jsp 均被成功移除文件，证实 WAF 删落盘 JSP 且 manager#app 部署路径生效；图01 Nginx 欢迎页、图02 Manager 弱口令登录后应用列表、图05 内存马连接基本信息 Current User: root 证实 getshell 打通。原理（# 映射规则、反代只放行 /manager/ 前缀、WAF 删 JSP 改用内存马）、触发条件、PoC（manager#app.war 命名 + POST /manager/html/upload + GET /manager/app/shell.jsp?cmd=id）、类名、路径 web/java/component/tomcat 与原文及 5 张图一致，confidence high 有据。dedup_review 成立：最相近 manager-basic-weak-auth-war-deploy 只讲弱口令上传 WAR，不含 # 映射与反代白名单路径约束，其余候选全为不同利用链，duplicate 为自匹配；dup-scan 无涉及本篇 pair。affected_versions=null 合理（CTF 靶场题解，原文未写受影响版本区间，tomcat8 目录名与图05 环境版本均为目标环境版本）。未验证点：内存马为原文提及但未给具体注入代码，卡内仅引用。'
url: /docs/web/java/component/tomcat/web-java-component-tomcat-war-hash-context-mapping-proxy-bypass/
draft: false
kb_aliases:
- foo#bar.war
- manager#app.war
- 'Tomcat # 号上下文映射'
- Tomcat 多级 Context path
- 反向代理路径白名单绕过
- WAR 部署到指定路径
---

## 一句话结论

Tomcat 自动部署 WAR 时会把文件名中的 `#` 当作上下文路径分隔符（`foo#bar.war` → 部署到 `/foo/bar/`）；当反向代理只把 `/manager/*` 转发给 Tomcat、其它路径一律不代理时，把恶意 WAR 命名为 `manager#app.war` 即可让应用落到 `/manager/app/`，从而落在代理放行的路径内被外部访问，配合 Manager 弱口令上传 WAR 即可 getshell（WAF 删落地 JSP 时用内存马）。

## 原理

- **# 映射规则**：Tomcat 自动部署（appBase 下未对应 Context 的 WAR 会自动展开）时，WAR 文件名里的 `#` 会被替换为 `/` 作为多级上下文路径。官方文档说明"可以用 # 来定义多级上下文，例如名为 `foo#bar.war` 的 WAR 上下文路径为 `/foo/bar`"。因此 `manager#app.war` 解压后注册到 `/manager/app`，而不是默认的 `/manager#app`。
- **为什么能绕过反代限制**：Nginx 通常按 URI 前缀做 `location /manager/ { proxy_pass ... }`，只把 `/manager/*` 转发给后端 Tomcat。若把 WAR 命名为普通名字（如 `evil.war`），应用落在 `/evil/`，请求被 Nginx 拦在前面，WebShell 永远不可达；用 `manager#app.war` 让应用的 URL 以 `/manager/` 开头，恰好命中 Nginx 代理规则，请求被转发到 Tomcat 并路由到该应用。
- **为什么需要弱口令/ Manager**：部署 WAR 需要 Tomcat Manager（`/manager/html` 或 `/manager/text/deploy`）的 `manager-script`/`manager-gui` 角色凭据；靶场用 `tomcat/123456` 弱口令登录后通过管理台上传。这是入口，不是 # 映射技巧本身。
- **WAF 删落地 JSP 时**：靶场有 JSP 文件实时监控器，发现 `*.jsp` 即删除（日志可见 `./manager#app/1.jsp [删除] 成功移除文件`），因此正解上传的是内存马（部署即注册 Filter/Listener/Valve，不依赖落盘 JSP），文件删除不影响已注入的内存马。
- **成立条件**：`unpackWARs`/自动部署开启（或 Manager deploy 生效）、`#` 未被过滤、代理按 `/manager/` 前缀转发、且部署后该路径能路由到应用。

## 触发条件

- 目标 Tomcat 前置 Nginx/网关只代理某个固定前缀（如 `/manager/*`），其它路径不转发到 Tomcat。
- 攻击者能向 Tomcat Manager 部署 WAR（弱口令、泄露的 manager-script 凭据、或可直接写 appBase）。
- Tomcat 按 # 号解析 WAR 文件名为多级上下文路径（默认自动部署行为）。
- 部署路径需要落在代理放行的前缀下，且应用内含可触发的 WebShell/内存马。

## 利用步骤

1. 探测代理边界：访问 `/manager` 看到 Tomcat 默认页/icon，确认只有该前缀可达；访问其它路径返回 Nginx 默认页或被拦。
2. 用弱口令（如 `tomcat/123456`）或已获得的凭据登录 `/manager/html`，确认 WAR 部署表单可用。
3. 制作恶意 WAR（内含 JSP WebShell，或注册内存马的 Filter/Listener/Servlet）；把文件名改为 `<代理放行前缀>#<应用名>.war`，例如 `manager#app.war`。
4. 通过 Manager 上传部署；Tomcat 解压并把应用注册到 `/manager/app/`。
5. 在外部访问 `/manager/app/<shell>`（该 URL 以 `/manager/` 开头，被 Nginx 转发到 Tomcat），连接 WebShell/内存马 getshell。
6. 若 WAF 会删除落盘 `.jsp`，改用部署即注入的内存马，或用自定义后缀 + web.xml 映射 JspServlet 的方式承载 JSP 代码。

## PoC

目录与命名（关键只在文件名）：

```text
manager#app.war
  └─ WEB-INF/web.xml
  └─ shell.jsp            # 或注册内存马的类
```

部署与访问：

```http
POST /manager/html/upload HTTP/1.1
Host: <target>
Authorization: Basic <base64(manager-script-凭据)>
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="deployWar"; filename="manager#app.war"
Content-Type: application/octet-stream

<WAR 二进制>
------X--
```

```http
GET /manager/app/shell.jsp?cmd=id HTTP/1.1
Host: <target>
```

`/manager/app/shell.jsp` 以 `/manager/` 开头，命中 Nginx 的 `location /manager/`，被转发到 Tomcat 后路由到 `manager#app` 应用。等价的 `/manager/text/deploy?path=/manager/app&war=...` 也可，但 # 映射让自动部署/上传路径更自然。

## 变体与关联

- **多级映射**：`a#b#c.war` → `/a/b/c/`；可用 `#` 后拼接任意层级，把应用落到代理放行的更深层路径。
- **同一目标的其它解法**：`/manager/..;/` 借助 Tomcat 把 `..;` 归一化、Nginx 不处理实现路径穿越访问 Tomcat 任意路径（属 `..;/` 白名单归一化家族，见关联）；WAR 内 `web.xml` 注册 `ServletContextListener` 在部署时自动执行代码，则完全绕过"必须能 HTTP 访问应用路径"这一限制，见 [[web-java-component-tomcat-war-listener-contextinitialized-deploy-rce]]。
- **WAF 绕过**：WAF 只拦上传表单中的 `.jsp` 时，可在 WAR 的 `WEB-INF/web.xml` 把自定义后缀（如 `*.x`）映射到 `org.apache.jasper.servlet.JspServlet`，上传 `evil.x` 承载 JSP 代码，见 [[web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell]]。
- **前置入口**：[[web-java-component-tomcat-manager-basic-weak-auth-war-deploy]]（Manager 弱口令 + WAR 部署基础链）；本卡的增量是"# 映射把应用放进反代白名单路径"。
- **内存马**：[[web-java-component-tomcat-listener-memshell]]、[[web-java-component-tomcat-valve-memshell]]。

## 检测与防御

- **认证**：不要用弱口令；限制 `/manager/*` 的访问来源（仅内网/堡垒机），为 `manager-gui`/`manager-script` 角色设置强口令并禁用不必要的 Manager 应用；生产环境可移除 `webapps/manager`。
- **部署审计**：监控 appBase 下新增 WAR 文件，尤其是文件名含 `#` 的 WAR 与 `/manager/` 下新出现的子应用；对 Manager 部署操作做告警与二次确认。
- **代理配置**：Nginx 不要按宽泛前缀把整个 `/manager/*` 透明转发给 Tomcat；若必须代理 manager，应精确限制到具体路径并对 `/manager/<子应用>` 做额外校验，避免任意部署的应用通过同一前缀暴露。
- **WAF/文件监控**：文件落地删除类 WAF 无法阻止内存马，需结合运行时检测（Filter/Servlet/Listener/Valve 列表异常、新增类加载、可疑 `Runtime.exec` 调用）；部署前后对比 `StandardContext` 中的组件。
- **检测特征**：访问日志中出现 `manager#`、`app#` 等含 `#` 的 WAR 文件名或 `/manager/<子应用>/<shell>` 路径；请求路径以白名单前缀开头但落到非预期应用。
