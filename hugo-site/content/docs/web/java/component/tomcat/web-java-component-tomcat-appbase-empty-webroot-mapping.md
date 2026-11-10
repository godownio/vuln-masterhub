---
id: web-java-component-tomcat-appbase-empty-webroot-mapping
title: Tomcat server.xml 中 appBase 为空导致 Web 根目录回退到 CATALINA_HOME
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-appbase-empty-webroot-mapping
tags:
- tomcat
- server.xml
- appBase
- 配置错误
- 信息泄露
- 目录映射
- 任意文件读取
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:40:15+08:00'
  notes: 已对照原文核对；原理与PoC(appBase空导致根回退、GET /conf/server.xml、本地复现)与图25/36/37一致；原文未写受影响版本区间、仅目标环境tomcat8，已clear；未验证点：无
url: /docs/web/java/component/tomcat/web-java-component-tomcat-appbase-empty-webroot-mapping/
draft: false
kb_aliases:
- appBase 为空
- Tomcat 根目录映射错误
- CATALINA_HOME 作为 Web 根
- conf/logs/bin 可 Web 访问
---

## 一句话结论

当 conf/server.xml 的 `<Host>` 把 `appBase` 置为空字符串时，Tomcat 会以 `$CATALINA_HOME`（安装目录/启动工作目录）作为 Web 根路径解析请求，导致 conf、logs、bin、work、lib 等本不应暴露的目录及其文件可直接经 HTTP 读取，为配置文件与日志泄露打开入口。

## 原理

- `appBase` 指定虚拟主机部署 Web 应用的物理根目录；取值 `webapps` 时根目录是 `$CATALINA_HOME/webapps/`。
- 当 `appBase=""`（空）时，Tomcat 没有可拼接的部署目录，回退使用当前工作目录即 `$CATALINA_HOME` 本身作为 Web 根。
- `<Context path="/" docBase="...">` 仍把具体工程挂到某个绝对路径，但请求 URI 到文件的解析是从 Web 根（即 CATALINA_HOME）开始查找的；于是 `/conf/server.xml` 指向 `$CATALINA_HOME/conf/server.xml`，`/logs/xxx.log` 指向真实日志目录。
- 这与"应用代码有漏洞"无关，是部署配置错误：一体化安装包常直接改 server.xml 把工程放到 webapps-two 等自定义目录，容易顺手把 appBase 留空。
- 危害是"目录映射错误 → 敏感目录可 Web 访问"，是后续读取 server.xml、应用配置、访问日志、class 文件的前提（原文两案例均以此/文件读取为起点）。

## 触发条件

- Tomcat 的 conf/server.xml 中 `<Host appBase="">`（空）。
- 站点可借 URI 访问 Web 根下子目录（无前置拦截或拦截不全）。
- 攻击者能发 HTTP 请求；目录扫描出现 bin/conf/logs/work/lib 等 Tomcat 安装目录特征即为信号。

## 利用步骤

1. 目录扫描发现 bin/conf/logs/work/lib 等 Tomcat 安装目录特征，判断 Web 根可能被设到了 CATALINA_HOME。
2. 直接请求 /conf/server.xml；若被前置规则 403，配合路径参数绕过（见"变体与关联"）。
3. 从 server.xml 读出 `<Context docBase>` / `<Host appBase>`，得到工程绝对路径与 Web 根。
4. 按绝对路径读取 WEB-INF/classes 配置、应用日志、class 文件，或读 /logs/localhost_access_log.*.txt。
5. 组合后续漏洞（日志 token 重放、后台上传等）扩大战果。

## PoC

缺陷配置与直接读取（最小化示意，未执行）：

```xml
<Host name="localhost" appBase="" unpackWARs="false" autoDeploy="true">
  <Context path="/" docBase="D:/apache-tomcat/tomcat/webapps-two/zzxxxxx" reloadable="false"/>
  <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
         prefix="localhost_access_log" suffix=".txt" pattern="%h %l %u %t &quot;%r&quot; %s %b"/>
</Host>
```

```http
GET /conf/server.xml HTTP/1.1
GET /logs/localhost_access_log.2024-03-22.txt HTTP/1.1
```

本地复现：把 appBase 置空后启动 Tomcat，浏览器访问 /conf/server.xml 即可看到 XML 全文（原文已验证）。

## 变体与关联

- 变体：appBase 指向一个包含 conf/logs 的自定义目录，同样会暴露。
- 变体：前置 nginx 对 /conf、/logs 做 403 时，用 `/;/conf/server.xml` 之类路径参数绕过拦截规则（Tomcat 解析时剥离 `;...`）。
- 关联：与"任意文件读取 + 读中间件配置定位路径"互补——本场景是配置错误直接让敏感目录可访问，后者是有文件读取时如何找准路径。
- 关联：目录扫描出现 /bin、/conf、/logs、/work、/lib 是识别该配置错误的强特征，不要当成普通静态目录。

## 检测与防御

- 检测：Web 根可访问 /conf/server.xml、/logs/、/bin/；server.xml 中出现 `<Host appBase="">`；目录扫描命中 Tomcat 安装目录结构。
- 防御：显式设置 `appBase="webapps"`（或明确的部署目录），绝不留空；不要手动把 appBase 改成安装目录。
- 防御：前置代理拒绝 /conf、/logs、/bin、/work、/WEB-INF、/META-INF，且规范化 URI 后再匹配（防 `;` 绕过）。
- 防御：Tomcat 以低权限用户运行，限制对配置文件与日志目录的读权限；部署后做"敏感目录可访问性"基线检查。
