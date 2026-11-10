---
id: web-java-component-tomcat-nooutbound-echo-jsp-webshell-memshell-fallback-suo5
title: 不出网 Tomcat 内存马 500 失败时用命令执行定位 webroot 后 echo 逐行写 JSP 落地 Webshell，再上传 suo5 搭 HTTP 代理隧道
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-no-outbound-command-exec-echo-jsp-webshell-suo5-http-tunnel
aliases:
- 不出网落地 JSP 马
- 内存马 500
- echo 写 webshell
- suo5 代理
tags:
- web
- java
- tomcat
- webshell
- jsp
- no-outbound
- proxy
- tunnel
- intranet
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-34
  verified_at: '2026-11-08T17:48:20+08:00'
  notes: 已对照原文核对：Tomcat 500 JasperException截图、echo写JSP后蚁剑连接成功截图、suo5代理均有佐证；与PUT上传/multipart上传/web.xml覆盖入口不同，差异成立
---

## 一句话结论

已拿到命令执行但目标 ICMP/HTTP 均不出网、内存马注入又因 Tomcat 版本兼容性返回 HTTP 500 失败时，先用命令执行确定 Tomcat 部署根路径，再以 echo 逐行重定向写入一个静态 JSP Webshell 并用蚁剑/冰蝎连接拿到 Web 权限，最后上传 suo5 基于 Web 服务端口搭 SOCKS/HTTP 代理打通内网。

## 原理

- 出网判断：反弹 shell 全失败可先执行 ping/curl 自证不出网（ICMP 与 HTTP 都被禁），此时任何依赖外连的载荷（反弹 shell、JNDI 远程加载）都不可用，必须走"写入可被正常 HTTP 访问的文件"路线。
- 内存马失败原因：filter/servlet 型内存马依赖 Tomcat 版本对应的容器内部 API（StandardContext、FilterDef 等），版本不匹配时 JSP 编译/注入直接抛异常返回 500；本例请求 `/shell.jsp` 报 JasperException，确认是版本兼容问题而非权限问题。
- 静态 JSP 落地：命令执行进程（与 Tomcat 同机同权限）对 webapps/部署目录有写权限，`echo` 逐行重定向写入 JSP 文件，用户请求该路径时 Jasper 编译执行；静态 JSP 不依赖容器内部 API，比内存马抗版本差异。注意 cmd 下引号与特殊字符转义。
- 隧道：suo5 通过 Web 中间件长连接复用 HTTP(S) 通道做全流量 SOCKS 代理，只需要目标 Web 端口可达即可穿透，解决攻击机无法直接访问内网横向目标的问题。

## 触发条件

- 已获得目标（Tomcat 所在 Windows 机器）命令执行。
- 出站 ICMP/HTTP 被禁（反弹 shell 失败），但目标 Web 服务端口对攻击者可达（可经代理访问）。
- Tomcat 版本与所用内存马不兼容（注入报 500），且运行账户对 webroot 有写权限。

## 利用步骤

1. 命令执行 `ipconfig /all` 确认网段与 DNS（DNS 指向内网 IP 提示域环境）。
2. 尝试各类型反弹 shell 失败，再用 ping/HTTP 请求确认 ICMP、HTTP 均不出网。
3. 注入内存马返回 HTTP 500（JasperException 处理 JSP 异常堆栈），判定为 Tomcat 版本兼容问题。
4. 命令执行定位 Web 根路径，`echo` 分段写入小马 JSP（注意转义与编码）。
5. 用连接工具配置 JSP 类型、UTF8 编码、连接密码（实战用 ant），连接成功拿到 Webshell。
6. 上传 suo5 建立基于 HTTP 的代理隧道，供后续内网扫描与横向使用。

## PoC

无 PoC（操作链见利用步骤；落地文件为简单密码型 JSP Webshell）。

## 变体与关联

- 入口常见为 Shiro 反序列化/Java RCE 得到的命令执行（见 Shiro rememberMe 卡）。
- 若内存马注入成功可优先内存马（无文件），echo 写 JSP 属版本不兼容时的稳定兜底。
- 同类隧道工具还可选 Neo-reGeorg 等，原理一致。

## 检测与防御

- 文件完整性监控/Sysmon 监控 webapps 目录内新建 .jsp 文件及 echo/重定向写文件行为。
- 限制 Tomcat 运行账户对部署目录的写权限，应用以普通账户运行。
- 检测异常长连接与上行流量特征（HTTP 隧道代理）。
