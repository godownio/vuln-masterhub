---
id: web-java-component-tomcat-semicolon-path-param-access-bypass
title: Tomcat 分号路径参数绕过对 conf 与 .log 的访问拦截
type: scenario
domain: web
path: web/java/component/tomcat
technique: tomcat-semicolon-path-parameter-access-bypass
aliases:
- /;/ 绕过
- 分号路径参数
- .log;.txt 绕过
- URI 路径参数绕过 403
tags:
- tomcat
- 分号
- 路径参数
- 访问绕过
- nginx
- 403
- 路径规范化
- 文件读取
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-2
  verified_at: '2026-11-07T21:40:23+08:00'
  notes: 已对照原文核对；/;/conf/server.xml绕过403与.log;.txt绕过扩展名拦截与图23/24/27/32一致；dedup_review对比jsherp与newbeemall等鉴权绕过卡成立，本卡目标为静态路径拦截而非鉴权Filter，非同一利用链；原文仅目标环境tomcat8，已clear
---

## 一句话结论

Tomcat 支持 URI 中的 `;` 路径参数，解析时会把 `;...` 从路径中剥离；而前置 nginx/WAF 或后端拦截规则常按原始 URI 字符串匹配 `/conf`、`.log` 等特征。在路径中插入 `;` 后拦截规则匹配不上而放行，Tomcat 却仍读取到目标文件，从而绕过 403 与扩展名黑名单。

## 原理

- HTTP URI 允许分段携带 `;param` 形式的路径参数（如 `/path;jsessionid=xxx`）。Servlet 容器（Tomcat）在映射资源前会去掉路径参数，用归一化后的路径查找文件。
- 前置代理/静态规则若直接用 `$uri` 或正则 `^/conf`、拒绝 `\.log$`，看到的是含 `;` 的原始串：`/;/conf/server.xml` 不以 `/conf` 开头、`log-warn-...log;.txt` 以 `.txt` 结尾，于是放行。
- 请求到达 Tomcat 后：`/;/conf/server.xml` 被规范化为 `/conf/server.xml`，`xxx.log;.txt` 被规范化为 `xxx.log`，仍命中真实敏感文件。校验点与执行点解析不一致，形成绕过。
- 这与目录映射错误（appBase 为空）常相伴：前者让 conf/logs 落到 Web 根，后者用来突破对这些路径的拦截。

## 触发条件

- 前置代理/应用对敏感路径（conf、WEB-INF）或敏感扩展名（.log、.xml）做基于原始 URI 字符串的黑名单拦截。
- 后端为 Tomcat（或同样支持 `;` 路径参数的 Servlet 容器），且拦截规则未做 URI 归一化后再匹配。
- 目标文件真实存在且位于 Web 可解析路径下。

## 利用步骤

1. 直接请求 /conf/server.xml 或 /logs/xxx.log 被 403/404，确认存在拦截。
2. 在路径首段插入 `;`：`/;/conf/server.xml`，观察是否 200 并返回文件内容。
3. 对扩展名黑名单，在真实文件名后追加 `;.txt`：`/logs/.../log-warn-2025-02-20.0.log;.txt`。
4. 成功后按归一化后的真实路径继续读取配置、日志、WEB-INF/classes 下的文件。
5. 若单一 `;` 不行，尝试 `/;a/`、`/./;/`、多重 `;`、URL 编码 `%3b` 等组合。

## PoC

```http
# 拦截 /conf → 403，插入分号后 200
GET /conf/server.xml HTTP/1.1        -> 403 Forbidden
GET /;/conf/server.xml HTTP/1.1      -> 200，返回 server.xml 全文

# 拦截 .log → 用 ;.txt 让后缀检查落空
GET /logs/zzxxx/warn/log-warn-2025-02-20.0.log HTTP/1.1        -> 拒绝
GET /logs/zzxxx/warn/log-warn-2025-02-20.0.log;.txt HTTP/1.1   -> 200，返回日志内容
```

## 变体与关联

- 变体：`;` 后可带任意参数名（`;jsessionid=`、`;a=`），或放在路径中段 `/conf/;x/server.xml`。
- 变体：与目录穿越 `../`、双重编码 `%3b`、反斜杠等组合绕过更复杂规则。
- 关联：凡"校验用原始 URI、执行用容器归一化路径"的链路都可能复现（Spring `;jsessionid=`、Shiro 历史绕过同理）。
- 关联：本技巧是读取 server.xml、application.yml、logback-spring.xml、.log 日志的前置手段。

## 检测与防御

- 检测：请求 URI 中出现 `;`（含 `%3b`）、`;/`、`;.txt`，尤其紧邻被保护路径或敏感扩展名；同一资源先 403 后 200。
- 防御：拦截规则先对 URI 做完整规范化（去路径参数、解码、解析 `../`、统一大小写）再匹配，拒绝含路径参数的敏感路径。
- 防御：不要在 Web 根下暴露 conf/logs/WEB-INF；用白名单限定可访问路径与扩展名，而非黑名单。
- 防御：由单一层（前置代理或容器）统一做访问控制，避免"代理看原始串、Tomcat 看归一化串"的解析分歧。
