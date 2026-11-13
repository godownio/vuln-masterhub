---
id: web-generic-auth-oa-setup-unauth-reinstall-admin-password
title: Spring Security 放行 /setup/** 导致安装向导未下线：重跑安装连接自有 MySQL 初始化，覆盖管理员密码接管 OA
type: scenario
domain: web
path: web/generic/auth
technique: unauth-setup-reinstall-admin-password-overwrite
tags:
- unauthorized
- installer
- setup
- admin
- password
- spring-security
- oa
- account-takeover
- cloudweb
cve: []
severity: critical
confidence: high
affected_versions: 云网OA 8.0（原文源码目录 yimioa-oa_git8.0 与安装页版本标注）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V582
  verified_at: '2026-11-12T12:51:10+08:00'
  notes: 已对照原文（174 行）与全部 22 张截图核对：图11 WebSecurityConfig 中 antMatchers 列表包含 "/setup/**" 且整体 permitAll；图12 /oa/setup/setup2_mysql.jsp 安装页可匿名访问，填写配置文件路径、root/密码、主机 192.168.177.131:3306、库名 ccc；图13 mysql select user.host 后 update user set host='%' where user='root' 并 flush privileges；图14 重装后以管理员登录成功进入 OA；图15 setup3.jsp 可设置文件上传路径（原文另将上传白名单置空）。卡中原理（/setup/** 放行、无已安装锁、用攻击者 MySQL 初始库重装、口令由 123456 变 111111）、触发条件与利用步骤与原文一致；原文未给出 setup 表单完整 POST 字段，卡中 PoC 已注明'按产品表单字段'；未在本机复跑；无 sources/source_url；affected_versions 云网OA 8.0 有安装页版本标注与源码目录 yimioa-oa_git8.0 佐证。dedup 推荐 new，唯一 related 为 Spring Actuator env 凭据接管（机制不同），与 dev-reset 卡（调试接口重置 admin/admin）入口与 PoC 不同，非同链。
url: /docs/web/generic/auth/web-generic-auth-oa-setup-unauth-reinstall-admin-password/
draft: false
kb_aliases:
- 未授权重装
- setup 安装向导未下线
- 重装覆盖管理员密码
- OA 安装页 get shell
- setup permitAll
- 云网OA setup
---

## 一句话结论

云网OA 的 Spring Security 配置把 `/setup/**` 整体 `permitAll`，且安装完成后安装向导未删除/未加锁；未认证攻击者可以重跑安装流程，指向自己控制并已导入产品初始库（如 `redmoonoa.sql`）的 MySQL，重新初始化系统并写入新的 `application.properties`，管理员密码随之被重置为安装默认值（原文从 123456 变为 111111），随后直接登录接管系统。

## 原理

- 安装向导是产品首次部署时使用的匿名功能，需要访问 `/setup/setup2_mysql.jsp`、`/setup/setup3.jsp` 等页面并写入 `WEB-INF/classes/application.properties`。Spring Security 的 `WebSecurityConfig` 将 `/setup/**` 列入放行列表（`antMatchers(...).permitAll()`），安装完成后该路由仍然存在。
- 安装流程没有“已安装”状态校验（或校验可被重跑绕过），攻击者可重新提交数据库连接参数与安装配置；向导会用这些参数重写配置文件、执行建库/初始化 SQL、重建管理员账户。
- 管理员口令来自初始化 SQL 中的默认值/安装流程生成值；重装后原密码被覆盖，攻击者用默认口令登录即获得管理员权限。原文环境重装前口令为 123456、重装后为 111111，证明口令被安装流程重置。
- 前置的 MySQL 条件：安装向导要求目标能连到一个可用的 MySQL 并已导入初始库。原文在攻击者本地 MySQL 上执行 `update user set host='%' where user='root'` 放开远程登录，再 `source redmoonoa.sql` 导入初始库，使目标可以连接并完成安装。
- 同一入口还能设置“文件上传路径”等环境变量；把它指向 Web 根目录即可让后续上传文件落到可访问目录（原文的上传文件随机名问题见跳过项），进一步扩大影响。

## 触发条件

- 目标 OA 的 `/setup/**` 可未授权访问（安装向导未下线，或网关未拦截）。
- 目标服务器能出网/横向访问攻击者控制的 MySQL（3306），且攻击者已导入与产品版本匹配的初始 SQL。
- 安装向导允许重写 `application.properties` 并重建管理员账户（无安装锁/已安装校验）。
- 攻击者知道该产品的默认管理员口令（或安装流程会重置为可预测值）。

## 利用步骤

1. 访问 `http://TARGET:PORT/oa/setup/` 或直接访问 `/oa/setup/setup2_mysql.jsp`，确认安装向导可匿名访问。
2. 准备攻击者 MySQL：导入产品初始库（原文 `source redmoonoa.sql`），按需放开远程访问：
   ```sql
   update user set host='%' where user='root';
   flush privileges;
   ```
3. 在安装页填入：配置文件路径（指向目标现有 `WEB-INF/classes/application.properties`）、MySQL 主机/端口/用户名/密码/库名，点击“连接测试/下一步”。
4. 在 `/setup/setup3.jsp?db_type=mysql` 设置系统名称、上传路径等环境变量（可设置为 Web 根目录），完成安装。
5. 安装结束后用新写入的管理员默认口令登录（原文重装后为 111111），获得后台管理员权限；进一步上传文件、改配置或继续利用其它漏洞。

## PoC

```text
GET  /oa/setup/setup2_mysql.jsp HTTP/1.1
Host: TARGET:8096
# 页面参数示例（按产品表单字段）：
#   配置文件路径 = .../WEB-INF/classes/application.properties
#   用户名 = root / 密码 = <attacker-mysql-pass>
#   主机名 = ATTACKER_DB / 端口 = 3306 / 数据库名 = <db>
#   -> 连接测试 -> 下一步
POST /oa/setup/... (安装步骤表单)
# 完成后：
POST /oa/login  name=admin&pwd=111111
```

```sql
-- 攻击者 MySQL 侧准备
CREATE DATABASE <db>;
USE <db>;
SOURCE redmoonoa.sql;
UPDATE mysql.user SET host='%' WHERE user='root';
FLUSH PRIVILEGES;
```

## 变体与关联

- 变体：若安装向导需要本地文件路径/权限，可先结合任意文件读取（同产品 `report/download.do`）读取现有 `application.properties`，再用同一数据库参数重装。
- 变体：把“文件上传路径”设为 Web 根目录，并在系统中把上传扩展名白名单置空，可上传任意类型文件（原文验证了 Web 访问，但文件名为时间戳+随机值）。
- 关联：[[web-java-deser-fastjson-cloudweb-updateuisetup-jdbcrowset-jndi]]（同一 `/setup/**` 放行下的 Fastjson 未授权 RCE）、[[web-generic-file-inclusion-cloudweb-report-download-filename-traversal]]（同产品任意文件下载）、[[web-generic-auth-dev-reset-admin-password-default]]（未授权重置管理员口令的同类思路）。
- 边界：安装目录被删除、`/setup/**` 被网关拦截、安装程序有已安装锁且校验严格、目标无法访问攻击者 MySQL、默认口令已被强制修改且安装流程不重置时失效。

## 检测与防御

- 检测：安装完成后仍出现 `/setup/**` 的访问与表单提交；`application.properties` 被重写；管理员口令/账户被重建；目标服务器向陌生 3306 发起连接；安装页返回 200。
- 防御：部署完成后删除安装目录或在 Web 服务器/网关层拒绝 `/setup/**`；安装程序增加“已安装”标记与本地安装令牌；首次登录强制改密且不提供固定默认口令；`application.properties` 只允许应用账户读写；数据库账户最小权限；对配置文件与管理员账户变更做监控。
