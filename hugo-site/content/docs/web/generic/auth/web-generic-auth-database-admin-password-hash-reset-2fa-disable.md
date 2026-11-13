---
id: web-generic-auth-database-admin-password-hash-reset-2fa-disable
title: 控制数据库后登录后台：从 Spring datasource 配置取凭据、按已知哈希格式改写 admin 密码，并改 config 表关闭 Google 2FA 后恢复原值
type: scenario
domain: web
path: web/generic/auth
technique: database-admin-hash-reset-google-2fa-config-disable
tags:
- java
- spring
- mysql
- password-hash
- admin-panel
- 2fa-bypass
- post-exploitation
- webshell
- code-audit
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V508
  verified_at: '2026-11-11T04:46:51+08:00'
  notes: 已对照原文与7张图逐张核对。重点两项：(1) md5公式：原文为 md5(md5(password明文)@用户名)，卡片一致；已用Python复算 md5(md5('123456')+'@'+'admin')=dd95a7354329cf3c2586446076f4ca3d，与原文更新值完全一致，并把该实测hash补入原理/步骤/PoC（注明账号名不同需重算）、把源码调用改为截图中的 SecurityUtil.cryptMd5(new String[]{password+'@'+account})。(2) 2FA关闭：原文按 is_bound_google_auth 配置判断（config_value='1' 才走Google验证），关闭SQL为 update gameplat_sc_data.config set config_value='0' where config_key='is_bound_google_auth'，恢复为'1'，与图05-07代码/图06 SQL一致；卡片一致。其余核对：图01 login函数与admin.getPassword().equals(md5Password)、图02 adminService.login调用、图03 datasource-master.xml明文root凭据(jdbc:mysql://localhost:3306/gameplat_sc_data)、图04 改hash后登录后台成功。dedup：最高候选 webshell-source-download-jdbc-dbadmin-md5-reuse(cos0.8808) 为读源码+弱MD5爆破的只读路线，本卡为写库改hash+关2FA配置并恢复，非同链；SQLi union伪造卡入口不同；dup-scan 30对无本篇。非组件版本类，未设affected_versions。PoC未复跑（hash可复算已验证）。
url: /docs/web/generic/auth/web-generic-auth-database-admin-password-hash-reset-2fa-disable/
draft: false
kb_aliases:
- 改数据库 admin 密码登录后台
- md5(md5(password)@用户名) 哈希构造
- is_bound_google_auth 关闭
- config 表关闭 Google 验证码
- datasource-master.xml 数据库凭据
- 后台管理员哈希重置
---

## 一句话结论

在已通过 webshell/源码泄露掌握应用配置的前提下，可从 Spring 的 `datasource-master.xml` 拿到明文数据库账号密码，直接连库按源码中的哈希格式（如 `md5(md5(明文)@用户名)`）把目标管理员账号的 password 改成已知明文对应的 hash 登录后台，或把 `config` 表里 `is_bound_google_auth` 之类的开关改为 0 关闭 Google 二次验证；操作完成后恢复原 hash/配置以降低被发现概率。

## 原理

- **数据库凭据就在应用配置里**：Java/Spring 项目通常把 `jdbc:mysql://host:3306/db`、`username`、`password` 明文写在 `WEB-INF/classes/spring/datasource-master.xml`（或 properties/yml）中；拿到 webshell 或源码即获得数据库访问权（本文前提是未授权文件上传已上马）。
- **哈希格式可从源码还原**：登录逻辑把口令与账号拼接后交 `SecurityUtil.cryptMd5(new String[]{password + "@" + account})` 计算再与库中 `admin.getPassword()` 比对；按原文示例可复算，实际存储值是 `md5(md5(明文) + "@" + 用户名)`（`123456`/`admin` 对应 `dd95a7354329cf3c2586446076f4ca3d`，与 `md5(md5("123456")+"@admin")` 一致）。salt 是用户名而非随机值，所以对目标账号（如 admin）可以用任意已知明文（123456）预先算出合法 hash 写库，无需知道原密码，也不需要爆破。
- **数据库表定位**：管理员表在业务库（示例 `gameplat_sc_data.admin`）；二次验证开关在配置表（示例 `config` 表，字段 `config_key`/`config_value`）。登录代码先 `configService.getByKey("is_bound_google_auth")` → `SELECT * FROM config WHERE config_key = ? ORDER BY config_sort`，若 `config_value='1'` 才走 Google 验证；改为 `'0'` 后登录流程直接跳过验证。
- **为什么可行**：认证的最终裁决是"数据库中的 hash 是否等于输入计算的 hash"和"配置是否要求 2FA"；拥有数据库写权限就能同时篡改两者。应用层没有对"管理员 hash 被更新"或"2FA 配置被关闭"做独立完整性校验（无签名、无审计告警）。
- **隐蔽操作**：在虚拟终端连接数据库前执行 `set +o history; history -d 1` 避免命令进入 shell history；改完登录后把 admin 表 hash 与 config 值恢复原样，减少管理员察觉。
- **注意**：若密码使用 bcrypt/argon2 等带随机 salt 的算法，无法直接构造已知明文 hash（需改配置/替换账号逻辑）；若应用数据库账号只有业务表读写权限而无法写 admin/config 表，则该方法失效。

## 触发条件

- 已控制目标主机或应用（webshell/命令执行/源码泄露），能读取 Spring 数据源配置文件或等效凭据。
- 数据库允许从当前主机/网络访问，且应用账号对 admin/config 等关键表有写权限。
- 能从源码确认密码哈希算法（含 salt 规则）与 2FA 配置键名/表名。
- 知道或能枚举后台管理员账号名（常见 admin），且目标未对数据库变更做审计告警。
- 测试授权范围内操作，并准备恢复原值。

## 利用步骤

1. 读取应用配置：`/WEB-INF/classes/spring/datasource-master.xml`（或 `application.yml`/`jdbc.properties`）中的 JDBC URL、用户名、密码。
2. 读登录相关源码确认哈希格式（如 `md5(md5(password) + "@" + account)`）、管理员表名与 2FA 配置键。
3. 通过 webshell 虚拟终端（或 SQL 客户端）连接数据库；先 `set +o history; history -d 1` 清理命令历史，并记录目标账号原 hash/配置原值。
4. 对无 2FA 的后台：把管理员 hash 更新为已知明文对应的值：
   ```sql
   -- dd95a7354329cf3c2586446076f4ca3d = md5(md5('123456') + '@' + 'admin')；账号名不同需重算
   update gameplat_sc_data.admin set password='dd95a7354329cf3c2586446076f4ca3d' where account='admin';
   ```
   用 `123456` 登录后台，操作完成后恢复：`update ... set password='<原hash>' where account='admin';`
5. 对带 Google 验证码的后台：先关闭开关再改密码（或仅改配置 + 已知 hash）：
   ```sql
   update gameplat_sc_data.config set config_value='0' where config_key='is_bound_google_auth';
   ```
   登录完成后恢复：
   ```sql
   update gameplat_sc_data.config set config_value='1' where config_key='is_bound_google_auth';
   ```
6. 登录后台查看数据/功能，验证权限；全程记录并恢复原值、清理命令历史。

## PoC

```sql
-- 1) 读原值（便于恢复）
select account, password from gameplat_sc_data.admin where account='admin';
select config_key, config_value from gameplat_sc_data.config where config_key='is_bound_google_auth';

-- 2) 写入已知明文的 hash（哈希格式按源码：md5(md5(明文) + "@" + 用户名)）
--    md5(md5('123456') + '@' + 'admin') = dd95a7354329cf3c2586446076f4ca3d，账号名不同需重算
update gameplat_sc_data.admin set password='dd95a7354329cf3c2586446076f4ca3d' where account='admin';

-- 3) 或关闭 Google 二次验证开关
update gameplat_sc_data.config set config_value='0' where config_key='is_bound_google_auth';

-- 4) 使用 123456（或关闭 2FA 后）登录，操作完恢复
update gameplat_sc_data.admin set password='<原hash>' where account='admin';
update gameplat_sc_data.config set config_value='1' where config_key='is_bound_google_auth';
```

```bash
# webshell 虚拟终端中连接数据库前清理命令历史
set +o history; history -d 1
mysql -uroot -p'<配置文件中的密码>' -e "select 1"
```

说明：示例表名/键名来自具体模板系统，实际以源码与数据库结构为准；hash 值按目标算法在本地计算。

## 变体与关联

- **仅读取不写入的路线**：getshell 后下载源码、从 `jdbc.properties`/`application.yml` 读明文库口令，再 SELECT 管理员表用弱口令解开原 MD5 登录，见 [[pentest-lateral-movement-webshell-source-download-jdbc-dbadmin-md5-reuse]]；本卡的重点是"覆盖哈希/关闭 2FA 配置后再恢复"的写入型手法。
- **无源码但有 SQL 注入**：通过 SQLi（堆叠/写权限）直接 update 管理员 hash 或 config 开关，思路相同；union 伪造 admin 登录哈希见 [[web-generic-sqli-login-union-forge-admin-known-md5]]。
- **2FA 其他关闭方式**：删除/重置管理员绑定的 Google secret、把 `google_auth_secret` 改为空、或直接把 `is_bound_google_auth` 置 0；有的系统把开关放在用户表字段而非全局配置，需按登录代码确认查询表与键。
- **密码哈希变体**：`md5(md5(pw)@user)` 可构造；纯 `md5(pw)` 可直接查彩虹表；bcrypt/argon2 无法离线构造，需改代码/配置或重置流程；若 hash 存于 LDAP/AD，需改目录服务。
- **前提链**：进入数据库的入口不限于本文的前置未授权上传（[[web-generic-file-upload-lkt-uploadimg-type-strreplace-php-webshell]] 一类），还包括命令执行、配置泄露、备份文件泄露、SQL 注入等。
- **边界**：应用账号对 admin/config 表无写权限、数据库仅内网且无可达跳板、或有数据库审计/完整性监控时失效；操作会留下 SQL 审计/日志，恢复原值仍可能被比对发现。

## 检测与防御

- **数据库权限**：应用数据库账号最小权限，禁止对 admin/权限/配置表做 UPDATE，或对这些表使用独立的管理账号；敏感表启用审计（MySQL audit plugin、云数据库 SQL 审计）。
- **应用设计**：管理员密码使用 bcrypt/argon2 等带随机 salt 的算法，登录流程对 hash/2FA 配置读取做完整性校验；2FA 开关变更要求二次认证并记录审计；后台登录与管理操作记录操作人/来源/时间。
- **检测**：SQL 审计中出现 `update admin set password`、`update config set config_value`（尤其 `is_bound_google_auth`）；后台管理员密码 hash 或 2FA 配置在非管理流程中被修改；webshell 虚拟终端/数据库客户端连接与 `set +o history`、`history -d` 等反取证命令。
- **响应**：发现此类变更后立即恢复并轮换管理员口令、重置 2FA 绑定、排查 webshell 与数据库账号权限，审计修改期间的后台操作。
