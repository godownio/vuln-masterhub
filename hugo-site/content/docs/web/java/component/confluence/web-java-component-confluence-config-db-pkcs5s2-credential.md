---
id: web-java-component-confluence-config-db-pkcs5s2-credential
title: Confluence 后渗透：confluence.cfg.xml 取数据库凭据 + cwd_user PKCS5S2 哈希破解/替换
type: scenario
domain: web
path: web/java/component/confluence
technique: confluence-config-db-pkcs5s2-credential
tags:
- java
- confluence
- atlassian
- post-exploitation
- credential-access
- pkcs5s2
- hashcat
- database
- cwd_user
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V245
  verified_at: '2026-11-07T12:36:06+08:00'
  notes: 已对照原文与图11/12/13核对：confluence.cfg.xml 中 hibernate connection confluenceuser/confdsdgfd/jdbc:mysql://localhost/confluence 与 jwt keys、Navicat cwd_user admin/cslab 两行及两个PKCS5S2哈希、hashcat -m 12001 top1200.txt 解出123456、三个预计算哈希替换值、空间成员 Harvey/Alana/Sameer/Mia、后续GetNPUsers/喷洒均与原文一致。未验证点：未复跑hashcat/Navicat；原文正文hashcat写rockyou.txt而图12为top1200.txt，卡采用图12的top1200.txt；哈希替换SQL为示意（原文未给SQL）。
url: /docs/web/java/component/confluence/web-java-component-confluence-config-db-pkcs5s2-credential/
draft: false
kb_aliases:
- confluence.cfg.xml
- Confluence 数据库凭据
- Confluence PKCS5S2
- hashcat 12001
- cwd_user 哈希
- Confluence 管理员哈希替换
- Confluence 空间成员枚举
---

## 一句话结论

拿到 Confluence 服务器命令执行/文件读权限后，读取 `confluence.cfg.xml` 可直接获得 `hibernate.connection.username/password`（数据库明文凭据）以及 `jwt.private.key`；连上本地 MySQL 的 Confluence 库查询 `cwd_user` 表，可拿到 `{PKCS5S2}...` 形式的用户口令哈希。弱口令可用 `hashcat -m 12001` 离线破解（原文 cslab 哈希解得 `123456`），或把 admin 的 credential 替换成已知口令的 `{PKCS5S2}` 哈希直接登录后台；后台空间成员表还能给出 AD 用户名，供后续 AS-REQ Roasting/密码喷洒使用。

## 原理

- **配置文件明文凭据**：Confluence 的 `confluence.cfg.xml`（常见路径 `/data/wiki/confluence/confluence.cfg.xml` 与 `shared-home/confluence.cfg.xml`）以 XML 属性保存 `hibernate.connection.url`、`hibernate.connection.username`、`hibernate.connection.password`、`hibernate.connection.driver_class` 等数据库连接信息；拿到文件即可直连数据库。配置里还有 `jwt.private.key`/`jwt.public.key`（原文未进一步利用，但可关注 JWT 伪造面）。
- **用户哈希存储**：Confluence 用户表 `cwd_user` 的 `credential` 列保存 `{PKCS5S2}<base64>`，即 PBKDF2-HMAC-SHA1 派生的口令哈希；`user_name`/`lower_user_name`/`active` 等字段可用于枚举用户。原文通过 Navicat 查出 `admin`、`cslab` 两行。
- **离线破解**：hashcat 模式 `12001` 对应 Atlassian PKCS5S2（PBKDF2-HMAC-SHA1）；原文把 `{PKCS5S2}xUjKeN7GD2/...` 放进 `top1200.txt` 字典，几秒内得到 `123456`。
- **哈希替换登录**：登录校验是比较数据库中的 `credential` 哈希；若攻击者有数据库写权限，可把 admin 的 credential 改成任意已知口令的 `{PKCS5S2}` 哈希（原文给出 `Ab123456`、`123123`、`123456` 三个预计算密文）后用该口令登录后台，不需要破解原密码。
- **从后台到 AD**：Confluence 空间成员表（原文 `cyberstrikelab` 空间成员页）列出 `admin/cslab/Harvey/Alana/Sameer/Mia/harvey/alana/sameer/mia` 等账号；其中 `cslab` 与域内 `cyberstrike.lab\cslab` 同名，后续可用该用户名做 AS-REQ Roasting/密码喷洒。
- **为什么成立**：配置文件权限/数据库权限与 Confluence 进程权限绑定；Confluence 默认把数据库口令明文写在配置里，PKCS5S2 是快速哈希且无盐值轮换/无 MFA 时弱口令可破；数据库 credential 字段没有额外签名，能改库就能改登录凭据。

## 触发条件

- 已获得 Confluence 服务器的命令执行或任意文件读权限（例如 `[[web-java-component-confluence-cve-2022-26134-ognl-rce]]`），或能直接读取 Confluence 安装目录/共享 home。
- `confluence.cfg.xml` 可读，且其中保存了数据库连接信息；数据库（原文为 localhost MySQL）可从当前主机或通过代理访问。
- 数据库账号有 `cwd_user` 的读权限（破解）或写权限（替换哈希）；原文用 Navicat 直连并查询。
- 目标用户使用弱口令或已知口令；若口令强且无写权限，破解/替换都不成立。
- 后台登录未启用 MFA/SSO 强制，或替换的账号不受额外认证保护。

## 利用步骤

1. 在 Confluence 主机上定位配置：`find / -name confluence.cfg.xml`，原文得到 `/data/wiki/confluence/shared-home/confluence.cfg.xml` 和 `/data/wiki/confluence/confluence.cfg.xml`。
2. 读取 `hibernate.connection.url/username/password`（原文 `confluenceuser` / `confdsdgfd`，`jdbc:mysql://localhost/confluence`），必要时记录 `jwt.private.key`。
3. 用 MySQL 客户端/Navicat 连接数据库，查询用户表：`SELECT * FROM cwd_user;`，记录 `user_name` 与 `credential`（`{PKCS5S2}...`）。
4. 破解：`hashcat -m 12001 -a 0 '<PKCS5S2哈希>' top1200.txt`（原文 cslab 哈希解得 `123456`）；或用 `rockyou.txt`/更大字典。
5. 若破解失败但有数据库写权限：把目标账号（如 admin）的 `credential` 替换为已知口令的 `{PKCS5S2}` 哈希（原文给出 `Ab123456`→`{PKCS5S2}ltrb9LlmZ0QDCJvktxd45WgYLOgPt2XTV8X7av2p0mhPvIwofs9bHYVz2OXQ6/kF`、`123123`→`{PKCS5S2}V1J8HcMvYsdtnETu2tjA1gFVQ1L3o+dAsNiooSAcSvpRcbkTR8K4Ha/iWgF145gk`、`123456`→`{PKCS5S2}UokaJs5wj02LBUJABpGmkxvCX0q+IbTdaUfxy1M9tVOeI38j95MRrVxWjNCu6gsm`），再用该口令登录。
6. 登录 Confluence 后台，进入空间成员页（原文 `http://target:8090/display/CYB/cyberstrikelab`）收集用户名/姓名，与域内 AD 账号对应，导出 `user.txt` 供 AS-REQ Roasting/密码喷洒。
7. 后续用 `impacket-GetNPUsers -dc-ip <DC> -usersfile user.txt <domain>/ -no-pass` 探测无预认证账号，或对同名账号做密码喷洒（原文 cslab 喷洒出 `qwe!@#123`）。

## PoC

配置文件关键字段（原文）：

```xml
<property name="hibernate.connection.url">jdbc:mysql://localhost/confluence</property>
<property name="hibernate.connection.username">confluenceuser</property>
<property name="hibernate.connection.password">confdsdgfd</property>
<property name="jwt.private.key">MIIG/gIBADANBgkqhkiG9w0BAQEFAASCBugwggbk...</property>
```

cwd_user 查询与哈希（原文）：

```sql
SELECT * FROM cwd_user;
-- admin  : {PKCS5S2}JYMqFvi/OcwDBkiBJVf9QV/jdE91lgptmigRB6oGmK4JFXnlZY4VQnLCuzcYK7KX
-- cslab  : {PKCS5S2}xUjKeN7GD2/e9WRWD0hpoaPaCuei2O5otn/mBcHv4ZVKT9ttjLQJ8oKvwm20bzDL
```

破解（原文）：

```bash
hashcat -m 12001 -a 0 \
  '{PKCS5S2}xUjKeN7GD2/e9WRWD0hpoaPaCuei2O5otn/mBcHv4ZVKT9ttjLQJ8oKvwm20bzDL' \
  top1200.txt
# ...:123456
```

哈希替换（原文未给 SQL，示意）：

```sql
UPDATE cwd_user SET credential='{PKCS5S2}UokaJs5wj02LBUJABpGmkxvCX0q+IbTdaUfxy1M9tVOeI38j95MRrVxWjNCu6gsm'
WHERE user_name='admin';   -- 之后用 123456 登录
```

原文截图显示 Navicat 的 `cwd_user` 两行、hashcat `Status: Cracked`/`123456`、后台空间成员表与用户列表；本卡未复跑。

## 变体与关联

- **配置文件位置**：不同安装方式下 `confluence.cfg.xml` 可能在 `<confluence-home>` 或 `shared-home`；先 `find` 再读，注意 Docker/集群挂载路径。
- **哈希破解**：`hashcat -m 12001`（Atlassian PKCS5S2）是原文方式；也可用 John 的对应格式或脚本验证 PBKDF2-HMAC-SHA1。字典越大成功率越高，弱口令常见于测试/靶场环境。
- **哈希替换**：需要数据库写权限；替换后目标账号原口令失效，属于破坏性操作。原文给出的是固定口令的预计算哈希，可直接复用。
- **JWT 私钥**：配置里的 `jwt.private.key` 可能用于伪造 Confluence JWT/应用链接；原文只读取未利用，是否可提权需按版本与配置验证。
- **关联**：`[[web-java-component-confluence-cve-2022-26134-ognl-rce]]`（获取服务器权限的入口）、`[[pentest-ad-kerbrute-asreq-username-enumeration]]`/`[[pentest-ad-asrep-roasting-active-etype23]]`/`[[pentest-ad-password-spray-kerberos-reuse-winrm]]`（用空间成员名做 AD 枚举/喷洒）。
- **不是同一场景**：数据库凭据读取与哈希破解是 Confluence 特有的后渗透；不要与通用 MySQL 弱口令卡或 AD 哈希破解卡混为一谈。

## 检测与防御

- **文件与权限**：限制 `confluence.cfg.xml` 的读权限，避免 Confluence 进程以 root 运行；使用专用低权数据库账号，最小权限；定期轮换数据库口令，不与其他系统复用。
- **数据库安全**：限制数据库仅本地/内网访问；审计 `cwd_user` 的异常查询与 `credential` 更新；对 Confluence 数据库账号禁止 DDL/任意 UPDATE。
- **口令策略**：强口令 + MFA/SSO；监控弱口令；PKCS5S2 参数较旧，升级/迁移到更强哈希并加盐轮换；禁止默认/测试账号。
- **检测**：Confluence 主机上 `find confluence.cfg.xml`、`cat` 配置、Navicat/MySQL 直连、hashcat 进程；`cwd_user.credential` 被批量/异常更新；后台登录来自新来源；空间成员被导出后紧跟 AD 的 AS-REQ/喷洒流量。
- **响应**：确认泄露后轮换数据库凭据、重置所有 Confluence 本地账号、检查 `jwt.private.key` 是否需要轮换、排查是否已利用该数据库账号横向。
