---
id: web-generic-sqli-mysql-constraint-truncation-admin-overwrite
title: MySQL 约束攻击：超长用户名截断插入覆盖 admin 账户
type: scenario
domain: web
path: web/generic/sqli
technique: mysql-constraint-truncation-username-overwrite
aliases:
- MySQL 约束攻击
- 用户名截断覆盖
- varchar 长度截断注册
- 超长用户名越权
- 约束攻击注册 admin
tags:
- sqli
- mysql
- constraint
- truncation
- auth-bypass
- username
- varchar
- registration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:05:59+08:00'
  notes: 已对照原文核对：varchar(20)、SELECT查重不截断/INSERT非严格模式截断、admin[空格]x覆盖的机制与建表/注册示例均与原文一致；注意原文写admin+20空格+x，卡中示例按20位字段给出admin+15空格+x，等价可用；原文无版本标记，未设置versions；PoC未复现
---

## 一句话结论

当注册逻辑先用 `SELECT` 检查用户名是否存在、再用 `INSERT` 写入，而用户名字段是 `varchar(N)` 且没有唯一约束时，攻击者提交“`admin` + N 个空格 + 额外字符”：`SELECT` 按完整字符串比较查不到重复，`INSERT` 在非严格模式下把超长值截断为 `admin` 写入，于是表中出现一条用户名为 `admin`、密码由攻击者控制的新记录，攻击者用该密码即可登录管理员账户。

## 原理

- **检查与写入使用不同语义**：注册代码通常先执行 `SELECT * FROM users WHERE username = '<input>'` 判断是否存在；`SELECT` 比较的是完整字符串，输入 `admin[20个空格]x` 与已有 `admin` 不相等，因此判定“用户名可用”。
- **MySQL 的隐式截断**：若 `username` 定义为 `varchar(20)`，在非严格 SQL 模式（`STRICT_TRANS_TABLES` 未启用或旧版本默认）下，`INSERT` 超长字符串会截断到列长度并只产生 warning，不报错；截断后的值正好是 `admin`。
- **无唯一约束导致重复行**：如果 `username` 没有 `UNIQUE` 索引，插入不会失败，表中出现两行 `admin`：原管理员行和攻击者新插入的行（密码为攻击者设置）。若存在唯一约束，`INSERT` 会因重复键失败，攻击不成立。
- **登录匹配攻击者行**：登录查询 `SELECT * FROM users WHERE username='admin' AND password='<攻击者密码>'` 会命中攻击者插入的那一行，从而以管理员身份登录。即使后续按用户名取用户时命中不同行，也已获得 admin 身份。
- **本质**：数据库层的长度约束/截断语义与应用层的“字符串相等”检查不一致，属于约束与校验不匹配导致的越权，不是传统 SQL 语法注入。

## 触发条件

- 注册流程先按完整用户名 `SELECT` 查重，再 `INSERT` 写入，且两步使用同一张表。
- 用户名字段有长度限制（如 `varchar(20)`），且 MySQL 处于非严格模式（截断而不是报错）。
- `username` 字段没有 `UNIQUE` 约束/唯一索引。
- 目标管理员用户名长度不超过字段长度，且其用户名可由攻击者预测（如 `admin`）。
- 登录查询以用户名 + 密码匹配，未使用用户 ID 等不可伪造标识。

## 利用步骤

1. 确认注册接口的字段长度限制与数据库类型（报错、响应差异、常见 `varchar(20)`）。
2. 用正常用户名注册，观察是否存在“用户名已存在”的检查。
3. 构造 `admin` + 若干空格 + 额外字符，使完整字符串长度超过字段上限、截断后等于 `admin`；空格数量按字段长度调整（如 20 位字段用 `admin` + 15 个空格 + `x`）。
4. 提交注册，若返回成功，说明查重通过且插入被截断。
5. 用用户名 `admin` 和注册时设置的密码登录，验证是否获得管理员会话。
6. 若插入报错（严格模式/唯一约束），该手法失效，改用其他注入或越权路径。

## PoC

建表与注册逻辑（示意）：

```sql
CREATE TABLE users(
    username varchar(20),
    password varchar(20)
);
```

```php
$username = addslashes($_POST['username']);
$password = addslashes($_POST['password']);
$sql = "select * from users where username = '$username'";
$rs = mysqli_query($conn, $sql);
if ($rs->fetch_row()) {
    die('账号已注册');
} else {
    $sql2 = "insert into users values('$username','$password')";
    mysqli_query($conn, $sql2);
}
```

攻击请求：

```text
username = admin[15个空格]x      # 总长超过 20，截断后为 admin
password = attacker_password
```

插入后表中出现：

```text
username | password
admin    | <原管理员密码>
admin    | attacker_password
```

随后用 `admin` / `attacker_password` 登录成功。

## 变体与关联

- 变体（字段长度）：不同 `varchar(N)` 需调整空格数量，使截断结果恰好为目标用户名；也可利用其它会被截断的字段（邮箱、昵称）影响查重/登录。
- 变体（严格模式）：MySQL 5.7+ 默认 `STRICT_TRANS_TABLES` 时超长插入会报错，需目标显式关闭严格模式或使用旧版本；部分应用会忽略 warning，仍需实测。
- 变体（唯一约束）：有 `UNIQUE` 时插入失败，但可尝试大小写/尾随空格/Unicode 归一化等唯一索引绕过，或转向其他逻辑漏洞。
- 关联：[[web-generic-sqli-login-password-unquoted-or-bypass]]（登录处的 SQL 逻辑绕过）。
- 关联：[[web-generic-sqli-second-order-injection]]（注册时写入脏数据、后续取出触发注入，同属“存储后语义变化”）。
- 边界：使用用户 ID 作为登录/鉴权凭据、注册前做长度校验、数据库严格模式、`username` 唯一索引时，本手法不成立。

## 检测与防御

- 修复：`username` 增加 `UNIQUE` 约束；注册前校验长度与字符集；使用 ID 而非用户名作为用户唯一标识。
- 数据库：启用严格 SQL 模式（`STRICT_TRANS_TABLES`），让超长写入直接报错而不是静默截断；应用检查 `INSERT` 的 warning/affected rows。
- 应用：查重与插入放在同一事务并使用唯一约束兜底；对用户名做规范化（trim、大小写、Unicode NFC）后再比较。
- 检测：注册请求中出现超长用户名、大量尾随空格或与已知管理员同前缀的字符串；数据库中同一 username 出现多行；注册后立即用管理员用户名登录；`INSERT` 产生 truncation warning。
