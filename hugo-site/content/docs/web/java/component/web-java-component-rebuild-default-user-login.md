---
id: web-java-component-rebuild-default-user-login
title: Rebuild 内置默认账号 admin/admin 与 rebuild/rebuild 可直接登录管理后台
type: scenario
domain: web
path: web/java/component
technique: default-credentials-built-in-users
tags:
- java
- rebuild
- default-credentials
- login
- unauthorized
- credential
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V600
  verified_at: '2026-11-12T17:24:41+08:00'
  notes: 已对照原文与图03/04核对：LoginController@PostMapping(user-login) vcode默认不开启、retry>3且vcode为空才要求验证码、checkUser用预编译SQL(select password from User where loginName=? or email=?)+EncryptUtils.toSHA256Hex校验，与卡片一致；原文明确admin/admin、system/system(默认未激活)、rebuild/rebuild三组内置账号，admin与rebuild可直接登录；原文仅'下载最新版3.5.4'为目标环境版本、未声明受影响区间，故不设affected_versions；与RuoYi/JumpServer等异产品默认口令卡非同链；未验证点：未实际登录(文中目标为作者内网192.168.1.2)
url: /docs/web/java/component/web-java-component-rebuild-default-user-login/
draft: false
kb_aliases:
- Rebuild 默认口令
- rebuild/rebuild 登录
- Rebuild admin/admin
- Rebuild 内置账号
- Rebuild 后台默认密码
---

## 一句话结论

Rebuild 的登录校验逻辑内置了 `admin/admin`、`system/system`、`rebuild/rebuild` 三组账号，其中 `system` 默认未激活，`admin/admin` 与 `rebuild/rebuild` 可直接登录；未修改默认口令的部署会被直接接管后台。

## 原理

- `LoginController#userLogin`（`@PostMapping("user-login")`）先做验证码判断：验证码默认不开启，只有 `retry > 3` 且 `vcode` 为空时才要求验证码，因此前三次口令尝试不受验证码约束。
- 随后取 `user` 参数与密码，调用 `LoginToken.checkUser(user, password)`。
- `checkUser` 先 `Application.getUserStore().existsUser(user)` 判断用户存在，再取 User 并检查 `isActive()`；然后执行预编译查询 `select password from User where loginName = ? or email = ?`，把库中口令与 `EncryptUtils.toSHA256Hex(password)` 比较。SQL 使用预编译，注入不成立，但校验只覆盖"用户存在 + 口令哈希匹配"，默认账号本身就成为入口。
- 系统初始化数据里保留了三个内置账号：`admin`（默认口令 `admin`）、`system`（默认口令 `system`，默认未激活）、`rebuild`（默认口令 `rebuild`，可正常登录）。产品名被直接用作演示/系统账号口令。
- 登录成功后即获得对应后台身份；系统配置等操作另需管理员身份，而 `admin`/`rebuild` 本身具备管理员权限，因此默认口令等价于后台接管。
- 该问题不依赖漏洞链：只要登录接口可达且口令未被修改即可利用。

## 触发条件

- 目标 Rebuild 部署未修改内置账号口令，尤其是 `admin` 或 `rebuild`。
- `/user/login` 登录接口可达；验证码默认关闭或攻击者可通过验证码。
- 账号未被禁用：`rebuild` 默认可用，`system` 默认未激活。

## 利用步骤

1. 访问 `/user/login` 识别 Rebuild 登录页。
2. 优先尝试 `admin/admin`；失败后尝试 `rebuild/rebuild`（`system/system` 因默认未激活通常不可用）。
3. 登录成功后进入后台，访问系统配置、用户管理等页面确认管理员权限。
4. 若连续失败触发验证码，等待重试计数重置或评估验证码强度（默认不开启）。
5. 在授权范围内修改口令或新建管理员账号以验证持久化影响。

## PoC

- 浏览器：打开 `http://target/user/login`，用户名 `admin`、口令 `admin`；失败后改用 `rebuild`/`rebuild`。
- HTTP 形式（口令从请求体读取，实际字段名与编码以目标前端为准）：

```http
POST /user/login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

user=admin&password=admin
```

说明：代码中 `password = ServletUtils.getRequestString(request)`，密码取自请求体字符串；原文通过浏览器实际登录验证默认账号，未给出原始 HTTP 报文，HTTP PoC 仅供参考。

## 变体与关联

- `system/system` 默认存在但未激活；管理员手动激活后等同于第三组默认口令。
- 与数据库凭据泄露链组合：读取 `~/.rebuild/.rebuild` 并用默认 AES 密钥解出 DB 口令后，可直连数据库重置用户口令，绕过登录限制，见 [[web-java-component-rebuild-unauth-file-read-install-config-aes-default-key]]。
- 关联：[[web-java-component-finereport-builtin-user-default-password]]、[[web-java-component-druid-monitor-default-credentials]]、[[web-java-component-o2oa-default-credential-invoke-jndi-rce]]（同类内置/默认口令模式）。

## 检测与防御

- 检测：登录日志中 `admin`、`rebuild` 账号从异常 IP 登录或短时间多次失败；默认口令尝试特征。
- 防御：安装后立即修改或禁用内置账号（至少 `admin` 与 `rebuild`），启用验证码并降低失败重试阈值，限制后台访问来源；升级版本并审计用户表是否存在未改密的默认账号。
