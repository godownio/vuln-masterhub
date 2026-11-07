---
id: web-generic-auth-hanvon-eface-globaltoken-recotoken-forgery
title: 汉王e脸通 globalToken/recoToken 可逆加密伪造：仅校验分段格式与时间戳即可获得 admin 会话
type: scenario
domain: web
path: web/generic/auth
technique: reversible-des-token-format-validation-admin-session-forgery
tags:
- web
- java
- token-forgery
- des
- hardcoded-key
- auth-bypass
- session
- hanvon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:07+08:00'
  notes: 已对照原文与图09-13核对：globalToken非空+decrypt().split(',').length==6+arr[2]/arr[3]纯数字、time=arr[2]+1483200000000L且abs<1800000ms、SessionalUser id=arr[3]/userName=decrypt(arr[4])/realName=decrypt(arr[5])；recoToken length==2+arr2[1]数字后硬编码id=1/admin/'reco server login'；Utils为DES(SecretKeySpec TOKEN_KEY/Cipher DES)，生成PoC与原文一致；原文未附登录响应截图
url: /docs/web/generic/auth/web-generic-auth-hanvon-eface-globaltoken-recotoken-forgery/
draft: false
kb_aliases:
- 汉王e脸通 token 伪造
- globalToken 伪造
- recoToken 伪造
- Utils.encrypt 伪造管理员会话
- 可逆 DES 令牌
---

## 一句话结论

汉王e脸通拦截器从 `globalToken`/`recoToken` 请求参数取令牌，用应用自带的 `Utils.decrypt` 解密后只检查分段数量、数字段和时间戳就写入 `__sessional_user__`；由于加解密是对称且工具类随应用分发，攻击者用同一个 `Utils.encrypt` 构造“6 段 globalToken”或“2 段 recoToken”，即可离线伪造 admin 会话，未登录进入后台。

## 原理

- `UserHandlerInterceptor.preHandle` 在 `__sessional_user__ == null` 时读取 `globalToken`，条件为：token 非空、`Utils.decrypt(token).split(",")` 长度为 6、第 3 段（索引 2）与第 4 段（索引 3）为纯数字。
- 时间校验：`time = Long.parseLong(arr[2]) + 1483200000000L`，与当前时间相差小于 1800000 ms（30 分钟）即通过；随后构造 `SessionalUser`，`id = arr[3]`，`userName = Utils.decrypt(arr[4])`，`realName = Utils.decrypt(arr[5])`，写入 session 并设为当前用户。
- `recoToken` 分支：`Utils.decrypt(recoToken).split(",")` 长度为 2 且第 2 段为数字即通过，直接写入 `__sessional_reco_id__`，并硬编码构造 `id=1`、`userName=admin`、`realName="reco server login"` 的 `SessionalUser` 写入 `__sessional_user__`。
- `Utils.encrypt/decrypt` 使用 DES（`SecretKeySpec(TOKEN_KEY)`、`Cipher.getInstance("DES")`），密钥 `TOKEN_KEY` 定义在随应用分发的 `encrypt.jar` 中；对称加密意味着拿到该 jar（反编译、备份、文件读取或源码泄露）就能对任意明文生成合法密文。
- 令牌本身没有任何签名/服务端状态绑定，也没有“用户是否存在/是否有权限”的校验；校验只覆盖“能解密 + 段数 + 数字段 + 时间窗口”，因此格式合规即可伪造。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本）。
- 攻击者可获得 `encrypt.jar` / `Utils` 类及 `TOKEN_KEY`（产品固件或源码泄露、任意文件读取、反编译安装包等）；若密钥为产品通用硬编码，任一实例即可复用。
- 拦截器对目标接口启用 `globalToken`/`recoToken` 分支（非白名单路径），且目标接口接受该伪造会话。
- 服务器时间与攻击者时间偏差在令牌时间窗口内（globalToken 30 分钟）。

## 利用步骤

1. 从目标应用包/源码/任意文件读取获得 `encrypt.jar`，反编译得到 `Utils.encrypt` 与 `TOKEN_KEY`。
2. 构造 globalToken 明文：`version,ip,time_st,userId,encrypt(userName),encrypt(realName)`；其中 `time_st = 当前毫秒 - 1483200000000`，`userId` 设为 `1`，用户名/姓名为目标管理员值。
3. 调用 `Utils.encrypt(明文)` 得到 globalToken，作为请求参数发送给任意受保护接口。
4. 或构造 recoToken：明文 `version,serverId`，如 `v1,1`，调用 `Utils.encrypt` 后作为 `recoToken` 参数；服务端会直接建立 `id=1`、`admin` 的会话。
5. 携带伪造 token 访问后台接口；若同时配合白名单 `..;/` 绕过，可进一步扩大可达路由。

## PoC

原文 globalToken 生成代码（依赖目标 `com.hanvon.iface.utils.Utils`）：

```java
long curr = System.currentTimeMillis();
long time_st = curr - 1483200000000L;
String data = "v1" + "," + "127.0.0.1" + "," + time_st + "," + "1"
        + "," + Utils.encrypt("admin") + "," + Utils.encrypt("系统管理员");
String globalToken = Utils.encrypt(data);
```

原文 recoToken 生成代码：

```java
String data = "v1" + "," + "1";
String recoToken = Utils.encrypt(data);
```

将结果作为 `globalToken` / `recoToken` 请求参数发送即可。原文仅给出生成与格式验证代码，未附后台登录响应截图。

## 变体与关联

- 参数变体：同一拦截器同时接受 `globalToken`（6 段）与 `recoToken`（2 段），任一即可建立会话；recoToken 分支直接硬编码 admin。
- 密钥获取变体：反编译安装包、读取 `encrypt.jar`、利用任意文件读取下载 jar、从源码/备份泄露获取 `TOKEN_KEY`。
- 关联：伪造会话后可访问本文章中的 SQL 注入、文件上传、文件读取与 fastjson 接口。
- 同类：OA skey 3DES 令牌伪造、硬编码 DES 会话伪造卡（不同产品，同一“可逆密钥 + 弱结构校验”根因）。

## 检测与防御

- 修复：不要把对称加密当签名；改用服务端签发、带 HMAC/签名且绑定用户与过期时间的令牌（如 JWT/HMAC），并在服务端校验用户状态与权限。
- 密钥：移除硬编码 `TOKEN_KEY`，改为部署时注入的随机密钥并支持轮换；不要把加解密工具类随客户端/安装包分发。
- 检测：同一 IP 使用不同 userId 的 globalToken、token 解密后格式异常、recoToken 登录、未登录直接访问后台；对 token 参数做频率与来源异常检测。
- 加固：服务端记录并校验会话创建事件；管理员操作强制二次认证/MFA；对 `recoToken` 这种内部服务令牌限制来源 IP 与固定服务账号。
