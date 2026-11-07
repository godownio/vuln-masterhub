---
id: web-generic-auth-myblog-hardcoded-aes-cookie-forgery
title: MyBlog 硬编码 AES 盐值记住我 Cookie 伪造接管后台
type: scenario
domain: web
path: web/generic/auth/cookie
technique: hardcoded-key-remember-me-cookie-forgery
aliases:
- MyBlog Cookie 伪造
- blog-master 认证绕过
- S_L_ID 伪造
- 记住我 Cookie 伪造
- 硬编码 AES 盐值
- AES_SALT 0123456789abcdef
- remember_me 任意用户登录
tags:
- web
- java
- springboot
- mybatis
- cookie
- auth-bypass
- hardcoded-key
- session-forgery
- myblog
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:29:56+08:00'
  notes: 已对照原文核对：图16-17确认硬编码AES_SALT=0123456789abcdef与USER_IN_COOKIE=S_L_ID，图18确认默认admin uid=1，图19生成EqTraX5StRb4FiQjWzL90g==，图20-21手工写入该Cookie后直接进入后台仪表盘，端到端成立。核对时修正卡内有效期描述：原文setMaxAge(60*30)为1800秒(30分钟)而非30天。未验证点：认证拦截器读取/信任该Cookie的代码原文未展示，仅由直接进入后台推断；frontmatter无sources/source_url；未本机复跑PoC。
---

## 一句话结论

MyBlog（blog-master）在勾选“记住我”时，把用户 `uid` 用硬编码在源码里的 AES 盐值 `0123456789abcdef` 加密后写入 `S_L_ID` Cookie；该 Cookie 既无签名也不与服务端会话绑定，知道源码和默认管理员 `uid=1` 的攻击者可以在本地算出合法 Cookie，直接以管理员身份进入后台。

## 原理

- 登录成功后，后台控制器在 `remember_me` 非空时调用 `TaleUtils.setCookie(response, user.getUid())`。该方法执行：
  ```java
  String val = Tools.enAes(uid.toString(), WebConst.AES_SALT);
  Cookie cookie = new Cookie(WebConst.USER_IN_COOKIE, val);
  cookie.setPath("/");
  cookie.setMaxAge(60 * 30);
  cookie.setSecure(false);
  response.addCookie(cookie);
  ```
- 两个关键常量都硬编码在公开源码中：Cookie 名为 `S_L_ID`（`WebConst.USER_IN_COOKIE`），盐值为 `0123456789abcdef`（`WebConst.AES_SALT`）。
- 加密输入只有 `uid`，没有随机 nonce、过期时间、用户名或服务端密钥参与；同一 `uid` 永远产生同一个 Cookie 值，AES 在这里只起到“可逆编码”的作用。
- 认证侧把该 Cookie 解密出的 `uid` 当作已登录身份使用，没有 HMAC/签名校验，也没有“该 Cookie 是否由本次登录签发”的服务端记录。因此 Cookie 是否“有效”只取决于密文能否被同一盐值解开并映射到用户，而攻击者完全具备这个能力。
- 开源系统部署方通常直接使用默认配置，`AES_SALT` 不会被修改；同时数据库初始化脚本把管理员建成 `uid=1`，使目标身份可预测。二者结合即构成完整的离线伪造链：公开源码提供算法和密钥，默认数据提供目标 uid。

## 触发条件

- 目标使用 MyBlog / blog-master 这套 SpringBoot + MyBatis + Thymeleaf 博客系统，且部署方未修改默认 `AES_SALT`。
- 系统允许“记住我”并据此下发 `S_L_ID` Cookie，认证拦截器信任该 Cookie。
- 攻击者能获取对应版本的公开源码（用于确认 `Tools.enAes` 的 AES 模式、填充和编码方式）。
- 目标存在可预测或可枚举的管理员 `uid`；默认管理员通常为 `uid=1`。

## 利用步骤

1. 识别目标是否为 MyBlog 系博客：观察登录页 `/admin/login`、静态资源与响应特征，或从公开指纹判断。
2. 获取对应版本的公开源码，确认 `WebConst.AES_SALT`、`WebConst.USER_IN_COOKIE` 未改动，并查看 `Tools.enAes` 的 AES 模式/填充/输出编码。
3. 确认目标管理员 `uid`。默认初始化数据中 admin 的 `uid=1`；也可通过后台用户枚举、文章作者信息或其它泄露渠道推断。
4. 在本地用同版本源码编译一个测试类，直接调用项目自身的 `Tools.enAes` 加密目标 uid，避免手写 AES 时模式/填充不一致：
   ```java
   System.out.println(Tools.enAes("1", WebConst.AES_SALT));
   ```
5. 将输出作为 `S_L_ID` 的值写入 Cookie，访问 `/admin` 或任意后台接口。
6. 若返回后台页面且可正常操作业务功能，说明伪造成功；若失败，优先核对 AES 模式、编码（Base64/hex）和 uid 是否正确。

## PoC

原文在本地复现时，用项目自带工具类加密 `uid=1`，得到：

```text
EqTraX5StRb4FiQjWzL90g==
```

构造请求：

```http
GET /admin HTTP/1.1
Host: target:8081
Cookie: S_L_ID=EqTraX5StRb4FiQjWzL90g==
```

随后页面直接进入后台仪表盘，无需输入账号密码。

说明：该密文依赖具体 AES 实现（模式、IV、填充、编码）。换目标时应使用目标同版本源码中的 `Tools.enAes` 现场生成，或先用一个已知账号的合法 Cookie 反推参数，不要直接套用示例密文。

## 变体与关联

- 变体：修改 `AES_SALT` 只能阻止“默认配置”批量利用；若盐值通过源码泄露、配置文件泄露、备份或供应链获取，仍可离线伪造。
- 变体：把目标 uid 换成任意普通用户 uid，可冒充任意用户；遍历 uid 即可批量接管账号。
- 变体：同类“记住我/自动登录令牌”常见缺陷——固定密钥、无签名、无服务端状态、令牌内容仅为用户 ID、有效期由 `setMaxAge(60*30)` 设置为 1800 秒（30 分钟）且不支持服务端吊销。
- 关联：[[web-generic-auth-hardcoded-des-session-forgery]]（硬编码 DES 密钥的会话伪造，利用思路一致，算法与产品不同）。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（Java 生态中另一类硬编码 rememberMe 密钥问题；本卡是身份伪造而非反序列化）。

## 检测与防御

- 修复：不要用固定盐值加密用户 ID 作为登录凭证。改用服务端 Session，或使用带 HMAC/AEAD 签名、包含随机 nonce 与过期时间、并与服务端状态绑定的令牌。
- 修复：密钥/盐值按实例随机生成并安全存储，禁止硬编码在源码中；部署时强制更换默认值。
- 修复：Cookie 设置 `HttpOnly`、`Secure`、`SameSite`；对“记住我”令牌支持服务端吊销和轮换。
- 加固：后台敏感操作二次鉴权；管理员账号不要使用可预测的固定 uid 作为唯一身份依据。
- 检测：出现“有合法 Cookie 但此前无对应登录成功日志”的后台访问；同一 Cookie 在多 IP/设备复用；短时间遍历不同 uid 的 Cookie。由于伪造 Cookie 在密码学上合法，单靠解密校验无法发现，必须结合登录审计与服务端会话记录。
- 自查：在源码中搜索 `AES_SALT`、`enAes`、`setCookie`、`USER_IN_COOKIE`，确认登录凭证是否由固定密钥加密且缺少签名。
