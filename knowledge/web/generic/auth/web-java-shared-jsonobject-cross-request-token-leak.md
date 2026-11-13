---
id: web-java-shared-jsonobject-cross-request-token-leak
title: 单例 Controller 共用 JSONObject 跨请求泄露：未认证接口返回已认证请求写入的 token
type: scenario
domain: web
path: web/generic/auth
technique: shared-jsonobject-cross-request-token-leak
aliases:
- 共享 JSONObject 泄露 token
- jsonObject 共用跨请求
- 单例 Controller 成员变量串数据
- 未认证接口返回认证 token
- Java 单例共享可变状态泄露
tags:
- java
- spring
- singleton
- shared-state
- token-leak
- information-disclosure
- code-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V633
  verified_at: '2026-11-13T00:50:08+08:00'
  notes: 已通读原文并逐张核对37张图（27/30/31/32/36/37为大图，读1200px缩略图；其余原图）：图35 CommonController.sendVerifyCode 为 @AuthInterceptor(InterceptorLevel.NONE) 的 POST /{email}/code，仅 jsonObject.put(status) 后 jsonObject.toString() 返回；图36 同一未认证接口响应残留 exists/message/email/status/token（token=kDGARS...），与卡内 PoC 逐字段一致；图33/17 可见多个 Controller 共用 jsonObject；图34 404 页面仅带 Set-Cookie。已修正卡内图34不支持的『残留数据』表述为仅 Set-Cookie。dedup：top 候选 web-generic-jwt-lin-cms-shared-secret-cross-instance-token-reuse 为跨实例共享 JWT secret（related/new），非同链；dup-scan 30 pair 无涉及；全库无其他共享 JSONObject/成员变量 token 泄露卡。efo 原文未标版本，affected_versions 留空。未验证点：未本机复跑；token 具体语义与可复用性原文未验证，confidence=medium 合理。
---

## 一句话结论

当多个 Controller 共用同一个 `JSONObject`（静态字段、单例 Bean 的成员变量或共享工具方法返回的同一实例）来组装响应时，认证流程写入其中的 token 不会被清理；未认证接口随后把该共享对象序列化返回，就会把最近一次已认证请求残留的 token 泄露给未认证访问者，形成跨请求敏感信息泄露。

## 原理

- Spring 的 Controller/Service 默认是单例：写在类字段上的可变对象（如 `private JSONObject jsonObject = new JSONObject()`）被所有请求、所有线程共享。
- 正常写法应在每个请求方法内新建响应对象；一旦把 `jsonObject` 提为成员变量或静态变量，它的内容就带上了"上一次调用"的状态。
- 认证接口在组装响应时 `jsonObject.put("token", token)`，请求结束后未清空；未认证接口（例如验证码、配置、错误页）只 put 自己的 `status/email` 等字段后直接 `jsonObject.toString()` 返回，序列化结果里仍包含残留的 `token` 键。
- 危害取决于 token 的语义：若它是会话/API 凭据，未认证攻击者可直接复用接管账号；即使 token 一次性或已过期，也构成敏感信息泄露，并可用于进一步探测。
- 该问题与并发无关也成立（串行请求即可残留），并发时会进一步放大为"请求间串数据"：A 用户的响应可能包含 B 用户写入的字段。

## 触发条件

- 响应对象被写成单例 Controller/工具类的成员变量或静态变量，而不是请求内局部变量。
- 某个已认证接口会把 token 或用户敏感信息写入该共享对象。
- 存在未认证可访问、且返回同一对象的接口（本例为发送验证码/错误响应接口）。
- 中间件不重建 Controller 实例（Spring 默认单例即满足）。

## 利用步骤

1. 正常登录/调用认证接口，观察响应中 token 等敏感字段。
2. 找到返回同一 `jsonObject` 的未认证接口（验证码、配置读取、404/错误处理等）。
3. 在已认证请求之后立即访问该未认证接口，检查响应中是否残留 `token`、用户名、邮箱等字段。
4. 取出的 token 用于会话固定/凭据重放，验证是否可接管账号或调用 API。
5. 多用户并发时观察响应串号，确认共享对象范围。

## PoC

未认证请求的响应中直接出现 token 字段（示意）：

```http
POST /common/system@local.host/code HTTP/1.1
Host: target

HTTP/1.1 200
Set-Cookie: JSESSIONID=...; Path=/; HttpOnly

{"exists":false,"message":"原密码不正确","email":"system@local.host","status":"error","token":"<上一个已认证请求写入的 token>"}
```

利用方式：先以任意账号登录触发 token 写入，再用未认证接口读取该 token，最后带 token 访问受保护接口。

## 变体与关联

- 同类共享状态问题还包括：静态 `SimpleDateFormat`（线程安全/串数据）、静态缓存的用户上下文、未在 finally 中 `remove()` 的 ThreadLocal、单例中的 `StringBuilder` 等。
- 若项目使用全局异常处理器/统一响应包装器，共享对象也可能经错误页返回；本例中部分未认证路径返回 404/错误页时同样带出 Set-Cookie（图34仅见 Set-Cookie，未见残留字段）。
- 关联：[[web-nodejs-regexp-global-lastindex-state-auth-bypass]]（同为共享可变状态导致的跨请求安全影响，语言不同）。

## 检测与防御

- 响应对象、`JSONObject`、`StringBuilder` 等可变状态一律在方法内新建，禁止作为单例字段/静态字段。
- 若必须使用 ThreadLocal 保存请求上下文，在 finally 中 `remove()`；请求结束后清空任何复用的响应对象。
- 代码审计时搜索 `private static.*JSONObject`、`private.*JSONObject.*=`（类字段）、`static.*Map`；重点检查认证/登录/验证码相关 Controller。
- 检测：未认证接口响应中出现 token/session/用户名字段；响应字段与请求不匹配；并发下响应串号。
- 响应：轮换泄露的 token/密钥，修复共享对象为请求级实例，审计是否已有账号被接管。
