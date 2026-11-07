---
id: web-generic-auth-sessionfilter-username-cache-key-session-hijack
title: SessionFilter 用请求参数 userName 查缓存会话：管理员在线时可取回其 SessionNameVO 绕过鉴权
type: scenario
domain: web
path: web/generic/auth
technique: session-cache-key-parameter-session-hijack
aliases:
- userName 参数查缓存会话
- SessionFilter 鉴权绕过
- jccx_cookie_session_xtbz 缓存键
- getCurrentOperatorByCache
- 管理员缓存会话劫持
- /sys/system/* 未授权访问
tags:
- java
- auth-bypass
- session
- cache-key
- parameter-tampering
- servlet-filter
- impersonation
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:50:04+08:00'
  notes: 已对照原文核对：图4-7确认XGXT SessionFilter映射*.action；图43-47确认SYS SessionFilter映射/sys/system/*，currentSessionKey非null即放行，getCurrentOperatorByCache用request.getParameter("userName")拼"jccx_cookie_session_xtbz"+userName查缓存并setModel2Session。未验证点：原文未给出实际请求/响应，需目标管理员缓存在线；frontmatter无sources/source_url；未本机复跑。
---

## 一句话结论

Java 后台的 `SessionFilter` 在 `/sys/system/*` 的鉴权逻辑里，先用请求参数 `userName` 覆盖当前用户名，再以 `"jccx_cookie_session_xtbz" + userName` 为键从服务端缓存取 `SessionNameVO`；只要目标管理员此前登录过且缓存仍在，攻击者构造 `/sys/system/任意接口?userName=admin` 就能把该管理员的会话对象写回自己的 session，从而通过 filter 并以管理员身份访问后续接口。

## 原理

- **过滤器入口**：`SessionFilter` 映射 `/sys/system/*`，`doFilter` 先调用 `getCurrentOperatorBySession(request, response)` 获取 `currentSessionKey`；只要返回值非 null 就直接 `chain.doFilter` 放行，不再校验 session 中是否真有当前用户的登录态。
- **身份来源链**：`getCurrentOperatorBySession` 依次尝试：session 属性 `userName` → Cookie `jccx_cookie_session_xtbz` → `getCurrentOperatorByCache(request, response, userName)`。
- **关键的参数覆盖**：进入 `getCurrentOperatorByCache` 后，代码重新执行 `String userName = request.getParameter("userName");`，把调用方传入的已登录用户名替换成**请求参数**；随后用 `MemberCacheUtil.getInstance().get("jccx_cookie_session_xtbz" + userName)` 读取缓存。
- **缓存内容与会话写入**：缓存值是 URL 编码后的 `SessionNameVO` JSON；命中后 `URLDecoder.decode` + `JsonUtil.getObject4JsonString` 还原对象，再 `setModel2Session(request, response, sessionNameVO02)` 写回当前 session，并返回该对象。于是攻击者的 session 被填充为目标管理员的身份信息，`currentSessionKey != null`，filter 放行。
- **为什么成立**：缓存键完全由请求参数拼接，服务端没有校验“这个 userName 是否等于当前已认证用户”；缓存中保存的又是可直接恢复的会话对象。鉴权从“证明你是谁”退化为“说出一个在线用户的名字”。
- **前提与限制**：目标用户名对应的缓存必须存在（通常是管理员近期登录后写入）；攻击者需知道/枚举用户名；原文未给出实际请求截图，属于代码审计结论。

## 触发条件

- 目标使用该 `SessionFilter` 保护 `/sys/system/*`，且 `getCurrentOperatorByCache` 按上述逻辑实现。
- 目标管理员或其他高权限用户处于登录状态，其 `SessionNameVO` 仍在缓存中（未过期/未重启）。
- 攻击者能访问 `/sys/system/*` 下的接口，并知道目标用户名（常见为 `admin`）。
- 过滤器未额外校验请求来源、Cookie 与 session 的绑定关系。

## 利用步骤

1. 确认 `/sys/system/*` 存在 `SessionFilter`，并确认未登录访问会跳转到登录页。
2. 枚举/猜测在线管理员用户名（默认常见 `admin`、`system` 等）。
3. 构造请求 `GET /sys/system/info?userName=admin`（原文示例路径），让 filter 的分支走到 `getCurrentOperatorByCache`。
4. 若缓存命中，服务端把管理员的 `SessionNameVO` 写入当前 session；后续请求携带同一 `JSESSIONID` 访问 `/sys/system/*` 即被当作管理员放行。
5. 验证可访问的敏感功能（用户管理、系统配置等），并评估持久化/横向影响。

## PoC

原文未给出实际请求/响应截图；示例请求如下（需目标管理员缓存存在）：

```http
GET /sys/system/info?userName=admin HTTP/1.1
Host: target
Cookie: JSESSIONID=<attacker-session>
```

服务端关键逻辑（原文）：

```java
public Object getCurrentOperatorBySession(HttpServletRequest request, HttpServletResponse response) {
    HttpSession session = request.getSession();
    String userName = String.valueOf(session.getAttribute("userName"));
    Object o = this.getCurrentOperatorByCookie(request, response);
    if (o == null) o = this.getCurrentOperatorByCache(request, response, userName);
    ...
}

private Object getCurrentOperatorByCache(HttpServletRequest request, HttpServletResponse response, String username) {
    String userName = request.getParameter("userName");
    String sessionNameVo = (String) MemberCacheUtil.getInstance().get("jccx_cookie_session_xtbz" + userName);
    if (sessionNameVo != null) {
        String newSessionNameVo = URLDecoder.decode(sessionNameVo);
        SessionNameVO vo = (SessionNameVO) JsonUtil.getObject4JsonString(newSessionNameVo, SessionNameVO.class);
        this.setModel2Session(request, response, vo);
        return vo;
    }
    return null;
}
```

## 变体与关联

- 变体：把 `userName` 换成其他在线高权限用户；若缓存键/值可预测，可批量枚举；若 Cookie 分支同样直接解析 JSON（原文代码显示 `URLDecoder.decode` 后 `JsonUtil` 解析，未提签名），还可能存在伪造 Cookie 的独立路径（原文未验证）。
- 关联：`[[web-generic-auth-loginadminfilter-sybz-param-bypass]]`（同系统另一过滤器用请求参数放行）；`[[web-generic-auth-unsigned-cookie-admin-keys]]`（无签名 Cookie 作为身份凭证）；`[[web-generic-auth-sessionfixation]]` 类卡片（会话固定/劫持）。
- 与普通会话劫持的区别：不需要窃取受害者 Cookie，只需在请求里带一个用户名参数，由服务端主动把缓存中的会话对象写入攻击者 session。

## 检测与防御

- 检测：`/sys/system/*` 请求出现 `userName` 参数；同一 session 在短时间内从普通用户变为管理员；缓存键查询日志中出现异常用户名；管理员在线期间出现来源 IP 不同的管理员操作。
- 修复：鉴权身份只能来自服务端已认证的 session/令牌，禁止用请求参数覆盖用户名；缓存键绑定 session id 或不可预测 token，并校验请求者与缓存主体一致。
- 缓解：缩短会话缓存 TTL；管理员操作二次认证；监控 `userName` 参数与越权访问；对敏感接口增加来源 IP/设备绑定。
