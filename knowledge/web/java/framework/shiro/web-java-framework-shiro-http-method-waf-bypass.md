---
id: web-java-framework-shiro-http-method-waf-bypass
title: Shiro rememberMe 反序列化被拦截：改用非标准 HTTP 方法绕过安全产品，405 由 MVC 返回但 Shiro 过滤器已反序列化
type: scenario
domain: web
path: web/java/framework/shiro
technique: shiro-rememberme-nonstandard-http-method-waf-bypass
aliases:
- HTTP 请求方法绕过 WAF
- 改请求方法绕过拦截
- 非标准方法 XXX 绕过
- Burp Match and Replace 批量替换方法
- 405 Method Not Allowed 仍打通 Shiro
- rememberMe 利用被拦截绕过
tags:
- java
- shiro
- rememberme
- deserialization
- waf-bypass
- http-method
- burp
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T13:01:41+08:00'
  notes: '已对照原文核对：图05 工具报『Unexpected end of file from server』、图07 请求方法 XXX 返回 405 Method Not Allowed + Allow: GET + Whitelabel Error Page + rememberMe=deleteMe、图08 Burp Match and Replace Request header GET→XXX、图09 批量 XXX 请求出现 200/405、图10 工具『发现构造链』均与卡内描述一致；原文确为修改请求方法后获得返回并跑通链。卡内『405 由 MVC 返回而此时 Shiro 过滤器已反序列化』属依据过滤器顺序的推断，卡内已明确标注为推断且 confidence=medium，合理。路径 web/java/framework/shiro 合法；frontmatter 无 sources/source/source_url/文章 ID；原文匿名目标未给组件版本，affected_versions 已 --clear。dedup 报告 recommendation=new，top 候选 rememberme-spring-interceptor-memshell-classdata 等均只讲 key/内存马/721，不涉及按请求方法拦截后的绕过环节，非同一利用链。未验证点：原文未给端点/密钥/gadget，PoC 为按原文结构重建，未在本机复现。dup-scan.json（2026-11-08）早于本卡建卡（2026-11-09），无涉及本卡的 pair。'
---

## 一句话结论

当 Shiro `rememberMe` 反序列化利用请求被安全产品/WAF 按请求方法拦截（工具发出 GET 无任何响应）时，把请求行的方法改成非标准 token（如 `XXX`）重放，请求就会穿过拦截到达后端；即使 Spring MVC 对未知方法返回 `405 Method Not Allowed` 且 `Allow: GET`，Shiro 过滤器链在此前已经解密并反序列化了 `rememberMe` Cookie，利用链照样执行——405 只能说明请求已到达应用。再用 Burp 的 Match and Replace 把代理流量里的 `GET` 批量替换成 `XXX`，就能让原利用工具跑通整条链。

## 原理

- Shiro 的 `rememberMe` 处理发生在 `ShiroFilter` 过滤器链中：请求进入 Servlet 容器后，`CookieRememberMeManager` 先从 Cookie 取出密文、AES 解密、Java 反序列化，再交给后续过滤器/Servlet。Spring MVC 的 HandlerMapping 对请求方法的校验（`RequestMethod` 匹配）发生在 DispatcherServlet 内，也就是 Shiro 过滤器之后。
- 因此请求方法是否被 MVC 接受，不影响 Shiro 反序列化是否发生。用非标准方法（`XXX`）请求时，Spring MVC 找不到对应映射，返回 `405 Method Not Allowed`、`Allow: GET`；但产生 405 之前，Shiro 过滤器已经处理了 Cookie，gadget 链已执行。
- 安全产品/ WAF 的常见缺陷是按请求方法（GET/POST 等）或"方法+URL"组合做规则匹配与拦截，对不在规则枚举内的任意方法 token 直接放行或无法解析转发。非标准方法因此成为一条"绕过检测但后端仍会处理关键副作用"的通道。
- 为什么工具原先不通：利用工具默认用 GET 携带 `rememberMe` Cookie，被设备拦截/丢弃，Burp 里只看到发出的请求、没有任何响应；换成 `XXX` 后立刻收到 405，说明请求到达了后端，随后工具能正常爆破出可用 gadget 链。
- 关键认知：**405 不是失败信号**。对依赖过滤器阶段副作用的漏洞（Shiro rememberMe、部分 Filter 中的鉴权/反序列化），只要响应来自应用自身（如 Whitelabel Error Page、`Allow` 头），就说明已穿过外围拦截，应继续观察命令执行/回显而不是放弃。

## 触发条件

- 目标使用 Shiro `rememberMe`，且攻击者已掌握可用 AES 密钥与一条可用 gadget 链（密钥可来自 heapdump、配置泄露、硬编码/默认 key 等）。
- 前置安全产品/WAF 会拦截正常方法（GET/POST）的利用请求，但未对任意/非标准 HTTP 方法做同样的规则匹配或方法白名单。
- 后端为 Spring MVC（或类似先过过滤器、后做方法映射的框架），Shiro 过滤器先于方法校验执行。
- 攻击者能把利用工具流量代理到 Burp 等可改写请求的工具。

## 利用步骤

1. 用 Shiro 利用工具发出带 `rememberMe` Cookie 的请求；若没有任何响应/连接被重置，怀疑被安全设备拦截。
2. 在 Burp 中把该请求的方法改成非标准 token（如 `XXX`）重放，观察是否出现应用自身响应（200/405/Whitelabel Error Page）。
3. 若返回 `405 Method Not Allowed` 且 `Allow: GET`，说明请求已到达 Spring MVC，Shiro 过滤器此前已处理 Cookie；继续用该方式跑密钥/利用链。
4. 在 Burp `Proxy → Match and replace rules` 添加规则：Type=`Request header`、Match=`GET`、Replace=`XXX`，让经 Burp 代理的利用工具请求被批量改写。
5. 用工具爆破利用链与回显方式；成功后执行 `whoami`/`ls` 等验证，再用 RCE 结果支撑后续操作。

## PoC

原始利用请求（被拦截，无响应）与绕过请求（到达后端）的差异只在请求方法：

```http
XXX /any/path HTTP/1.1
Host: target
Cookie: rememberMe=<base64(IV + AES-CBC(序列化 gadget))>
Connection: keep-alive
```

响应：

```http
HTTP/1.1 405 Method Not Allowed
Allow: GET
Content-Language: zh-CN
Set-Cookie: rememberMe=deleteMe; Path=/; Max-Age=0

<html><body><h1>Whitelabel Error Page</h1>...
```

Burp 批量改写配置：`Proxy → Match and replace rules → Add`，Type 选 `Request header`，Match 填 `GET`，Replace 填 `XXX`；随后保持利用工具代理指向 Burp，工具发出的每个请求都会被改写为 `XXX` 方法，从而批量绕过拦截并跑通利用链。

说明：原文目标为某匿名安全产品，接口路径、密钥与具体 gadget 均已打码；卡内按原文现象描述机制，`405 时 Shiro 已完成反序列化` 为依据过滤器顺序与响应来源的推断，未在本机复现，confidence 标 medium。

## 变体与关联

- 变体（方法选择）：`PUT`/`DELETE`/`PATCH`/`FOO` 等任意 token；大小写变体（`get`/`Get`）；HTTP/1.0 与 HTTP/1.1 差异；部分栈可用 `X-HTTP-Method-Override` 头影响后续方法判定。
- 变体（绕过点）：WAF 只检查 GET/POST 的 URL 与 Body、不检查非标准方法的 Body；或方法 token 不在解析器白名单导致规则跳过。
- 关联：[[web-java-framework-shiro-550-hardcoded-key-deserialization]]（rememberMe 密文构造与默认 key）、[[web-java-framework-shiro-actuator-heapdump-key-account-forgery]]（heapdump 提取 ShiroKey）、[[web-java-framework-shiro-rememberme-two-stage-memshell-loader]]（拿到执行后的内存马投递）；本卡只解决"利用请求被拦截"这一环。
- 边界：若前置设备对方法白名单严格（只放行 RFC 方法并统一解析所有方法体），或 Shiro 过滤器本身对非预期方法不放行，则该方法无效；此时需回到其它请求走私/编码/分块绕过思路。

## 检测与防御

- 检测：HTTP 历史中出现非标准方法（`XXX`/`FOO` 等）且携带 `rememberMe` Cookie、超长 Base64 Cookie；对任意方法返回 405 却带 `deleteMe` Cookie 的请求；工具化批量请求中方法被统一改写。
- WAF/网关：对所有 HTTP 方法统一解析与检测，显式拒绝未知方法 token；不要把"方法不在规则内"当作放行条件；对 `rememberMe` Cookie 做长度/熵检测与已知 key 黑名单。
- 应用：升级 Shiro、轮换/移除硬编码 key、关闭不必要的 rememberMe；不要把安全边界建立在请求方法上。
- 纵深：Shiro 过滤器只应在受信任边界内运行；对 405 等错误响应也记录完整请求（含 Cookie 指纹），便于发现"错误响应但副作用已发生"的利用。
