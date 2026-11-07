---
id: web-generic-sqli-business-exemption-param-filter-bypass
title: 业务豁免参数 operType=132 使 SQL 注入过滤器整体放行
type: scenario
domain: web
path: web/generic/sqli
technique: business-exemption-param-filter-bypass
aliases:
- operType=132
- 过滤器豁免参数
- 业务白名单后门
- SQL 注入过滤器绕过
- 豁免参数绕过 WAF
tags:
- sqli
- waf-bypass
- filter
- exemption
- java
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V4
  verified_at: '2026-11-04T21:42:50+08:00'
  notes: 已对照原文核对：同一payload不带operType=132返回500非法字符拦截，加上后过滤器放行（截图9/10）；豁免实现由黑盒对比推断、无过滤器源码，卡片已标注不确定点；未设versions；未执行PoC
---

## 一句话结论

SQL 注入过滤器内部有一个“业务豁免”分支：请求只要带上 `operType=132`，就被标记为不需要过滤。于是原本返回 500“参数中含有非法字符”的注入请求，加上该参数后直接 302→200，SQL 正常执行——一个客户端可控的豁免参数等于整站注入防护的后门。

## 原理

过滤器通常会对参数做关键字/特殊字符匹配，命中则返回拦截页。为了不误伤某些业务，开发者在过滤器里加入豁免逻辑：当请求携带特定业务标识（示例 `operType=132`）时，跳过全部检查。

问题在于：

- 豁免标识来自客户端参数，攻击者可以任意添加；
- 豁免粒度是“整条请求”，不是“该业务所需的某个参数”；
- 过滤器没有校验该业务标识是否真的对应已认证的业务流程；
- 因此 `id=1 and 1=1` 被拦，而 `id=1 and 1=1&operType=132` 直接放行。

这不是绕过某个正则，而是让过滤器主动放弃检查；本质是“业务白名单/豁免参数 = 防护后门”。

## 触发条件

- 应用存在 SQL 注入过滤器（拦截 `and`、引号、注释等）；
- 过滤器代码含基于请求参数的豁免/白名单分支（如 `operType` 等于某值即 `return`/放行）；
- 攻击者能控制该参数，且目标注入点所在路径受同一过滤器保护；
- 注入点本身存在字符串拼接（否则即使放行也无法注入）。

## 利用步骤

1. 找到受过滤器保护的注入点，先发原始 payload，确认被拦截（500/拦截页/“参数中含有非法字符”）。
2. 从报错、JS、源码或历史请求中寻找业务参数名与豁免值（示例 `operType=132`）。
3. 在 payload 后追加 `&operType=132`，重放同一请求。
4. 观察响应由拦截变为 302/200；对比两次响应，确认 SQL 已执行。
5. 在该请求上继续做 UNION/布尔/时间盲注；若豁免只对特定路径生效，换用对应路径。

## PoC

```http
GET /***Web/news/New_detail.jsp?id=1%20and%201=1 HTTP/1.1
Host: target
```

响应：HTTP 500，页面提示“您发送请求中的参数中含有非法字符！”（过滤器拦截）。

```http
GET /***Web/news/New_detail.jsp?id=1%20and%201=1&operType=132 HTTP/1.1
Host: target
```

响应：HTTP 302 → HTTP 200，SQL 真实执行（过滤器被绕过）。

对比表：

| 请求 | 响应 | 含义 |
|---|---|---|
| `?id=1 and 1=1` | 500 拦截 | 过滤器生效 |
| `?id=1 and 1=1&operType=132` | 302 → 200 | 过滤器被绕过，进入 SQL 执行 |

## 变体与关联

- 变体：其他命名的豁免参数（`from`、`source`、`client`、`isApp`、`debug`、`admin`）；豁免值可能是数字、字符串或布尔；也可能通过 Cookie/Header 传递。
- 变体：路径白名单（`/api/`、`/m/` 不过滤）、方法白名单（POST 不过滤）、Content-Type 白名单（JSON 不过滤）。
- 关联：[[web-generic-sqli-exists-left-boolean-oracle]]（同一系统的盲注利用）；[[web-java-framework-do-filter-reflection-dispatch]]（另一条未授权入口）；[[defense-detection-logstash-nginx-sqli-tagging]]（日志侧识别异常豁免参数）。
- 不确定点：文章未给出过滤器源码，豁免实现由黑盒对比推断；不同版本/部署的豁免参数可能不同。

## 检测与防御

- **代码审计**：搜索过滤器中的 `return`/`chain.doFilter` 提前放行分支，检查判断条件是否来自客户端参数；重点看 `operType`、`isApp`、`source` 一类字段。
- **修复**：豁免必须绑定“已认证身份 + 明确路由 + 方法”，不能由客户端参数单独决定；对豁免请求仍做参数化/安全校验。
- **日志检测**：同一注入 payload 在添加某参数后由 500 变 200/302；异常豁免参数高频出现；过滤器日志记录“豁免命中”的请求。
- **纵深防御**：WAF 与代码层参数化查询并存，不能依赖单一过滤器；对豁免路径做单独审计与告警。
- **测试**：把所有豁免参数/值纳入回归测试，验证“带豁免参数 + 恶意 payload”仍被正确拦截或安全处理。
