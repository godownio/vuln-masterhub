---
id: web-generic-xss-newbeemall-admin-thymeleaf-utext-fields
title: NewBeeMall 后台 th:utext 未转义多字段存储型 XSS：商品信息/订单收件人信息/首页配置跳转链接
type: scenario
domain: web
path: web/generic/xss
technique: newbeemall-admin-thymeleaf-utext-stored-xss
tags:
- xss
- stored-xss
- thymeleaf
- utext
- java
- spring
- newbee-mall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:04:37+08:00'
  notes: 对照原文与 img27-35：search.html 搜索词为 th:text 转义、payload 被原样显示不弹框（img27/28，负向对照）；商品信息编辑页文本输入框写入 <script>alert("XSS")</script> 后 /admin/goods 商品列表弹窗（img30/31）；订单编辑收件人信息（含 payload）保存后订单管理页弹窗（img32/33）；新品上线配置跳转链接写入 payload 后首页配置页弹窗（img34/35）。核对修正两处：原文未将 search.html 列为 th:utext 示例（其为 th:text 对照），已改正文；截图未显示商品信息字段标签，goodsName 无法确证，已改为商品信息文本字段（名称/简介一类）并同步标题与 PoC 注释。与 goods-detail-stored 卡（goodsDetailContent 前台富文本）字段/页面不同，非同链。
url: /docs/web/generic/xss/web-generic-xss-newbeemall-admin-thymeleaf-utext-fields/
draft: false
kb_aliases:
- NewBeeMall 后台存储型XSS
- th:utext 未转义
- 商品名 XSS
- 订单收件人信息 XSS
- 新品上线配置 XSS
- thymeleaf utext xss
---

## 一句话结论

NewBeeMall 后台用的 Thymeleaf 模板对商品信息文本字段、订单收件人信息、首页配置“跳转链接”等字段使用了 `th:utext`（不转义），在这些字段写入 `<script>alert("XSS")</script>` 后保存，打开对应后台页面（商品管理、订单管理、首页配置）即触发弹窗；其中订单收件人信息由普通用户下单时填写，可形成“普通用户 → 管理员”的存储型 XSS。

## 原理

- **Thymeleaf 的两种输出**：`th:text` 对 HTML 特殊字符做转义，`th:utext` 原样输出 HTML。原文以 search.html 的搜索词展示用 `th:text`（payload 被转义、不弹框）作负向对照，并定位到后台商品/订单/首页配置模板中存在 `th:utext` 输出；写入这些字段后打开对应后台页面弹框。
- **注入点与触发页**：
  1. 商品管理 → 商品信息编辑页，在商品信息的文本输入框写入 payload（原文用 `<script>alert("XSS")</script>`；原文未标注具体字段名，截图为商品信息编辑页顶部的文本输入框，应为商品名称/简介一类字段），保存后打开后台商品列表 `/admin/goods` 触发；
  2. 订单管理 → 订单编辑，收件人信息（收件人姓名/地址/备注等文本）写入 payload，保存后打开订单管理页触发；
  3. 首页配置管理 → 新品上线配置，商品“跳转链接”字段写入 payload，保存后打开配置页触发。
- **为什么是存储型**：payload 随业务字段落库，所有打开对应后台页面的管理员都会触发，不是一次性反射。
- **为什么值得关注**：收件人信息在下单/订单流程中由普通用户可控（即使原文是在后台订单编辑里注入，该字段的正常数据来源仍是买家），管理员查看订单时会执行脚本，可读取后台会话（非 HttpOnly Cookie）或代替管理员发起后台操作；商品信息/跳转链接则可在管理员/运营同事之间传播。
- **根因**：输入侧没有 HTML 白名单清洗，输出侧对普通文本字段错误使用不转义输出；对富文本（如商品详情）使用 `th:utext` 是业务需要，但普通文本字段不应如此。
- **边界**：若后台 Cookie 为 HttpOnly、部署了严格 CSP 或对字段做了 HTML 清洗，危害会下降；需要能写对应字段（后台权限或用户下单可控字段），因此原文只证明弹窗。

## 触发条件

- 目标为 NewBeeMall（或同款 Thymeleaf 后台），对应后台页面用 `th:utext` 渲染用户可控字段。
- 攻击者具备后台对应编辑权限（商品/配置），或可通过正常业务写入字段（订单收件人信息）。
- 响应未设置可阻断内联脚本的严格 CSP；后台会话 Cookie 未全部 HttpOnly 时危害更大。

## 利用步骤

1. 进入后台商品管理 → 商品信息编辑页，在商品信息的文本输入框（商品名称/简介一类字段）填入 `<script>alert("XSS")</script>` 保存，打开商品列表确认弹窗。
2. 进入订单管理 → 订单编辑，在收件人信息字段填入 payload 保存，打开订单管理页确认弹窗。
3. 进入首页配置管理 → 新品上线配置，在“跳转链接”填入 payload 保存，打开配置页确认弹窗。
4. 将 payload 换成窃取 Cookie/以管理员身份发起请求的脚本进行危害验证（授权环境内）。
5. 验证后清理测试数据，避免影响线上。

## PoC

```html
<script>alert("XSS")</script>
```

```text
# 1) 商品管理：商品信息编辑页文本输入框保存上述 payload → /admin/goods 列表弹窗（原文截图；具体字段名原文未标注）
# 2) 订单管理：收件人信息字段保存 payload → 订单管理页弹窗
# 3) 首页配置：新品上线配置的“跳转链接”保存 payload → 配置页弹窗
# 原文三个点均以 alert 验证；本卡未在真实目标复跑。
```

## 变体与关联

- 变体：若 `th:utext` 只对部分字段生效，可全局审计模板中的 `th:utext`，逐一回溯字段来源；富文本字段（商品详情）与普通文本字段要区分处理。
- 关联：[[web-generic-xss-newbeemall-goods-detail-stored]]（同产品前台商品详情富文本 XSS，字段是 goodsDetailContent，与本卡的后台字段/页面不同）；[[web-generic-xss-admin-blind-stored-registration]]（后台内容触发的存储型 XSS 同类）。
- 边界：后台自身写入的 payload 属于“自伤”场景，真正有外部攻击价值的是普通用户可控字段（订单收件人信息）；XSS 与 CSRF 组合时，可用同源 fetch 绕过 JSON Content-Type 限制（原文的 CSRF 演示即把 fetch 脚本写进商品详情，经前端渲染执行）。

## 检测与防御

- 检测：模板中搜索 `th:utext`，回溯每个字段是否用户可控；数据库业务表（商品名、订单收件信息、首页配置）中出现 `<script`、`onerror`、`onload`、`javascript:` 等特征；后台页面 CSP 报告与异常外联。
- 修复：普通文本字段一律 `th:text`；确需富文本时在服务端用 HTML 白名单清洗（如 Jsoup Safelist，禁止事件属性与 javascript: URL）后再 `th:utext`。
- 加固：后台会话 Cookie 加 HttpOnly/Secure 与严格 CSP；敏感后台操作加 CSRF token 与二次确认；对商品/配置内容做保存前安全扫描。
