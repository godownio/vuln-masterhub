---
id: web-generic-xss-newbeemall-goods-detail-stored
title: newbee-mall 商品详情 goodsDetailContent 原样渲染：后台富文本注入形成前台存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: admin-richtext-goods-detail-stored-xss
aliases:
- newbee-mall 存储型XSS
- 商品详情 XSS
- goodsDetailContent XSS
- 后台富文本 XSS
- 商品编辑器 XSS
tags:
- web
- xss
- stored-xss
- richtext
- java
- spring
- newbee-mall
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T09:20:25+08:00'
  notes: 已对照原文与图19-21核对：图20 POST /admin/goods/save 的 goodsDetailContent 为 <img src=0 onerror=alert(1)> 且返回 200 SUCCESS，图21 前台 /goods/detail/10911 商品页弹窗 1，存储型 XSS 成立；注入点需后台商品编辑会话（原文用管理员 Cookie），卡内 severity medium 与触发条件准确。原文未展示 goods/save controller 源码，卡内“直接绑定并保存、未见过滤”为基于成功 PoC 的合理推断，且已在原理中按前台不转义渲染描述。原文未给版本，未写 affected_versions 正确。PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

newbee-mall 后台商品保存接口 `POST /admin/goods/save` 接收 `goodsDetailContent` 富文本字段，未做 HTML 过滤即入库；前台商品详情页将该字段原样渲染，管理员在编辑器里写入的 `<img src=0 onerror=alert(1)>` 会在所有访问该商品的用户浏览器中执行，形成存储型 XSS。

## 原理

- 后台商品编辑页的富文本编辑器把 HTML 内容放入 `goodsDetailContent`，随 `POST /admin/goods/save` 的 JSON 提交；Controller 直接绑定到商品实体并保存，未见 `Jsoup.clean`、白名单过滤或转义。
- 前台商品详情页为了展示富文本排版，通常使用不转义输出（Thymeleaf `th:utext` 或等价方式）渲染 `goodsDetailContent`；浏览器把其中的 `<img onerror>`、`<svg onload>`、`<script>` 当作页面内容执行。
- 由于内容存储在商品表中，所有访问该商品的用户都会触发，属于持久化存储型 XSS；脚本可读取同源非 HttpOnly Cookie、以受害者身份发起下单/改资料请求、篡改页面或钓鱼。
- 触发条件是“拥有后台商品编辑权限”——恶意管理员、被盗管理员账号或已通过其他漏洞进入后台的攻击者，可借此把 XSS 持久化到前台，攻击范围从后台扩展到所有商城用户。
- 根因是把“富文本”当成可信内容：输入侧未按 HTML 白名单清洗，输出侧又未转义，两个环节同时缺失。

## 触发条件

- 后台商品保存接口接受 `goodsDetailContent` 等富文本字段，且未做服务端 HTML 清洗。
- 前台商品详情页以不转义方式渲染该字段（富文本展示需求常见）。
- 攻击者拥有后台商品管理权限（管理员会话）。
- 响应未设置可阻断内联脚本的严格 CSP。

## 利用步骤

1. 登录后台，进入商品管理 → 商品编辑，抓取 `POST /admin/goods/save` 请求。
2. 在 `goodsDetailContent` 中写入 XSS 载荷（如 `<img src=0 onerror=alert(1)>`），其余商品字段填合法值，保存。
3. 前台打开该商品详情页，确认脚本执行（原文用弹窗验证）。
4. 将商品链接发给目标用户，或以商品页作为持久化载荷等待访问；脚本可进一步窃取 Cookie、发起带 CSRF 的操作。
5. 验证后删除测试商品，避免影响线上。

## PoC

```http
POST /admin/goods/save HTTP/1.1
Host: target
Cookie: JSESSIONID=<管理员会话>
Content-Type: application/json

{
  "goodsName":"test5",
  "goodsIntro":"test5",
  "goodsCategoryId":"20",
  "tag":"test5",
  "originalPrice":"1",
  "sellingPrice":"1",
  "stockNum":"0",
  "goodsDetailContent":"<img src=0 onerror=alert(1)>",
  "goodsCoverImg":"http://target/upload/cover.jpg",
  "goodsCarousel":"http://target/upload/cover.jpg",
  "goodsSellStatus":"0"
}
```

保存后访问 `http://target/goods/detail/<商品ID>`，页面弹窗 `1`。

## 变体与关联

- 变体：把载荷换成 `<svg onload=...>`、`<iframe srcdoc=...>` 或事件属性，绕过简单关键词黑名单。
- 变体：`goodsName`、`goodsIntro`、`tag` 等字段若同样不转义输出，也可作为存储型 XSS 入口。
- 变体：结合后台文件上传的 HTML 上传（见关联卡），可在前台形成多条持久化 XSS 路径。
- 关联：[[web-generic-file-upload-imageio-polyglot-arbitrary-extension]]（同一项目的上传型存储 XSS；本卡是富文本字段型）。
- 关联：[[web-generic-xss-admin-blind-stored-registration]]（后台内容触发的前台/管理端存储型 XSS 的另一入口）。

## 检测与防御

- 防御：服务端对富文本使用 HTML 白名单清洗（如 Jsoup Safelist，仅允许固定标签/属性，禁止事件属性与 javascript: URL）；输出侧按上下文转义，确需富文本时只对已清洗内容使用不转义输出。
- 防御：商品编辑等后台接口加强鉴权与操作审计；管理员会话使用 HttpOnly/Secure Cookie 与严格 CSP。
- 检测：商品表 `goods_detail_content` 中出现 `onerror`、`onload`、`<script`、`<iframe`、`javascript:` 等特征；后台保存请求的富文本字段含事件属性；前台商品页 CSP 报告或可疑外联。
- 检测：对管理员账号异常登录、批量修改商品详情后前台出现脚本告警进行关联分析。
