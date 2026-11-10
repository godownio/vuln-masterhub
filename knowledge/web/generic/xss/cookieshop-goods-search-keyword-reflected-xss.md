---
id: cookieshop-goods-search-keyword-reflected-xss
title: CookieShop 商品搜索 keyword 反射型 XSS：JSP 直接输出 ${param.keyword}
type: scenario
domain: web
path: web/generic/xss
technique: reflected-xss
aliases:
- CookieShop 反射型XSS
- goods_search keyword XSS
- 商品搜索 XSS
tags:
- xss
- reflected-xss
- java
- spring-boot
- jsp
- jstl
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:17:32+08:00'
  notes: 已对照原文核对：img32 goods_search.jsp 中 h2 标签直接输出 ${param.keyword}、img33 URL keyword=test<img src=x onerror=alert(/al1ex/)> 弹窗 /al1ex/，sink 为 JSP EL 直接输出请求参数（与 controller 里 model.addAttribute(URLEncoder.encode) 的另一路输出无关），反射型 XSS 实测成立，与同篇存储型 XSS 卡不同 sink，并列保留。未验证点：无。
---

## 一句话结论

CookieShop 的 `GET /goods_search` 把 `keyword` 放进 `Model`，JSP 顶部用 `<h2>搜索 "${param.keyword}" 的结果</h2>` 直接回显，`${param.keyword}` 不做 HTML 转义，构造 `"><img src=x onerror=alert(1)>` 即可在前台页面执行脚本。

## 原理

JSP 的 EL 表达式 `${param.keyword}` 等价于 `request.getParameter("keyword")` 的原始字符串输出，EL 本身不做 HTML 实体编码；只有 `<c:out>`（默认 `escapeXml=true`）或 `fn:escapeXml()` 才会转义。因此该参数从 URL 到响应体是一条没有任何编码的直通链路。

控制器这一侧还存在一个容易误判的细节：`GoodsCustController.goodsSearch` 先做了 `URLEncoder.encode(keyword, "utf-8")` 再放进 `model`：

```java
model.addAttribute("keyword", URLEncoder.encode(keyword, "utf-8"));
return "goods_search";
```

但 JSP 里引用的不是 `${keyword}` 而是 `${param.keyword}`，即直接取原始请求参数，URL 编码那一步对最终输出毫无作用——这正是“看起来做了处理、实际没生效”的典型写法。之所以能执行：`"` 闭合了 `<h2>搜索 "` 的属性/文本上下文，`<img onerror>` 在页面解析时被当作标签插入 DOM 并触发。

## 触发条件

- 目标暴露前台搜索路由 `GET /goods_search`（或 `/goods?keyword=` 同源实现）；
- 模板用 `${param.keyword}`、`${param.xxx}` 或 `<%= request.getParameter(...) %>` 直接输出参数；
- 受害者在已登录/有会话的浏览器中打开攻击者构造的链接。

## 利用步骤

1. 拼接链接：`/goods_search?keyword=<payload>`，payload 需 URL 编码；
2. 用 `"><img src=x onerror=alert(1)>` 验证反射点是否位于 HTML 文本/属性上下文；
3. 触发后确认脚本执行，再把 payload 换成窃取 cookie、发起后台请求或钓鱼浮层的代码；
4. 由于该页面为前台公开路由，可直接投递链接诱导管理员点击（管理员通常同时持有后台会话）。

## PoC

```http
GET /goods_search?keyword=test%3Cimg%20src%3Dx%20onerror%3Dalert(%2Fal%2F)%3E HTTP/1.1
Host: 192.168.204.151:8080
```

响应中被注入的模板片段：

```jsp
<h2>搜索 "${param.keyword}" 的结果</h2>
```

渲染后表单提交即弹出 `/al/`，说明参数未经编码直接进入 HTML。

## 变体与关联

- 参数变体：同一模板若还用 `${param.type}`、`${param.pageNumber}` 等回显，可逐个测试，未编码的都可利用；
- 编码变体：`URLEncoder.encode` 只处理 `%xx` 传输层编码，不处理 HTML 元字符，把 `%3C` 解码成 `<` 后照常执行，是常见的“假修复”；
- 关联：同站存储型 XSS（用户资料/收货地址）可在无交互情况下命中管理员，反射型需要诱导点击；两者常组合成“先反射钓鱼、再存储持久化”；
- 关联：JSP EL 未转义输出是 Java Web 审计的高频 sink，与 `fn:escapeXml` 缺失、`<c:out>` 误用同源。

## 检测与防御

- 输出编码：把 `${param.keyword}` 改为 `<c:out value="${param.keyword}"/>` 或 `${fn:escapeXml(param.keyword)}`；
- 编码位置：统一在视图层做上下文相关编码（HTML/属性/JS/URL 分别处理），不要依赖控制器里的 `URLEncoder`；
- 响应头：为全站设置 `Content-Type: text/html; charset=UTF-8` 与 `X-Content-Type-Options: nosniff`，并部署 CSP（禁止 inline script 与 `onerror` 一类内联事件）；
- 检测：在搜索参数中注入 `"><svg/onload=alert(1)>` 观察是否原样回显；SIEM 监控 URL 中的 `<script`、`onerror=`、`javascript:` 编码变体。
