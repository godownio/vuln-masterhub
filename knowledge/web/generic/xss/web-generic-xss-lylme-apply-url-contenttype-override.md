---
id: web-generic-xss-lylme-apply-url-contenttype-override
title: LyLme Spage apply/index.php url 参数反射型 XSS：get_head() 把 Content-Type 覆盖回 text/html，json_encode 只转义斜杠
type: scenario
domain: web
path: web/generic/xss
technique: json-url-reflection-content-type-override-xss
aliases:
- LyLme Spage 反射型 XSS
- 六零导航页 XSS
- get_head Content-Type 覆盖
- json_encode 斜杠转义绕过
- apply url XSS
tags:
- web
- php
- xss
- reflected
- json
- content-type
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V516
  verified_at: '2026-11-11T11:53:09+08:00'
  notes: 已对照原文全文与9张图核对：apply/index.php 先 header(application/json)、get_head() 内再 header(text/html) 覆盖（PHP 同名 header 后设置生效，图02 弹 Cookie 实证）；json_encode 默认将 / 转义为 \/ 阻止 </script>，<、> 不转义；已修正卡片原句『" 不在默认转义范围』——实际 json_encode 会把 " 转义为 \"，但 HTML 解析中反斜杠只是普通字符，仍可构成/闭合属性，故 <img src="" onerror=...> 成立。PoC 响应中 icon 已按图01 调试实况修正为 :\/\/\/favicon.ico（payload 无 scheme 时 parse_url 结果）。图片来源：图01 调试器  与 json_encode 输出、图02 浏览器 alert(document.cookie)。原文本节与 SSRF 共用 url 入口但本卡只覆盖反射 XSS+Content-Type 覆盖，与 SSRF 卡为不同 sink、各自原子。dedup：recommendation=new，最近候选 web-generic-xss-jsonp-callback-html-content-type-reflected-xss 为 JSONP callback 注入、成因不同；referer-header-showmsg-reflection 为 Referer 头拼接，均非同链；dup-scan.json 未涉及。去留：保留并 verified。
---

## 一句话结论

LyLme Spage 的 `apply/index.php?url=` 把参数原样传给 `get_head()` 并放进 JSON 的 `url` 字段输出；`get_head()` 内部先执行 `header("Content-type:text/html;charset=utf-8")`，把调用方设置的 `application/json` 覆盖成 `text/html`，浏览器因此按 HTML 解析响应；`json_encode` 只把 `/` 转义成 `\/`（`<`、`>` 不转义），用不需要闭合斜杠的 `<img src="" onerror=alert(document.cookie)>` 即可反射执行。

## 原理

- 入口（`apply/index.php`）：
  ```php
  if(!empty($url = isset($_GET['url']) ? $_GET['url'] : null)) {
      header('Content-Type:application/json');
      $head = get_head($_GET['url']);
      $head = json_encode($head, JSON_UNESCAPED_UNICODE);
      exit($head);
  }
  ```
  `$url` 未经任何过滤直接进入 `get_head()`，最终作为数组的 `"url" => $url` 键进入 JSON。
- `get_head()`（`include/function.php`）第一行是 `header("Content-type:text/html;charset=utf-8");`。由于它是在 `header('Content-Type:application/json')` 之后执行的，最终响应头被覆盖为 `text/html`，这是 XSS 能执行的关键——否则浏览器只会把 JSON 当文本显示。
- `json_encode()` 默认会转义 `/`（输出 `\/`），所以 `</script>` 会变成 `<\/script>` 无法闭合标签；但 `<`、`>` 不在默认转义范围；`"` 会被 json_encode 转义为 `\"`（反斜杠+引号），而 HTML 解析时反斜杠只是普通字符，`\"` 仍可构成/闭合属性，因此不含 `/` 的标签可用，例如 `<img src="" onerror=alert(document.cookie)>`。
- 原文调试截图显示 `$head` 中 `url` 为 `<script>alert(1)</script>`、json_encode 后 `/` 变为 `\/`；改用 img/onerror 后成功弹出 Cookie。

## 触发条件

- 目标运行含该代码的 LyLme Spage 版本（原文未标注具体版本）。
- 攻击者能构造链接诱导受害者访问 `/apply/index.php?url=<payload>`。
- 浏览器把覆盖后的 `text/html` 响应按页面解析（常规浏览器行为）。

## 利用步骤

1. 构造 payload：`<img src="" onerror=alert(document.cookie)>`。
2. URL 编码后拼到 `url` 参数：`/apply/index.php?url=%3Cimg%20src%3D%22%22%20onerror%3Dalert(document.cookie)%3E`。
3. 诱导受害者访问，脚本在受害者浏览器上下文执行，可读取 Cookie/发起同源请求。

## PoC

```http
GET /apply/index.php?url=%3Cimg%20src=%22%22%20onerror=alert(document.cookie)%3E HTTP/1.1
Host: target
```

响应（Content-Type 已被 get_head 覆盖为 text/html）：

```json
{"title":"","charset":"EUC-CN","icon":":\/\/\/favicon.ico","description":null,"keywords":null,"url":"<img src=\"\" onerror=alert(document.cookie)>"}
```

浏览器把其中的 img 标签解析执行，弹出 Cookie。

## 变体与关联

- 变体：`<svg onload=alert(1)>`、`<body onload=...>` 等同样不含 `/` 的标签；`<img src=x onerror=...>` 最常用。
- 变体：若过滤了空格/引号，可用其他事件属性与编码方式；`json_encode` 对其他特殊字符的处理决定了可用 payload 集合。
- 关联：[[web-generic-xss-jsonp-callback-html-content-type-reflected-xss]]——另一类「JSON/JSONP + text/html 响应」反射 XSS，但注入点是 callback 且成因不同。
- 关联：同一 `get_head()/get_curl()` 的盲 SSRF，见 [[web-generic-ssrf-lylme-get-head-curl-blind-timing]]。

## 检测与防御

- 防御：输出时对 `url` 做 HTML 实体编码；不要依赖 `json_encode` 做 HTML 上下文转义。
- 防御：`get_head()` 内不要无条件覆盖 Content-Type，JSON 接口保持 `application/json` 并加 `X-Content-Type-Options: nosniff`。
- 防御：对 `url` 做协议/域名白名单，拒绝非 HTTP(S) 与内网地址（同时缓解 SSRF）。
- 检测：响应头在 JSON 接口上出现 `text/html`；`url` 参数包含 `<`、`onerror`、`onload` 等 HTML/事件关键字；WAF 对反射参数做 HTML 归一化检查。
