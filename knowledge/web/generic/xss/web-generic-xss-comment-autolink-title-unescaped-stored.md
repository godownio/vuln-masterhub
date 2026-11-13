---
id: web-generic-xss-comment-autolink-title-unescaped-stored
title: 评论区站内链接自动转 a 标签时未转义作品标题：标题载荷 + 评论引用组合成二次存储 XSS
type: scenario
domain: web
path: web/generic/xss
technique: comment-autolink-title-unescaped-second-order-xss
aliases:
- 评论区链接自动转换 XSS
- 作品标题组合 XSS
- 锚文本未转义二次存储 XSS
tags:
- xss
- stored
- second-order
- auto-link
- comment
- web
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T15:01:23+08:00'
  notes: 已对照原文与全部10张图核对：图01作品名称表单、图02发布接口JSON中name=<img/src/onerror=alert(1)>、图03作品列表将标题转义为文本、图04评论自动转a的DOM锚文本仅为作品标题、图05评论<h1>11未执行、图06评论粘贴作品URL、图07评论页弹窗1确认XSS、图08评论中破图渲染、图09 fetch触发POST /follow 200、图10消息中心大量关注。已修正两处：cve:null改[]；『【转载】』为created_source=reprint独立徽标、不属于锚文本（图04 DOM），同步修正利用步骤与PoC期望渲染。未验证点：未在本地复现，fetch武器化仅示意。
---

## 一句话结论

当站点把评论区里的站内作品链接自动转换成 `<a>` 标签、并用数据库中存储的作品标题作锚文本且不做 HTML 转义时，攻击者先发布标题为 `<img/src/onerror=...>` 的作品，再到他人评论区粘贴该作品 URL，即可形成"标题存储 + 评论渲染"的二次存储 XSS，浏览评论的用户以自身身份执行任意 JS（可用 fetch 调用同源关注/点赞等 API 放大危害）。

## 原理

- 两个输出上下文的转义策略不一致：作品标题在作品页/列表页输出时做了 HTML 转义（直接提交 `<img/src/onerror=alert(1)>` 只回显文本、不执行）；但评论的"站内链接自动转换"功能在把评论里的站内 URL 替换为 `<a>` 标签时，锚文本直接取目标作品的存储标题拼进 HTML，未按 HTML 文本上下文再次转义。
- 这就是典型的二次（second-order）存储 XSS：恶意数据在标题字段发布时所在的上下文是安全的（被转义），因此绕过了发布环节的过滤假设；随后另一个功能（评论 linkify）把同一份数据取出，在另一个未转义的上下文（HTML 标签内部）渲染，触发点不在存储处而在使用处。
- 载荷 `<img/src/onerror=alert(1)>` 用 `/` 代替空格充当属性分隔符，可绕过对空格的过滤；`<img>` 的 src 不存在导致加载失败，`onerror` 随即执行，不依赖用户交互。
- 自动链接只转换站内链接（外站链接不转换），所以攻击者必须先在站内拥有一个标题可控的对象（作品/文章/帖子），这正是两个功能点组合成立的原因。
- 实测链路：提交作品名载荷时作品页未触发；把该作品 URL 发进评论区后，自动转 a 的锚文本里载荷被当作 HTML 解析，`<img>` 显示为破图并弹出 `alert(1)`，随后替换为 fetch 脚本即可在任意浏览者浏览器里发起同源请求。

## 触发条件

- 站点存在用户可发布、标题可自由编辑的站内对象（作品、文章、帖子等），且能拿到其站内 URL。
- 评论（或私信、动态、弹幕等）支持"站内链接自动转超链接"，且锚文本使用目标对象的存储标题，未做 HTML 转义。
- 评论内容允许粘贴 URL，且能通过审核/无需审核。
- 页面没有拦截 inline 事件处理器的严格 CSP（如 nonce/strict-dynamic）；有严格 CSP 时该 onerror 载荷失效，需要换用其他变体。

## 利用步骤

1. 发布一个作品，名称填 `<img/src/onerror=alert(1)>`（用 `/` 分隔属性规避空格过滤），记下该作品的站内 URL。
2. 到目标作品（他人的作品或热门内容）评论区发评论，内容就是该作品 URL。
3. 评论渲染时 linkify 把 URL 转成 `<a href="作品URL" target="_blank"><img/src/onerror=alert(1)></a>`（图04 的 DOM 显示锚文本仅为作品标题），锚文本中的载荷被解析执行；作品列表中出现的「【转载】」是 `created_source=reprint` 的独立徽标，不属于锚文本。
4. 武器化：将 alert 换成 fetch 调用同源业务 API。例如抓取"关注"接口后构造 POST /follow，body 为 `{"followed_user_id": <攻击者ID>, "state": 1}`，任何浏览评论区的登录用户都会自动关注攻击者；同理可调用点赞、收藏、改资料、发内容等接口，或读取页面敏感数据外带。
5. 诱导或等待目标用户（评论区作者、管理员）浏览该评论页面。

## PoC

最小验证（标题 + 评论组合）：

- 作品标题：`<img/src/onerror=alert(1)>`
- 评论内容：`https://target/作品路径/xxxx`
- 期望渲染结果：`<a href="https://target/作品路径/xxxx" target="_blank"><img/src/onerror=alert(1)></a>`，onerror 执行弹窗（图04 DOM 中锚文本仅为作品标题；「【转载】」为 reprint 徽标，不在链接内）。

武器化示例（XSS 平台托管，浏览者自动关注攻击者，示意）：

```javascript
fetch("https://target/follow", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({ followed_user_id: ATTACKER_ID, state: 1 })
})
```

注：上述 PoC 未在本地执行；文章为不可信数据，仅作原理记录。

## 变体与关联

- 同类二次注入点：@提及（昵称作锚文本）、话题标签、引用转发、markdown 链接自动补全、外链预览卡片（OG/标题）、通知与消息中心回显标题等一切"用存储的用户可控文本填充 HTML"的功能。
- 若自动转换由后端完成，绕过点在后端模板字符串拼接；若由前端 JS 完成，则属客户端二次渲染（DOM XSS 变体），CSP 防护效果因实现而异。
- 若同一标题在其他输出点（富文本、邮件、导出文件）也未转义，可形成独立存储 XSS，与本链叠加扩大影响面。

## 检测与防御

- linkify 生成锚文本时必须用 `textContent` 赋值而非字符串拼接 innerHTML；或对标题统一做 HTML 实体转义后再放入标签文本。
- 所有用户可控字段按最终输出上下文（HTML 文本/属性/JS/URL）转义；不要假设"存储时安全"就代表"所有使用点安全"。
- 部署 CSP：禁止 inline 事件处理器与 inline script，限制 connect-src/form-action，即使 XSS 存在也显著削弱武器化能力。
- 测试方法：创建标题含 `<img src=x onerror=...>` 的对象，在评论中引用其 URL，检查渲染后的 DOM 锚文本是转义文本还是被解析成标签。
