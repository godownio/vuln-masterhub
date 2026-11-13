---
id: web-generic-xss-inxedu-question-title-content-stored
title: inxedu 前台提问 title/content 未过滤存储：问题详情页原样输出触发存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: xss-inxedu-question-title-content-stored
tags:
- xss
- stored-xss
- java
- inxedu
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V555
  verified_at: '2026-11-12T00:19:04+08:00'
  notes: 已通读原文并逐张核读20张图：图17 GET /questions/info/12 页面 title/content 为 <script>alert("123")</script>，弹窗显示 127.0.0.1:81 / 123，存储型 XSS 执行已打通；图18 QuestionsController.addQuestions 调试器中文档显示 title="<script>alert(\"123\")\"</script>"、content 同为脚本，且 questionsTag 经 substring(1)、split(",") 构造 QuestionsTagRelation，校验仅 randomCode 与 SingletonLoginUtils.getLoginUserId，与卡内数据流一致；图19/20 为 QuestionsTagRelationServiceImpl/DAO 对应关系，原文文字给出的写入接口 /questions/ajax/add 与卡内一致。dedup 两个 related（ZrLog 后台配置字段、Tmall 多业务字段）为不同产品不同写入点，非同一链；dup-scan 无配对。未验证点：/questions/ajax/add 的原始请求包截图未直接展示（原文以文字给出），后台审核列表触发为原文未验证的扩展推断；PoC 未本机复跑。原文未标版本，不设 affected_versions；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/xss/web-generic-xss-inxedu-question-title-content-stored/
draft: false
kb_aliases:
- inxedu 存储型XSS
- 因酷问答提问XSS
- /questions/ajax/add 存储XSS
- 问题详情 title 弹窗
- 前台提问脚本注入
---

## 一句话结论

inxedu 前台「提问」接口 `/questions/ajax/add` 把用户提交的 `title` 与 `content` 原样落库，问题详情页 `/questions/info/{id}` 渲染时不做 HTML 转义；在标题或正文提交 `<script>alert("123")</script>`，打开问题页即以当前站点源执行脚本，可盗取任意查看该问题的用户（含管理员）会话或发起同源操作。

## 原理

- **存储型 XSS 的两段式**：写入接口 `QuestionsController.addQuestions()` 接收 `title`/`content`（调试器可见 `questions.title = "<script>alert(\"123\")</script>"`、`content` 同为脚本），调用 `questionsService.addQuestions(questions)` 入库；读取接口 `/questions/info/12` 从数据库取值后直接拼进 HTML 模板输出，未做 `htmlspecialchars`/转义。
- **触发位置**：问题详情页展示标题与正文；`title` 位于页面标题/头部区域，`content` 位于正文，两者都是常见输出点，只要模板使用原样输出（如 JSP `${questions.title}` 未转义）即执行。
- **为什么是存储型**：payload 存在数据库，任何访问该问题详情页的用户都会触发，不依赖诱导点击特定 URL；前台问题通常还有后台审核/管理列表，管理员查看时同样触发（可扩展为后台 XSS）。
- **注入参数**：`questionsTag` 参数还会经过 `substring(1)`、`split(",")` 生成 `QuestionsTagRelation`，说明该接口同时把标签写入关联表；title/content 的校验仅为登录与随机码（`randCode`），没有 HTML 过滤。
- **影响**：同源脚本可读取页面数据、以受害者身份发请求（提问/改资料）、窃取 Cookie（若未 HttpOnly）或绕过 CSRF token。

## 触发条件

- 目标为 inxedu（因酷在线教育）开源版。
- 攻击者拥有可提问的前台用户账号（接口要求登录：`SingletonLoginUtils.getLoginUserId` 非 0）。
- 提问接口只校验登录与验证码，不过滤/转义 title、content。
- 问题详情页输出未编码。

## 利用步骤

1. 登录前台普通用户，进入提问页，填写标题/内容为 `<script>alert("123")</script>`，输入验证码后提交。
2. 抓 `POST /questions/ajax/add`，确认参数包含 `title`、`content`、`questionsTag`、`randomCode` 等并成功返回。
3. 打开问题详情 `/questions/info/{questionsId}`，脚本执行（原文弹出 `123`）。
4. 将 payload 换成实际利用代码（读取 document.cookie、发起同源请求、加载外部 JS），诱导管理员查看问题或在后台审核列表触发。

## PoC

```http
POST /questions/ajax/add HTTP/1.1
Host: 127.0.0.1:81
Cookie: JSESSIONID=<...>; inxedulogin_sys_user_=<普通用户>
Content-Type: application/x-www-form-urlencoded

title=%3Cscript%3Ealert(%22123%22)%3C%2Fscript%3E&content=%3Cscript%3Ealert(%22123%22)%3C%2Fscript%3E&questionsTag=3&randomCode=8139
```

详情页触发：

```text
GET /questions/info/12
→ 页面标题/正文输出 <script>alert("123")</script>，浏览器弹出 123
```

## 变体与关联

- 变体：payload 换 `<img src=x onerror=...>` 绕过只过滤 `<script>` 的规则；或利用 `questionsTag` 标签字段在其它页面的输出点。
- 关联：[[web-generic-xss-jfinalcms-profile-realname-beetl-unescaped-default]]（同类「入库不转义、模板原样输出」的 Java 存储型 XSS）、[[cookieshop-user-profile-stored-xss-admin-list]]（存储型 XSS 打到后台列表）。
- 边界：详情页若在输出时做了转义/富文本白名单，则 payload 不执行；仅前台自助提问（self-XSS）时需诱导他人查看才构成实际危害。

## 检测与防御

- 修复：输出编码（HTML 实体转义）是根本；对 title/content 入库前做 HTML 白名单过滤（如 OWASP Java HTML Sanitizer），展示时按纯文本输出。
- 加固：Cookie 设置 HttpOnly/Secure；后台管理页面同样做输出编码；对用户生成内容（UGC）统一走安全模板。
- 检测：审计 JSP/模板中的 `${...}` 原样输出点与 UGC 字段；WAF 对提问参数中的 `<script`、`onerror` 等标签告警；定期扫描库中 UGC 字段的脚本特征。
