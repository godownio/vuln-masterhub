---
id: web-generic-xss-llm-insecure-output-handling-product-review-account-deletion
title: LLM 输出未转义渲染商品评论触发存储型 XSS：绕过评论展示路径防护删除用户账户
type: scenario
domain: web
path: web/generic/xss
technique: llm-insecure-output-handling-stored-xss
aliases:
- insecure output handling in LLMs
- LLM XSS
- 输出处理不安全
- 间接提示注入触发 XSS
- Web LLM attacks
tags:
- web
- xss
- stored-xss
- llm
- prompt-injection
- output-encoding
- burp-lab
- account-deletion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-4
  verified_at: '2026-11-07T21:30:19+08:00'
  notes: 已对照原文及 11 张图核对；图09 显示 LAB Solved，删除账户链已打通，非 DoS/未打通/半链；dedup 除自身外无同链候选，dedup_review 理由成立；未验证点：未独立复现 Burp 靶场，PoC 依赖具体会话/登录态且无自动化脚本；靶场场景无受影响版本未设 affected_versions，路径 web/generic/xss 合法，frontmatter 无 sources/source 违规字段
---

## 一句话结论

把 XSS 载荷藏在攻击者可控的第三方数据（商品评论）里，让集成 LLM 的应用读取该数据并把内容原样输出到未做 HTML 转义的聊天页面，就能绕过"直接查看评论"路径上已有的 XSS 过滤，在受害者浏览器执行任意 JS（示例为提交删除账户表单）；本质是存储型 XSS，LLM 只是新引入、防护缺位的输出通道。

## 原理

- **输出处理不安全（insecure output handling）**：应用把 LLM 返回的文本直接以 `innerHTML`/模板插值渲染进聊天页，未做 HTML 实体转义或白名单 sanitize，于是模型输出里的标签被浏览器当 HTML 解析。
- **数据流**：攻击者可控内容（商品评论）→ LLM 通过工具/API 读取商品详情（详情里包含评论字段）→ LLM 把详情（连同 payload）作为回答复述 → 前端渲染 → 浏览器执行脚本。
- **为什么能绕过已有防护**：商品详情页对评论展示做了输出编码/过滤（评论区里的 payload 被拦下），但"LLM 聊天"这条新增出口没有继承同样的编码策略，形成"同源数据、不同出口、防护不一致"，攻击面随 LLM 集成被重新打开。
- **为什么成立**：payload 并不需要操纵 LLM 的行为，只是被当作普通文本搬运；只要 LLM 忠实复述评论原文、且前端信任模型输出，注入即成立。这也是"传统漏洞在 LLM 集成应用上的新体现"。
- **最终危害**：在查看该商品详情的用户会话中执行任意 JS；示例用 iframe 的 `onload` 提交 `my-account` 的删除账户表单，实现账户删除（CSRF 式敏感操作），危害明确且已打通，不是仅 DoS 或半链。

## 触发条件

- 应用集成 LLM，且 LLM 能读取攻击者可控的外部数据（评论、商品描述、工单、文档、网页、邮件等）。
- LLM 回答被前端以 HTML 方式渲染，且未对模型输出做转义/净化。
- 原数据源的展示路径有 XSS 防护，但 LLM 输出路径缺失或更弱（防护不一致）。
- 受害者会话里存在可被 JS 触发的敏感操作（删除账户、改密、转账）或需要窃取的凭证/令牌。

## 利用步骤

1. 确认 LLM 聊天页存在 XSS：在聊天输入框提交一个简单探针（如带 `onerror`/`onload` 的标签或弹窗），观察是否被解析执行。
2. 确认 LLM 能读取含用户评论的商品详情：询问某商品详细信息，检查返回是否包含 `Reviews`/`Content`/`Author` 等由用户提交的字段。
3. 在该商品的评论里写入 XSS payload（示例为提交删除账户表单的 iframe）。
4. 诱导或等待受害者通过 LLM 询问该商品详情，使 LLM 把含 payload 的评论文本复述到聊天页。
5. 前端渲染 LLM 输出时触发 payload，完成账户删除或任意 JS 执行。
6. 对照直接打开商品详情页：该路径有过滤、payload 不执行，从而确认漏防点位于 LLM 输出通道。

## PoC

商品评论中提交（最小化载荷，借助 `my-account` 页面第二个表单完成删除账户）：

```html
<iframe src =my-account onload = this.contentDocument.forms[1].submit() >
```

随后在 LLM 聊天框提问"告诉我 Lightweight 'l33t' Leather Jacket 的详细信息"，模型输出商品详情（含 Reviews/Content 字段）时前端渲染即触发。聊天页探测阶段可用 `<img src=1 onerror=...>` 类探针确认是否解析。无自动化利用脚本（依赖具体靶场会话与登录态）。

## 变体与关联

- **变体**：payload 换成窃取 Cookie/token、键盘记录、以受害者身份发起任意请求；数据源换成邮件、RAG 文档、工单、第三方网页，本质同为"不可信外部数据经 LLM 输出通道落地"。
- **关联**：属于"间接提示注入 + 不安全输出处理"的组合；与 RAG 检索污染（文档注入）、MCP 工具返回内容不可信同源；与 [[ai-security-mcp-security-github-malicious-issue-indirect-injection-private-repo-exfil]] 同属 LLM 集成应用对不可信数据处理不当。
- **区别**：与"让 LLM 执行恶意指令"的提示注入不同，这里只把 LLM 当作数据搬运通道，不要求模型被越狱。

## 检测与防御

- **输出侧**：对 LLM 输出按与用户输入同等标准做上下文相关的输出编码/sanitize（HTML 实体转义、属性白名单、禁止 `innerHTML` 直插）；不要因为"内容来自模型"就默认可信。
- **一致性**：统一所有渲染出口的编码策略，新增 LLM/AI 功能时复用既有 XSS 防护，避免出现防护洼地。
- **输入侧**：对 LLM 可读取的第三方内容做清洗与标注；最小权限约束 LLM 可调用的工具与可访问的数据范围。
- **纵深**：部署严格 CSP、Trusted Types、敏感操作二次确认/CSRF Token，降低 XSS 被利用后的实际危害。
- **检测**：监控评论等外部数据中的 HTML 标签与事件属性；审计所有渲染模型输出的前端组件；对聊天页做 XSS 回归测试（把 AI 输出当作不可信输入）。
