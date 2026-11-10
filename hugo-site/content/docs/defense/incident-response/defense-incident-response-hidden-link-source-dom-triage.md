---
id: defense-incident-response-hidden-link-source-dom-triage
title: 网页暗链排查：页面外观正常时，从 meta 关键词与 DOM 中隐藏的 a>img 外链识别被植入的黑帽链接
type: scenario
domain: defense
path: defense/incident-response
technique: hidden-link-source-dom-triage
tags:
- incident-response
- web-tampering
- hidden-link
- defacement
- seo-spam
- dom
- triage
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V475
  verified_at: '2026-11-10T17:05:19+08:00'
  notes: 已对照原文及图9-11核对：meta description/keywords 堆砌与 a>img（/pic/smh1-1.jpg）两种暗链形式与原文一致；排查步骤为作者原文手法归纳，未实测。
url: /docs/defense/incident-response/defense-incident-response-hidden-link-source-dom-triage/
draft: false
kb_aliases:
- 网页暗链排查
- 隐藏外链识别
- meta keywords 关键词堆砌
- a 包 img 暗链
- 空页面暗链
- 黑帽链接排查
---

## 一句话结论

站点渲染正常不代表没被动手脚：暗链常见两种隐蔽形式——把博彩/色情关键词堆进 `meta keywords/description` 或隐藏文本，或用 `<a target="_blank"><img src=...></a>` 把外链藏在图片里；对照浏览器渲染结果与原始 HTML/DOM，就能发现普通访客看不到的非法外链与关键词。

## 原理

- **目的决定藏法**：暗链要给黑帽站点输送搜索引擎权重和流量，既需要被爬虫抓到，又不能让访客和管理员一眼看见，所以放在"渲染不可见、源码可见"的位置。
- **形式一：关键词堆砌**。把大量博彩/色情词写进 `meta name="keywords"`、`meta name="description"` 或不可见元素（`display:none`、`font-size:0`、同背景色文字）。页面视觉无变化，搜索引擎抓源码时会计入关键词。
- **形式二：图片包裹外链**。`<a>` 的 href 指向黑帽站点，内部只放一张图片；图片加载失败、透明或尺寸极小时页面空白，但爬虫能读到链接。也可以把外链直接放进 `<img src>`，由图片请求/跳转承载。空无一文的占位页面最容易被这种暗链利用，因为"没内容"本身不引人怀疑。
- **形式三：脚本注入**。页面被追加非常规域名的 `<script src=...>`，由 JS 完成跳转或加载，源码里能看到与站点无关的脚本域名。
- **检测本质**：渲染视图（可见文本、截图）与源码/DOM 不一致——源码里出现与业务无关的关键词、外链域名和 a/img/script 节点。只看页面功能正常就会漏掉。
- **为什么管理员也常漏**：日常巡检只看页面显示与主业务功能；空页面、占位页被当成"未建设完成"跳过；meta 区从来不检查。

## 触发条件

- 排查方能够查看原始 HTML 源码和 DOM（浏览器 F12、curl、Burp/SQLMap 之外的普通代理响应）。
- 站点存在被写入的痕迹（模板/数据库/上传点/弱口令被利用过），或需要对第三方单位站点做安全情报核实。
- 暗链尚未被清理，注入内容仍在响应中。

## 利用步骤

1. 先看渲染效果，再 Ctrl+U 看源码；搜索 `meta name="keywords"`、`meta name="description"`，检查是否出现博彩/色情/医疗等与业务完全无关的词堆。
2. 搜索源码中的 `<a`、`<iframe`、`<script src=`、`<img`，检查指向非常规域名/IP 的外链；对 `target="_blank"` 的 a 标签逐个看 href 和内部节点。
3. F12 检查 DOM 中被 CSS 隐藏的元素：`display:none`、`visibility:hidden`、`opacity:0`、`position:absolute` 移出视口、同色文字、0 宽高 iframe/img。
4. 对"空无一文"的页面重点检查 DOM 结构，往往仍保留 `<a><img></a>`、隐藏 div 等节点。
5. 取出注入资源的独特路径（如 `/pic/<name>.jpg`）作为指纹，到测绘引擎做 body 检索，定位同批被黑站点。
6. 固定证据（源码、DOM、截图、响应头），删除注入内容并排查写入入口（模板、数据库、上传点、弱口令），同时检查同服务器其他站点。

## PoC

```html
<!-- 形式一：meta 关键词堆砌，页面无可见变化 -->
<meta name="keywords" content="<博彩/色情关键词堆>">

<!-- 形式二：图片包裹外链，页面无可见文字 -->
<a target="_blank" href="hxxp://<黑帽站点>/">
  <img src="/pic/<name>.jpg" width="100%" height="auto">
</a>
```

```bash
# 快速取源码中的可疑外链与关键词
curl -s http://<target>/ | grep -Eio 'meta name="(keywords|description)"[^>]*|<(a|img|iframe|script)[^>]*(href|src)="https?://[^"]*"'
```

说明：示例为最小化复现片段，域名做占位化；未对任何真实站点执行。

## 变体与关联

- 变体：JS 动态写入 DOM、CSS 伪元素 `content` 放链接、robots.txt/sitemap 注入、图片 alt/title 藏关键词、隐藏 iframe、meta refresh。
- 变体：暗链只在特定 UA/Referer/地区下输出（对访客隐藏、对爬虫展示），需换 UA 或直接用搜索引擎缓存对比。
- [[defense-incident-response-web-defacement-proxy-js-ua-redirect-triage]]：处理"可见跳转"类篡改；本卡处理"看不见"的暗链。
- [[defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage]]：前端被植入诱导下载；可对照模板/JS 篡改的定位手法。
- [[pentest-recon-fofa-body-injected-asset-path-cluster]]：用本卡第 5 步取出的资源路径做批量拓线。
- 边界：内容由第三方 CDN/边缘节点或第三方 JS 注入时，源站源码可能干净，需要对比多节点响应与外部依赖。

## 检测与防御

- 检测：模板/页面文件完整性监控（FIM）与版本 diff；定期抓取全站源码，搜白名单之外的外链域名；搜索引擎 `site:` 看标题/摘要是否出现博彩词；监控 meta keywords/description 变化。
- 检测：全站源码中 `target="_blank"` 且只包图片的 a 标签、0 宽高元素，作为规则化巡检项。
- 防御：最小化模板/数据库写入权限；CMS 与插件及时更新；WAF 拦截对模板和首页文件的写入；CSP 限制外链脚本/图片；上线前与定期做源码安全巡检。
- 响应：清理注入代码后修改相关口令，排查同服务器其他站点、计划任务与数据库内容，防止再次写入。
