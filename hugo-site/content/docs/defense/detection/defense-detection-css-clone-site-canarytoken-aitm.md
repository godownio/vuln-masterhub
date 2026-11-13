---
id: defense-detection-css-clone-site-canarytoken-aitm
title: CSS 克隆站 Canarytoken：不可见背景 url() + CloudFront 边缘函数比对 Referer，检测 AitM 反向代理钓鱼
type: scenario
domain: defense
path: defense/detection
technique: css-clone-site-canarytoken-aitm-detection
tags:
- defense
- detection
- canarytoken
- honeytoken
- phishing
- aitm
- css
- cloudfront
- azure-entra
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V549
  verified_at: '2026-11-11T22:06:18+08:00'
  notes: 已对照原文(xz 13097)与17张截图复核：AitM 背景、JS/CSS 克隆站令牌、CloudFront 边缘函数解析预期 Referer 与 token ID、匹配返回1×1透明GIF否则重定向到令牌服务器告警、Referer隐私策略不受代理控制、Azure Entra 自定义品牌CSS自动安装（Organization.ReadWrite.All/Application.ReadWrite.All、默认User.Read、P1/P2订阅、装后撤销权限、传播数分钟到数小时）均与原文一致。验证中修正：步骤2与PoC由 display:none 元素改为原文生成的 body 背景 + 1×1 透明GIF（display:none 可能不加载背景图）；边缘函数伪代码由 startswith 改为按域名比对，并注明原文未给逐字节比对细节；部署面澄清有限管理权限指第三方资产、Azure授权需足够管理员并补默认User.Read。PoC为按原文描述整理的最小示意（原文无边缘函数源码）。frontmatter无sources/source_url/文章ID/URL，cve []，无affected_versions，path defense/detection合法；dedup仅命中自身，与既有honeytoken/检测卡不同链。未执行任何部署。
url: /docs/defense/detection/defense-detection-css-clone-site-canarytoken-aitm/
draft: false
kb_aliases:
- CSS 克隆网站令牌
- CSS Canarytoken
- AitM 钓鱼检测
- CloudFront Function Referer 校验
- 不可见背景图蜜标
---

## 一句话结论

在只允许改 HTML/CSS、不允许插入 JavaScript 的站点（如 Azure Entra ID 登录门户、托管博客）里，用一条不可见的 `background: url(...)` 指向自己的 CDN 端点，就能部署“克隆站 Canarytoken”：CDN 边缘函数从请求中解析预期 Referer 与令牌 ID，Referer 与预期域名一致时返回 1×1 透明 GIF（不告警），不一致时把请求转给令牌服务器并告警，从而在 Evilginx/Modlishka 这类 AitM 反向代理克隆登录页时拿到攻击者使用的域名与客户端 IP。

## 原理

- **AitM 钓鱼的特点**：攻击者用 Evilginx、Modlishka 等反向代理夹在用户与真实站点之间，页面由真实站点动态渲染，可实时改写 JavaScript，因此能绕过 TOTP/SMS 甚至推送类 MFA 并窃取会话；静态 HTML 克隆难以处理动态登录与 MFA。
- **JavaScript 令牌的局限**：经典克隆站令牌插入一段 JS，检查页面是否从预期父域加载，异常时向令牌服务器发请求；但很多第三方托管服务不允许上传自定义 JavaScript，令牌无法部署。
- **CSS 令牌的最小原语**：CSS 解释器能力受限，但 `url()` 可以引用一张不可见背景图。把 `url()` 指向自己控制的 CDN 端点，即使用户看不到任何内容，浏览器加载页面时也会向该端点发起请求；端点检查 HTTP `Referer` 是否来自预期域名。
- **为什么要边缘函数**：每次页面加载都回源会增加延迟与服务器负载，且令牌检测工具常用 `canarytokens.com` 之类字符串做 grep。把入口放在 CloudFront 这类 CDN 上，用边缘函数（毫秒级、全球部署）解析请求里的“预期 Referer + 令牌 ID”：Referer 匹配则直接返回 1×1 透明 GIF 并终止，不产生告警；不匹配才重定向到令牌服务器。CDN 资产本身不引人怀疑，也降低了被攻击者识别的概率。
- **为什么能发现 AitM**：反向代理虽然能改写页面内容，但无法控制受害者浏览器对 `Referer` 的隐私策略；当页面由攻击者域名提供时，浏览器发出的 Referer 与预期域名不一致，令牌即触发。告警包含客户端 IP 与引用域名，可用于提交滥用报告或封禁。
- **部署面**：除普通网页外，也可部署到只有有限管理权限的第三方资产（如 Azure Entra ID 登录门户、托管博客）；Azure 场景由授权的 Azure 应用写入/更新租户自定义品牌 CSS，申请 `Organization.ReadWrite.All` 与 `Application.ReadWrite.All`（另有默认 `User.Read` 用于应用认证），因此授权用户需有足够管理员权限，安装完成后应用会撤销自身权限。Entra 自定义品牌需要 P1/P2 订阅，CSS 传播到 CDN 可能需要数分钟到数小时。
- **边界**：部分浏览器会省略或伪造 Referer；页面每次加载都会请求令牌端点（延迟与负载）；若攻击者完全禁用外部资源加载或使用不执行 CSS 的客户端，令牌不会触发；它只是整体防御的一层，不能替代 FIDO2/通行密钥等抗钓鱼认证。

## 触发条件

- 防守方拥有可编辑 HTML/CSS 的站点或第三方登录门户（Azure Entra ID、WordPress 等），并能把 CSS 放入页面。
- 已注册 CSS 克隆站令牌，获得指向 CDN 的 `url()` 与令牌 ID；CDN 边缘函数可解析预期域名与 ID 并访问令牌服务器。
- 攻击者使用 AitM 反向代理（或任何以非预期域名提供页面的克隆方式）访问该页面，且客户端会发送与预期不符的 Referer。
- 防守方已配置令牌告警的接收邮箱/工单。

## 利用步骤

> 以下为防守方部署与验证步骤。

1. 在 Canarytokens 类服务创建“CSS 克隆网站令牌”，填写接收邮箱、预期域名与备注（备注用于告警时提醒部署位置）。
2. 把生成的 CSS 放入目标页面：令牌服务给的是类似 `body { background: url('https://<cdn>/<token-id>/<编码后的预期域名>/img.gif') !important; }` 的规则，靠返回的 1×1 透明 GIF 做到肉眼不可见；不要用 `display:none` 隐藏承载元素，否则浏览器可能不加载背景图、令牌不会触发。
3. 在 CDN（如 CloudFront）部署边缘函数：从请求路径/查询串解析预期域名与令牌 ID；读取 `Referer`，若与预期域名匹配，返回 1×1 透明 GIF；否则重定向到令牌服务器对应 ID 的告警端点。
4. 正常访问页面验证“无告警、无可见变化”；用代理/改 hosts/Evilginx 从其他域名提供同一页面，确认收到含客户端 IP 与引用域名的告警。
5. Azure Entra ID 场景可用授权应用自动安装自定义品牌 CSS；安装后撤销应用权限，等待 CDN 传播后重复第 4 步验证。
6. 把告警接入 SOC：按引用域名与源 IP 封禁、提交滥用报告，并排查是否已有会话被窃取。

## PoC

```css
/* 页面中仅需一条背景引用；1×1 透明 GIF 使页面无可见变化。URL 为示意，实际由令牌服务生成 */
body { background: url("https://<dist>.cloudfront.net/<token-id>/<b64-expected-domain>/img.gif") !important; }
```

```text
# CDN 边缘函数逻辑（伪代码）
expected, token_id = parse(path)
if expected_domain_of(request.headers["Referer"]) == expected:
    return 1x1_transparent_gif()      # 正常访问：静默
else:
    return redirect(token_server + "/" + token_id)  # 异常：触发告警
```

说明：文章给出的是产品化部署流程与截图，未提供可直接复用的边缘函数源码；上述为按原文描述整理的最小结构，需按所选 CDN 的运行时实现。原文只说 Referer 与预期标头“匹配”时返回 GIF，未给出逐字节/前缀等比对细节，伪代码以域名比对表示。

## 变体与关联

- **JavaScript 克隆站令牌**：可插入 JS 的站点用脚本检查父域，覆盖更直接，但受第三方平台限制；CSS 令牌是其补充。
- **其他蜜标形态**：假 AWS API Key、假 Excel/PDF 文件、视频文件引用原子等，见 [[defense-detection-video-file-canarytoken-rdrf]]；文件型蜜标依赖阅读器主动访问外部 URL。
- **AitM 对抗**：抗钓鱼认证（FIDO2/通行密钥）、条件访问与令牌绑定可降低会话被代理复用的风险；蜜标用于发现而非阻断。
- **边界**：Referer 缺失/伪造、浏览器隐私设置、客户端不加载外部资源都会导致漏报；令牌端点本身也可能被攻击者指纹识别。

## 检测与防御

- **部署侧**：令牌 CSS 尽量放在登录页等攻击者必然经过的页面；用 CDN 边缘函数过滤正常请求，避免每次加载都回源；告警备注写清部署位置与预期域名。
- **运营侧**：对告警按源 IP、引用域名、时间窗聚合；与身份日志（登录失败、MFA 推送、会话创建）关联，确认是否已有账号被接管。
- **防御纵深**：推进 FIDO2/通行密钥与条件访问；限制管理员同意权限，定期审计 Azure 应用的 `Organization.ReadWrite.All`、`Application.ReadWrite.All` 授权；对自定义品牌 CSS 的变更加监控。
- **攻击者规避**：若发现页面被注入未知 CSS/外部图片，可能已被布蜜标；AitM 代理应避免无条件透传 Referer，但这会进一步暴露异常。
