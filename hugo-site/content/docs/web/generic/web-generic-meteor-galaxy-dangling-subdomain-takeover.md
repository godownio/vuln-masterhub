---
id: web-generic-meteor-galaxy-dangling-subdomain-takeover
title: Meteor Galaxy 悬空子域接管：CNAME 指向 us-east-1.galaxy-ingress.meteor.com，注册同名应用即可控制子域
type: scenario
domain: web
path: web/generic
technique: meteor-galaxy-dangling-subdomain-takeover
tags:
- subdomain-takeover
- dns
- cname
- saas
- meteor
- galaxy
- dangling-dns
- phishing
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V336
  verified_at: '2026-11-08T19:02:17+08:00'
  notes: 已对照原文与图 06-09 核对：host annualmeeting2022.globe.gov 显示 alias us-east-1.galaxy-ingress.meteor.com（52.86.95.224 等）；DEPLOY_HOSTNAME=galaxy.meteor.com meteor deploy annualmeeting2022.globe.gov 输出 Uploaded app bundle... version 2 / successfully upgraded；Meteor Cloud 控制台显示该域名 Version 2、由 nickguitar 部署、1 container；访问子域显示 takeover PoC 页面，均与卡一致。账号需绑卡支付 1 美元（停用后退还）的边界也已记录。原文无版本概念，affected_versions 已 --clear。dedup 仅自匹配，与对象存储 CNAME 接管卡机制不同。另核对被跳过的 XSS：原文 no_welcome=a'-alert(1)// 与 AutoRefreshInterval=%27;alert(document.cookie)// 属内联 <script> 字符串闭合，既有 web-generic-xss-javascript-context-injection 已覆盖同 sink，跳过成立，不需要 needs_extraction。
url: /docs/web/generic/web-generic-meteor-galaxy-dangling-subdomain-takeover/
draft: false
kb_aliases:
- Meteor 子域接管
- Galaxy 子域劫持
- galaxy-ingress.meteor.com
- SaaS 悬空 DNS 接管
- dangling CNAME takeover
- meteor deploy takeover
---

## 一句话结论

子域 `annualmeeting2022.<target>` 的 DNS 别名指向 Meteor Galaxy 的共享入口 `us-east-1.galaxy-ingress.meteor.com`；当该 hostname 在 Meteor 侧没有被占用（原应用已删除但 DNS 未清理）时，攻击者注册 Meteor 账户并执行 `DEPLOY_HOSTNAME=galaxy.meteor.com meteor deploy annualmeeting2022.<target>`，即可让 Galaxy 把该 hostname 分配给攻击者的应用，从而完全控制这个子域并提供任意内容。

## 原理

- **DNS 仍指向第三方 SaaS**：目标组织曾用 Meteor Galaxy 托管某个应用，DNS 配置了 CNAME/别名指向 Galaxy 共享入口 `us-east-1.galaxy-ingress.meteor.com`。应用下线或账户删除后，DNS 记录没有清理，域名继续解析到 Galaxy 的入口 IP。
- **Galaxy 按 Host 路由到租户应用**：Meteor Galaxy 的 ingress 根据请求的 Host 头把流量路由到对应租户的应用。只要某个租户在 Galaxy 上声明了该自定义域名，Galaxy 就会为该域名提供服务；如果原租户已释放该 hostname，声明权就空出来了。
- **攻击者如何声明**：Meteor 的部署命令允许用 `DEPLOY_HOSTNAME=galaxy.meteor.com meteor deploy <custom-domain>` 把应用部署到自定义域名；Galaxy 会在账户下创建/更新该域名的应用。若该 hostname 未被其他账户占用，部署成功，Galaxy 开始用攻击者的应用响应来自目标子域的请求。
- **为什么浏览器/用户会信任**：访问者看到的是目标组织的合法域名（如 `annualmeeting2022.globe.gov`），TLS 证书可由 Galaxy 为该域名签发/提供，页面内容却由攻击者控制；可用于钓鱼、挂马、窃取 Cookie（同域）、SEO 污染、绕过基于域名白名单的信任。
- **接管判定**：`host <subdomain>` 显示为 `us-east-1.galaxy-ingress.meteor.com` 的别名；访问该子域返回 Galaxy 的 404/默认页或没有应用；Meteor 侧该 hostname 可被新账户声明。原文用 nuclei 的 `meteor-takeover` 模板发现该问题。
- **成本/边界**：Meteor 账户可能需要绑定信用卡（原文支付 1 美元，停用后返还）；Galaxy 可能对自定义域名做归属验证/保留，或原租户仍占用 hostname；DNS 记录被删除、CAA/证书策略限制、或 Galaxy 修复共享入口的声明逻辑，都会使接管失败。该技术不限于 Meteor，任何“DNS 指向 SaaS 共享入口 + SaaS 允许声明自定义域名”的组合都可能悬空。

## 触发条件

- 目标子域的 DNS 存在指向 `*.galaxy-ingress.meteor.com`（或其他 SaaS 共享入口）的 CNAME/别名。
- 该 hostname 在 SaaS 侧未被原租户占用/已释放，且新用户可声明。
- 攻击者能注册 SaaS 账户（可能需要支付方式）并执行部署命令。
- 目标未监控子域内容/证书透明度，也未定期清理悬空 DNS。
- 子域未被 CAA、DNSSEC、代理/WAF 等额外机制保护到无法接管。

## 利用步骤

1. 子域枚举：用 amass/subfinder/crt.sh/ffuf 等收集目标子域，保存列表。
2. 指纹扫描：用 nuclei 的 takeover 模板或手工检查 CNAME/HTTP 响应；发现 `annualmeeting2022.<target>` 指向 `us-east-1.galaxy-ingress.meteor.com`。
3. 确认悬空：`host annualmeeting2022.<target>` 显示别名与 Galaxy IP；访问子域没有正常应用/返回默认页；确认 Meteor 侧无同名应用。
4. 注册 Meteor 账户并准备一个最小 Meteor 应用（或静态页面），安装 `meteor` CLI。
5. 部署并声明域名：

```bash
DEPLOY_HOSTNAME=galaxy.meteor.com meteor deploy annualmeeting2022.<target>
```

6. 等待 Galaxy 构建/部署完成；访问 `https://annualmeeting2022.<target>`，应显示攻击者的页面（原文放了一个 `takeover PoC` 页面）。
7. 可选：配置 HTTPS/证书、上传钓鱼内容或 JS；验证 Cookie 作用域与同域信任影响。
8. 报告/清理：在授权范围内截图取证，停止应用并释放 hostname，避免长期占用。

## PoC

原文命令与结果（未在本机复现）：

```bash
$ host annualmeeting2022.globe.gov
annualmeeting2022.globe.gov is an alias for us-east-1.galaxy-ingress.meteor.com.
us-east-1.galaxy-ingress.meteor.com has address 52.86.95.224
...

$ DEPLOY_HOSTNAME=galaxy.meteor.com meteor deploy annualmeeting2022.globe.gov
...
Uploaded app bundle to upgrade annualmeeting2022.globe.gov to version 2.
...
You have successfully upgraded your app to version 2.
```

部署后访问子域显示攻击者控制的 `takeover PoC` 页面。原文另在 Meteor Cloud 控制台看到该应用由攻击者账户部署、1 个容器运行。

## 变体与关联

- **其他 SaaS 悬空 DNS**：Heroku、GitHub Pages、Shopify、Netlify、Vercel、Azure App Service、Fastly、S3/对象存储等都可能出现“DNS 指向共享入口 + 自定义域名可被重新声明”的接管；判定与利用方式类似，只是声明入口/验证方式不同。
- **对象存储 CNAME 接管**：见 `cloud-object-storage-dangling-cname-bucket-takeover`，那是 Bucket 删除后 CNAME 悬空，攻击者同地域创建同名 Bucket；本卡是 PaaS 共享 ingress 的 hostname 声明，机制不同。
- **子域接管检测**：nuclei 的 `meteor-takeover`、`subjack`、`dnsReaper` 等；也可手工检查 CNAME 指纹与 SaaS 默认页。
- **影响升级**：接管后可配合 XSS/钓鱼/恶意下载/证书签发（若 SaaS 可为该域名签证书）扩大影响；同域 Cookie 可能被读取，具体取决于 Cookie 的 Domain/HttpOnly/SameSite。
- **与 XSS 的关系**：本卡是 DNS/托管层接管，XSS 是页面内脚本注入；两者可组合，但 sink 不同。

## 检测与防御

- **DNS 资产治理**：定期导出所有子域与 CNAME，检查是否指向第三方共享入口；删除不再使用的记录；对必须保留的记录做归属验证/保留声明。
- **SaaS 侧**：启用自定义域名归属验证（TXT/文件/HTTP），删除应用时同步释放/保留 hostname，防止被其他租户抢注；监控域名声明变更。
- **监控**：证书透明度日志（CT）监控为目标域名新签发的证书；子域内容变化/默认页指纹监控；nuclei/subjack 定期扫描；对指向 `galaxy-ingress.meteor.com` 等共享入口的记录告警。
- **防御**：CAA 限制可签发证书的 CA；对高价值子域使用独立托管/专用 IP；WAF/代理层校验 Host 与后端一致性；建立子域下线流程，先删 DNS 再删应用。
- **响应**：发现接管后立即删除悬空 DNS 记录、向 SaaS 报告并回收 hostname、吊销/监控异常证书、排查是否已被用于钓鱼。
