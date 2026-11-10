---
id: defense-incident-response-supply-chain-phishing-fake-login-attribution
title: 供应链钓鱼处置：仿冒登录页取证 + 供应商子域/FOFA 历史资产反查定位入口
type: scenario
domain: defense
path: defense/incident-response
technique: supply-chain-phishing-fake-login-domain-attribution
tags:
- incident-response
- phishing
- supply-chain
- domain-attribution
- fofa
- osint
- credential-theft
- dns
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-07T23:23:56+08:00'
  notes: 已对照原文核对并逐张查看 15 图：01 短链还原（sojson）得到 https://new.<redacted>/Login.html；02/03 仿冒登录页与公司 logo；04 验证码已发送提示；05 页面源码 placeholder/验证码输入框；06 前端 JS（/search/998a1628-93d8-4e12-bc4b-6a3eccf2b27d、username,password[,vcode]、{__..__} 占位）；07 Network POST 该端点 200、0 字节；08 ICP 备案主体/备案时间 2023-07-22 至 2024-07-30；09 new.<域> 当前解析 47.102.x（中国上海阿里云）、历史 2024-07-30；10 微信/支付宝账号不存在；11 钉钉昵称末尾可见字符；12 chaziyu 主域仅 4 个子域（new./moc-test./www. 等）；13 空间测绘产物 59 条；14 URL 探活 0 存活/53 失败、54/54 队列；15 Excel 历史资产（47.102.x 的 80/443/22/8080/3306，更新从 2024-07-29 回溯到 2023-03-03，SSH 2023-12-24、MySQL 2023-08-17、squid 2023-10-24）。卡片的时间线推断、SSH 22 遗留、子域/DNS 权限分析与原文一致；作者多处明示『推测』，卡片 confidence=medium 且在边界说明，符合。未验证点：未复现事件；原文多处打码、IP/域名不可复核；frontmatter 无 sources/source_url；非组件漏洞无 affected_versions。kb show 存在；dedup top1 为自身，其余候选均为攻击侧克隆/资产测绘卡，非同链；dup-scan 无本篇 pair。
url: /docs/defense/incident-response/defense-incident-response-supply-chain-phishing-fake-login-attribution/
draft: false
kb_aliases:
- 供应链钓鱼
- 仿冒登录页取证
- 短链恢复
- 子域名反查
- FOFA 历史资产
- 钓鱼域名溯源
- 供应商 DNS 权限
- SSH 暴露面
---

## 一句话结论

收到针对员工的短信钓鱼后，先恢复短链并对仿冒登录页做前端/接口取证（找出 AJAX 凭据外传端点、验证码假逻辑），再通过备案/子域枚举把域名归属定位到供应商主域，用 FOFA 等历史资产反查同一云服务器 IP 的域名与端口（发现 SSH 22 长期暴露、服务器 2023 年底关停但服务残留），结合“新增二级域名需要 DNS 管理权限”与时间线推断红队经供应商云服务器入口搭建钓鱼站；供应商不配合时用历史资产与解析记录作为证据推动协查。

## 原理

- **仿冒页取证**：钓鱼页通常伪造目标单位 logo/登录框。查看页面源码与 DevTools Network 可发现：点击登录后 JS 把 `username,password` 通过 AJAX POST 到形如 `/search/<uuid>` 的接口（凭据外传/暂存），随后才显示验证码；由于 AJAX 异步与状态变量逻辑错误，输入任意内容都会直接跳到“验证码已发送”，后端接口返回 0 字节/占位符，说明页面是批量套用的钓鱼模板。
- **域名归属**：对钓鱼域名做 WHOIS/ICP 备案查询，发现备案主体是某供应商公司；钓鱼站是主域名下的二级域名（如 `new.<supplier-domain>`），解析到云服务器 IP。与供应商官网 IP 对比通常不同，说明不是主站同一台服务器。
- **子域与 DNS 权限**：通过子域枚举/被动 DNS 查询主域名，只有少数几个子域（如 4 个）备案/解析，钓鱼子域是其中之一。新增二级域名解析需要主域名 DNS 账号权限，因此要么 DNS 账号被攻陷，要么供应商内部人员参与；这是供应链钓鱼与普通仿冒站溯源的关键区别。
- **历史资产反查**：用 FOFA/Shodan/鹰图等对钓鱼 IP 做反查，可得到该 IP 上历史绑定的域名、端口与服务（HTTP/HTTPS、22/SSH、8080/squid、3306/MySQL 等）。对域名批量探活常发现全部已下线，但历史记录显示服务器在 2023 年某时段仍承载供应商业务，且在 2023 年底关停时遗留了 22 端口；结合钓鱼站上线日期（如 2024-07-29），可推断红队通过遗留 SSH 进入服务器并利用供应商 DNS 权限添加二级域名。
- **手机号/账号 OSINT**：对短信发送号码做呼叫转移测试、微信/支付宝搜索、钉钉资料查看、公开社工库查询等，可得到归属地/运营商、钉钉昵称末尾字符等线索；这些信息主要用于证据固定与配合警方，不宜作为唯一归因依据。
- **供应链协同**：钓鱼站位于供应商资产上，防守方无法单方面取证；需要供应商提供 DNS 解析日志、账号登录记录、服务器镜像/SSH 日志与关停记录。很多软件供应商安全能力弱，必须由甲方安全团队主导并借助合同/法务/警方推动。

## 触发条件

- 员工收到定向短信/邮件，短链指向仿冒登录页，疑似凭据钓鱼。
- 钓鱼域名/子域可查询备案、WHOIS、DNS 解析与历史资产（FOFA/Shodan/被动 DNS 等）。
- 钓鱼站托管在供应商或第三方云服务器上，需供应商配合取证。
- 有合法授权与事件响应流程；涉及手机号/社交账号查询时遵守隐私与法律要求。

## 利用步骤

（防御方处置流程，非攻击复现。）

1. 证据固定：保存短信原文、短链、二维码、页面截图、完整 HTML/JS、HAR、DNS 解析、TLS 证书、IP、WHOIS/备案信息与访问时间；不要用真实员工凭据登录。
2. 短链恢复与页面分析：展开短链得到真实 URL；用浏览器 DevTools 观察登录按钮的 AJAX 请求，记录凭据外传端点（如 `/search/<uuid>`）、请求参数（`username,password[,vcode]`）与响应；用假账号测试页面逻辑，判断是否为套用模板。
3. 域名归属：WHOIS/ICP 查备案主体；查主域名与子域；对比钓鱼站 IP 与供应商官网 IP；记录 DNS 解析历史与证书 CN/SAN。
4. 子域与 DNS 权限分析：用子域枚举/被动 DNS 列出主域名下所有子域，确认钓鱼子域；分析新增该子域需要哪个 DNS 账号权限，要求供应商提供解析变更日志。
5. 历史资产反查：对钓鱼 IP 用 FOFA/Shodan/鹰图查询 `ip="<ip>"`，导出域名/端口/服务/更新时间；批量探活，标记已下线资产；根据历史记录建立“服务器启用—关停—钓鱼上线”时间线，重点看 SSH/远程管理端口是否遗留。
6. 手机号/账号 OSINT（合法范围内）：呼测、微信/支付宝搜索、钉钉资料、公开信息检索；记录归属地/运营商/昵称线索，保留证据链。
7. 供应商协查：把仿冒页、子域、IP 历史资产、时间线整理成材料，要求供应商提供 DNS 日志、账号登录日志、服务器快照/SSH 日志与资产关停证明；必要时通过法务/警方介入。
8. 处置与加固：协调下线钓鱼站；重置 DNS/云账号密码并启用 MFA；关闭遗留 SSH/管理端口、清理关停资产；通知员工修改密码、监控凭据复用；对供应商提出安全整改与复测。

## PoC

短链与域名排查（示例命令）：

```bash
# 展开短链（不跟随到钓鱼页时可只看 Location）
curl -sI 'https://<short-link>' | grep -i '^location:'

# DNS / WHOIS / 证书
dig +short new.<supplier-domain>
whois <supplier-domain>
curl -sI https://new.<supplier-domain>/Login.html | openssl s_client -servername new.<supplier-domain> -connect new.<supplier-domain>:443 2>/dev/null | openssl x509 -noout -subject -issuer

# 子域枚举（示例工具）
subfinder -d <supplier-domain> -silent
# 被动 DNS/证书透明日志：crt.sh 查询 %.supplier-domain
```

```text
# FOFA/Shodan 反查（示例语法）
ip="47.x.x.x"
ip="47.x.x.x" && port="22"
# 导出字段：URL、IP、端口、协议、标题、指纹、应用、更新时间
```

钓鱼页凭据外传特征（前端代码节选，示意）：

```javascript
$.ajax({
  type: "POST",
  url: '/search/998a1628-93d8-4e12-bc4b-6a3eccf2b27d',
  data: 'data=' + encodeURIComponent($("#username").val() + "," + $("#password").val()),
  success: function () { $("#passwordinput").hide(); $("#valicodeinput").show(); }
});
// 第二次提交：username,password,vcode 到同一端点；响应占位符 {__...__} 表明模板套用
```

历史资产时间线（示意）：

```text
2023-03 ~ 2023-12：该 IP 承载供应商多个域名/业务（FOFA 历史记录）
2023 年底：服务器关停，但 22/SSH 端口遗留
2024-07-29：钓鱼子域 new.<supplier-domain> 解析到该 IP
→ 推断：SSH 入口被利用 + 供应商 DNS 账号权限被用于添加二级域名
```

## 变体与关联

- 投放变体：短信短链、邮件附件、二维码、社交软件消息；仿冒页可克隆登录/SSO/邮箱/ VPN 页面。
- 归属变体：钓鱼站直接在攻击者云主机（无供应商关系）、供应商主站被入侵、供应商 DNS 账号被攻陷、内部人员参与。
- 取证变体：无 FOFA 权限时用 Shodan/Censys/鹰图/被动 DNS/证书透明日志；无供应商配合时通过域名注册商/云厂商/警方调证。
- 关联卡片：[[pentest-recon-equity-icp-subsidiary-domain-asset-discovery]]（域名/ICP/子公司资产发现）、[[pentest-c2-cdn-fronting-cname-hide-origin]]（CDN/域前置隐藏源站）、[[defense-incident-response-public-evidence-source-audit-cross-validation]]（无完整日志时证据分级）、[[defense-forensics-email-header-spoof-detection]]（邮件头溯源）。
- 边界：供应商不配合/日志缺失时只能形成“高度可能”的推断；FOFA 历史数据有延迟/缺失；手机号 OSINT 受隐私与法律限制；域名/DNS 记录可能被攻击者删除或伪造。

## 检测与防御

- 检测：员工上报可疑短信/短链；仿冒域名与品牌相似（`new.`、拼写变体、子域滥用）；DNS 解析中出现陌生二级域名；供应商域名/IP 上出现登录页克隆；FOFA 历史资产中出现遗留 SSH/RDP/数据库端口。
- 防御：对员工做钓鱼演练与上报培训；部署邮件/短信链接检测与品牌监测；要求供应商提供资产清单、关闭闲置端口与关停资产、DNS/云账号启用 MFA 与最小权限、保留解析与登录日志；甲方对供应商做安全准入与年度复测。
- 响应：建立供应链事件联系人清单与协查模板；发现钓鱼站先取证再下线；同步修改凭据、检查凭据复用与横向登录；必要时报警并保留法律证据。
