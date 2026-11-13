---
id: web-generic-auth-lodop-print-default-empty-password
title: Lodop/C-Lodop 云打印服务默认空口令：admin/guest 初始密码为空，可未授权控制打印输出
type: scenario
domain: web
path: web/generic/auth
technique: lodop-print-service-default-empty-password
aliases:
- Lodop 默认口令
- C-Lodop 空口令
- 云打印服务默认密码
- admin guest 初始密码为空
- 打印服务未授权
- Lodop 8000 18000
tags:
- lodop
- print-service
- default-credential
- auth-bypass
- intranet
- web
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V559
  verified_at: '2026-11-12T00:49:42+08:00'
  notes: 已对照原文与15张图核对：图13 为 Lodop 官方帮助页，明确'默认情况下，只要能访问本页，都可以通过本服务控制打印机输出'、'为guest设置密码（设置前需用admin身份登录，初始密码皆空）'、'俩http端口默认是8000和18000'，卡内端口/默认空口令/危害描述均出自该页；图14 为修改客户(guest)登录密码页（Old/New password，初始为空），图15 为修改管理员(admin)登录密码页（admin），页面在目标 172.x 地址可达。卡内如实标注原文未给出打印接口调用与成功回显、不声称已复现打印控制，confidence 与危害边界表述合理。dedup：与 JumpServer 默认口令接管资产、网络设备默认口令批量狩猎、未授权用户信息接口泄露 default_password 等卡产品/入口/危害均不同，非同链。未验证点：未访问实际服务验证空口令登录与打印控制；原文非组件漏洞无 CVE/受影响版本（未设 versions）；frontmatter 无 sources/source_url（库内惯例）。
---

## 一句话结论

Lodop/C-Lodop 云打印服务默认同时开放 8000 与 18000 两个 HTTP 端口，管理端 `admin` 与客户端 `guest` 的初始密码均为空；任何能访问该页面的攻击者可直接进入密码修改/打印控制页面，未授权控制打印机输出（打印任意内容），并可能借打印服务所在主机做内网探测与社工。

## 原理

- Lodop 是常用的 Web 打印中间件：业务页面通过 `CLodopfuncs.js` 连接本机或内网的 C-Lodop 服务，由服务端驱动打印机输出。服务自带一个 Web 管理/配置页面（8000 与 18000 端口）。
- 服务默认允许无密码访问；官方页面明确说明"默认情况下，只要能访问本页，都可以通过本服务控制打印机输出"，管理员可为 guest 设置密码，初始密码皆空；admin 的密码修改页面同样以空密码为初始状态。
- 因此攻击者只要能在内网访问到 8000/18000，即可打开 `mlogin`/`c_mpermit` 等页面，修改 admin/guest 密码或直接调用打印功能（打印任意文档），无需任何凭据。
- 危害边界：主要是打印机控制与信息泄露（打印内容可被攻击者指定、可能用于钓鱼/伪造单据）；是否能进一步读取打印任务或主机文件取决于服务版本与配置，原文未验证。

## 触发条件

- 目标内网存在 Lodop/C-Lodop 云打印服务，8000 和/或 18000 端口可从攻击者所在网段访问。
- 管理员未修改 admin/guest 默认空密码（或仍为初始状态）。
- 攻击者能访问服务页面（无需登录）。

## 利用步骤

1. 扫描/发现内网 8000、18000 端口上的 Lodop 服务（页面标题/`CLodopfuncs.js` 特征）。
2. 访问管理/密码页面（如 `/mlogin`、`/c_mpermit`），确认 admin/guest 可空密码进入。
3. 修改 admin/guest 密码锁定服务，或直接使用打印接口向目标打印机下发任意内容。
4. 结合打印机型号/队列信息做内网资产梳理；必要时把打印内容用于社工（伪造通知/单据）。

## PoC

```text
原文截图暴露的页面与说明（Lodop 自带帮助页）：
- 修改客户(guest)登录密码：Old password / New password / Submit（初始密码为空）
- 修改管理员(admin)登录密码：User name、New password、Confirm password（初始为空）
- "默认情况下，只要能访问本页，都可以通过本服务控制打印机输出"
- "设置前需用admin身份登录，初始密码皆空"；服务默认端口 8000 与 18000
```

原文未给出具体打印接口调用与成功回显，仅证明页面可访问、默认口令为空；本卡不声称已复现打印控制。

## 变体与关联

- **变体**：若管理员已改密码，可尝试弱口令/默认口令喷洒；部分版本支持 IP 白名单（URL_White_List），配置不当仍可绕过。
- **关联**：[[rtsp-weakauth-unauth-surveillance-view]]（同为内网设备/服务默认弱认证暴露）、[[pentest-initial-access-jumpserver-default-admin-password-asset-takeover]]（默认口令接管资产）。
- **边界**：服务仅监听本机/受防火墙保护、管理员已改强口令、或打印服务与业务解耦时，攻击面显著缩小；打印控制不等同于主机 RCE。

## 检测与防御

- **检测**：内网扫描 8000/18000 端口的 Lodop 特征；对打印服务的空口令登录与密码修改操作告警；监控异常打印任务/大量打印。
- **防御**：部署后立即修改 admin/guest 密码并限制访问来源（防火墙/URL_White_List）；不要把打印服务暴露到不可信网段；升级到官方最新版本并关注默认配置说明。
