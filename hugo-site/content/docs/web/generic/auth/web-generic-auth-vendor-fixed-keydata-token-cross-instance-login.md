---
id: web-generic-auth-vendor-fixed-keydata-token-cross-instance-login
title: 同厂商通用系统固定 KEYDATA 登录令牌跨实例复用：专家入口抓包得到 key 即可登录其它部署
type: scenario
domain: web
path: web/generic/auth
technique: fixed-vendor-login-token-cross-deployment
tags:
- web
- auth
- hardcoded-secret
- login-bypass
- broken-access-control
- vendor-product
- cross-instance
cve: []
severity: high
confidence: medium
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T14:02:00+08:00'
  notes: 已对照原文核对：POST /login_login、Cookie 含 shiro.session 与 JSESSIONID、KEYDATA=qq<手机号>fhadmin%2Cf%2C0192023A7BBD73250516F069DF... 的请求形态（图 16）与原文一致；专家入口抓包 -> 同厂商其它实例登录 -> 后台 Druid 的叙述链条与原文案例顺序一致。未验证点：跨实例复用结论依赖同厂商同密钥的推断，原文只给出一次抓包，故 confidence=medium 合理；未实际提交 KEYDATA。
url: /docs/web/generic/auth/web-generic-auth-vendor-fixed-keydata-token-cross-instance-login/
draft: false
kb_aliases:
- KEYDATA 登录
- 固定登录密钥通杀
- 同厂商系统通用密钥
- /login_login KEYDATA
- 专家入口密钥复用
---

## 一句话结论

同一厂商的通用系统（如各类“实验室/实训/申报平台”）在多个单位部署时使用同一套代码和同一个固定登录令牌：`POST /login_login` 的请求体里带一个名为 `KEYDATA` 的参数（形如 `qq<手机号>fhadmin%2Cf%2C0192023A7BBD73250516F069DF...`），它的后半段是与部署无关的固定 hex 常量；在任意一个实例的“专家入口/临时登录”处抓到一个可用 `KEYDATA`，就能用它直接登录同厂商的其它单位系统，形成跨实例通杀。

## 原理

- 这类系统的登录表单除了用户名口令，还会附带一个 `KEYDATA` 字段用于“免密/快速登录”或“专家/临时入口校验”。服务端对 `KEYDATA` 的校验逻辑是“解析出用户标识 + 比对后半段固定签名常量”，而该常量被硬编码在代码/前端 JS 中，随产品分发给每个客户，因此所有部署实例共享同一个签名值。
- 更糟的是 `KEYDATA` 里的用户标识部分（如 `fhadmin`）也是固定角色名，意味着它直接指向该实例的管理员/专家账号，而不是绑定当前会话或当前用户的临时凭证。
- 由于签名不包含实例标识、时间戳或 nonce，服务端无法区分“这是为本系统签发的”还是“从别的客户系统抄来的”。攻击者在 A 单位系统抓到一个 `KEYDATA`（甚至只是从公开的前端 JS/示例请求里拿到），把它放到 B 单位系统的同名登录接口上，服务端照样解析出 `fhadmin` 并放行。
- 这条链真正成立的关键是“同厂商产品复用同一密钥”——它是供应链级别的横向能力：不必破解每个实例，只要找到一个暴露的实例或一段泄露的请求，就能批量登录同类系统。
- 为什么 `KEYDATA` 会被看到：系统往往给评审专家/临时人员提供独立入口，前端把带 `KEYDATA` 的登录请求明文发出（HTTP 或可被代理查看），抓包即可完整拿到。

## 触发条件

- 目标是某厂商通用系统（同一代码基线多单位部署），登录接口为 `POST /login_login`（或同类 `/login`），并使用固定 `KEYDATA`/固定签名常量做校验。
- 攻击者已从任一实例（或前端 JS、公开文档、历史泄露请求）获得一个有效的 `KEYDATA` 值。
- 目标实例未对 `KEYDATA` 做实例绑定（无部署 ID、无时间戳、无 nonce 校验）。
- 目标实例的用户名/角色字段仍存在 `fhadmin` 一类固定管理员标识，或 `KEYDATA` 单独即可完成登录。
- 攻击者可访问目标登录接口（无需其它账号）。

## 利用步骤

1. 指纹识别：登录页标题/页脚/JS 路径（如 `dxhxy`、`schoolHome.do`、`login_login`）表明是某厂商通用产品；用 FOFA/Hunter 类测绘语法按相同特征找同厂商其它实例。
2. 在任一可访问实例上打开“评审专家/临时登录”入口，抓取登录请求，记录完整 `KEYDATA` 值与 Cookie（如 `JSESSIONID`、`shiro.session`）。
3. 解析 `KEYDATA`：`KEYDATA=qq<手机号>fhadmin%2Cf%2C<固定hex>`，其中 `%2C` 是逗号编码；确认后半段 hex 是否在不同实例间一致（一致即共享密钥）。
4. 把同一 `KEYDATA` 提交到目标实例的 `POST /login_login`，配合任意/空口令字段，观察是否返回登录成功与跳转。
5. 成功后进入后台，确认当前身份（通常是管理员/专家），再结合其它缺陷（如 Druid 监控、导出接口）继续扩大影响。
6. 若目标实例的 Cookie 名不同（`shiro.session` vs `JSESSIONID`），只替换请求体 `KEYDATA` 与必要的 CSRF/验证码头即可复现。

## PoC

```http
POST /login_login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: shiro.session=<任意或新会话>; JSESSIONID=<任意或新会话>
Referer: https://target/schoolHome.do

KEYDATA=qq<手机号>fhadmin%2Cf%2C<固定hex常量>
```

响应返回登录成功并下发有效会话（`Set-Cookie`），随后访问 `/schoolHome.do` 即进入已登录后台。

跨实例复用要点：把在 A 实例抓到的 `KEYDATA` 原样用于 B 实例；若 B 实例还要求账号口令，可先试空口令或固定口令候选。

## 变体与关联

- 变体：`KEYDATA` 里的用户标识可改成其它角色名（如 `admin`、`teacher`），若服务端只解析不改签，则能直接指定身份。
- 变体：前端 JS 里硬编码同一 hex 常量，攻击者不必抓包，直接读 JS 就能构造 `KEYDATA`。
- 变体：部分实例把 `KEYDATA` 放在 GET 查询串或 Header 中，同样可复用。
- 关联：[[web-generic-auth-hardcoded-bip-cred-orgid-user-create]]（同为硬编码对接凭据导致未授权建号/登录，差别是该卡为固定账号口令、本卡为固定签名令牌且跨实例通杀）。
- 关联：[[web-generic-auth-edu-expert-channel-path-concat-admin-takeover]]（同为教育类系统“专家入口”权限设计缺陷；本卡用固定密钥直接登录，不依赖路径拼接）。
- 关联：[[web-java-component-druid-monitor-default-credentials]]（本场景登录后常能进一步发现 Druid 监控未授权，形成信息泄露放大）。

## 检测与防御

- 防御：`KEYDATA` 这类快速登录令牌必须包含实例唯一标识、签发时间、随机 nonce 与 HMAC 签名，服务端校验实例与时效，禁止跨部署复用；密钥按实例生成，不入库不进前端。
- 防御：快速/专家登录令牌应一次性使用并绑定手机号/邮箱验证，或改为短信验证码登录；不要以固定管理员标识作为令牌载荷。
- 防御：登录成功要记录来源、令牌类型与实例 ID；对同一令牌在不同 IP/不同实例出现的行为告警。
- 检测：登录请求中出现 `KEYDATA` 且其 hex 段与历史值相同；同一 `KEYDATA` 在短时间内命中多个不同主机；前端 JS 中出现长 hex 常量且被用作登录参数。
- 检测：厂商侧应排查同一密钥在多客户环境的复用情况（供应链级风险）。
