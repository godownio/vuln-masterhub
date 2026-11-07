---
id: web-generic-auth-captcha-ocr-username-enumeration-same-password
title: 带验证码登录口：OCR 识别验证码枚举账号并用用户名=口令批量登录
type: scenario
domain: web
path: web/generic/auth
technique: captcha-ocr-username-enumeration-same-password
aliases:
- 验证码 OCR 识别
- 登录口账号枚举
- 用户名等于口令
- 账号密码一致弱口令
- 培训平台批量账号登录
tags:
- auth
- captcha
- ocr
- username-enumeration
- weak-password
- bruteforce
- account-takeover
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V81
  verified_at: '2026-11-05T18:08:59+08:00'
  notes: 已对照原文与 img01-06：img01 登录框带图形验证码，img02 抓包字段为 ssoFlag/loginWay/username/password/captchaKey/captchaCode 且用户名密码均为 admin，img03/04 显示验证码 OCR 日志与 Intruder 账号枚举（200/长度差异），img06 登录成功。原文明确先跑 100 个常见口令失败、后测用户名=口令成功，卡片一致。原文未给脚本源码（img05/OCR 日志），confidence=medium 合适；未实测。
---

## 一句话结论

登录口带图形验证码时，可用 OCR/打码脚本自动识别验证码，先把有效账号枚举出来；若系统由管理员批量下发初始口令，优先测试“用户名=口令”，往往能一次性登录多个账号，比通用口令字典命中率更高。

## 原理

- 图形验证码若只是简单字符加噪点，OCR 或打码平台可较高准确率识别；登录请求通常把验证码答案与 `captchaKey` 一起提交，脚本可以“取图 → 识别 → 提交”自动化。
- 账号枚举：对用户名列表逐一提交登录（或注册/找回接口），按响应长度、状态码、错误文案差异判断账号是否存在；验证码被自动识别后，枚举不再受人工输入限制。
- 企业培训/内部平台常由管理员批量创建账号并设置初始口令，常见弱模式包括：
  - 用户名=口令（账号 `zhangsan`，口令 `zhangsan`）；
  - 全员统一默认口令；
  - 工号/手机号后几位、姓名拼音+固定后缀。
- 原文先尝试“多个账号 × 100 个常见口令”的交叉爆破失败，随后改测“用户名=口令”，十多个账号全部登录成功；说明账号发放规则本身比口令字典更值得优先分析。
- 登录后进入的是真实业务账号，可继续做越权/文件访问测试；这类问题的根因是初始口令策略缺失 + 未强制首次改密 + 验证码未与风险控制联动。

## 触发条件

- 登录口有图形验证码，但字符简单、可 OCR/打码，且验证码可随登录请求同步获取；
- 用户名可枚举（登录响应差异、注册/找回接口、员工编号规则等）；
- 系统由管理员批量创建账号并下发初始口令，未强制首次登录改密；
- 没有有效的登录失败锁定/限速，或限速可按 IP/账号维度绕过；
- 测试在授权范围内，避免触发账号锁定影响业务。

## 利用步骤

1. 抓登录请求，确认验证码字段（如 `captchaKey`/`captchaCode`）、验证码图片接口与刷新逻辑。
2. 写脚本：获取验证码图片 → OCR/打码平台识别 → 用候选用户名提交登录 → 按响应长度/文案/状态码过滤出有效账号。
3. 对有效账号优先测试 `password = username`；再测试统一初始口令、工号规则、姓名拼音+后缀等业务相关口令。
4. 命中后登录，检查账号权限与业务功能；必要时修改口令保持访问（注意合法授权与业务影响）。
5. 记录命中账号、口令规则与登录后的功能面，作为弱口令/账号管理问题的证据。

## PoC

```python
# 伪代码：验证码识别 + 账号枚举 + 用户名=口令
for user in candidate_users:
    key, image = get_captcha()          # 请求验证码接口，拿 key 与图片
    code = ocr(image)                   # OCR 或打码平台识别
    resp = login(username=user, password=user, captchaKey=key, captchaCode=code)
    if is_success(resp):                # 按长度/文案/跳转判断
        print("[+]", user, "password = username")
```

```http
POST /clientLogin HTTP/1.1
Host: target
Content-Type: application/json

{"ssoFlag":"1","loginWay":"1","username":"<user>","password":"<user>","captchaKey":"<key>","captchaCode":"<code>"}
```

原文的验证码识别程序日志显示逐张图片识别（处理第 N 个验证码、识别结果、进度），随后把结果导入 Intruder 枚举账号；脚本源码未在文中给出。

## 变体与关联

- 变体：验证码可复用/可删除/前端校验时，直接绕过而不需要 OCR；也可用打码平台替代本地 OCR。
- 变体：账号枚举失败时，改从注册、找回密码、通讯录、员工编号规则获取用户名。
- 变体：用户名=口令不成立时，再测统一默认口令、工号/手机号后几位、姓名拼音规则；注意锁定与限速。
- 关联：登录爆破响应判读 [[web-generic-auth-login-bruteforce-response-payload]]、错误文案账号枚举 [[web-generic-auth-error-message-username-enumeration]]、限速绕过 [[web-generic-auth-login-rate-limit-bypass-cookie-xff]]、公开手册默认口令 [[pentest-initial-access-public-manual-default-password-pii-leak]]。

## 检测与防御

- 检测：同一 IP/设备短时间大量验证码获取与登录尝试；大量账号使用“用户名=口令”登录成功；登录失败/成功比例异常；验证码识别请求频率异常。
- 防御：不要只靠图形验证码，叠加 IP/账号维度限速、失败锁定与风险评分；首次登录强制改密并校验口令复杂度；禁止用户名与口令相同；对批量创建账号使用随机初始口令并通过安全渠道下发；启用 MFA/SSO；监控批量登录与异常验证码请求。
- 注意：验证码 OCR 成功率受图片复杂度影响，需先小批量验证准确率；测试时控制请求量，避免锁定真实员工账号。
