---
id: web-generic-auth-captcha-ocr-username-enum-bruteforce
title: 图形验证码 OCR + 用户名枚举：ddddocr 与 Burp captcha-killer 爆破管理员口令
type: scenario
domain: web
path: web/generic/auth
technique: captcha-ocr-login-bruteforce
tags:
- web
- auth
- captcha
- ocr
- brute-force
- username-enumeration
- burp
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V72
  verified_at: '2026-11-05T16:53:27+08:00'
  notes: 已对照原文与图43-54核对：注册页 admin 提示用户名占用、ddddocr /reg 服务、captcha-killer-modified 模板、Pitchfork(密码+Extension-generated 验证码)、Resource Pool 并发1/延迟500ms、爆破后进入管理后台，均与截图一致。未本地复现
url: /docs/web/generic/auth/web-generic-auth-captcha-ocr-username-enum-bruteforce/
draft: false
kb_aliases:
- ddddocr 验证码识别
- captcha-killer-modified
- 图形验证码爆破
- 验证码 OCR 绕过
- 用户名枚举爆破
---

## 一句话结论

登录口使用图形验证码、但没有账号锁定和频率限制时，攻击者可以通过注册页/手机号登录枚举出 `admin` 等有效账号，再用 `ddddocr` 自建 OCR 服务配合 Burp `captcha-killer-modified` 自动识别并回填验证码，以 Pitchfork 模式同时跑密码字典和验证码，最终爆破出管理员口令。

## 原理

- 图形验证码的设计目标是区分人和自动化程序，但如果验证码是简单字符图片、没有行为分析/设备指纹/失败锁定，OCR 模型可以稳定识别；验证码因此退化为“多一步请求”的速率限制，而不是不可绕过的身份验证。
- 用户名枚举降低爆破成本：注册页提示“当前用户名已被占用”、登录/手机号登录的错误文案差异、响应时间/状态码差异，都能确认账号存在；案例先确认 `admin` 存在，再用手机号登录接口遍历。
- Burp `captcha-killer-modified` 插件允许把验证码图片请求转发到外部 OCR 服务，并把识别结果作为 Intruder 的 payload。请求模板用 `<@BASE64><@IMG_RAW></@IMG_RAW></@BASE64>` 表示取图片二进制并 Base64 编码，匹配规则从 OCR 服务响应中提取文字。
- Intruder 使用 Pitchfork 模式：Payload 1 是密码字典，Payload 2 是插件生成的验证码；两者按序配对。用自定义 Resource Pool 把并发降到 1、请求间隔设为 500ms，避免验证码图片请求过快导致识别失败或触发风控。
- 成功判据通常是响应长度/状态码/跳转差异；案例中大量失败响应长度一致，命中后长度/内容变化，从而定位正确口令。

## 触发条件

- 登录口有图形验证码，但字符简单、无干扰或干扰可被 OCR 处理；
- 没有账号锁定、IP 限速、行为验证或设备指纹；或限制阈值高于爆破所需请求量；
- 能枚举出有效用户名（注册页占用提示、错误文案、手机号登录等）；
- 攻击者能部署 OCR 服务并配置 Burp 插件（或使用等价自动化脚本）。

## 利用步骤

1. 在注册页输入 `admin` 等常见账号，观察“用户名已被占用”提示；结合登录/手机号登录错误差异枚举有效账号。
2. 部署 OCR 服务（示例用 `ddddocr` + `aiohttp`，监听 8888，`/reg` 接收 Base64 图片并返回识别文本）。
3. 安装 Burp `captcha-killer-modified`，抓取验证码图片请求，填入接口 URL 与请求模板，测试识别结果。
4. 抓取登录请求，标记用户名、密码、验证码三个位置；用 Pitchfork：密码字典 + Extension-generated（captcha-killer）验证码。
5. 设置 Resource Pool：最大并发 1、请求间隔 500ms；开始爆破。
6. 按响应长度/状态码/跳转筛选成功请求，用命中口令登录后台。

## PoC

```python
# ddddocr OCR 服务（最小化）
import base64
import ddddocr
from aiohttp import web

ocr = ddddocr.DdddOcr()

async def handle(request):
    img = base64.b64decode(await request.text())
    return web.Response(text=ocr.classification(img)[0:4])

app = web.Application()
app.add_routes([web.post('/reg', handle)])
web.run_app(app, port=8888)
```

```http
POST /reg HTTP/1.1
Host: 127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded

<@BASE64><@IMG_RAW></@IMG_RAW></@BASE64>
```

```http
POST /admin/Login/index.html HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin&password=<password>&verify=<ocr-code>
```

```text
Intruder:
  Attack type: Pitchfork
  Payload 1: password list
  Payload 2: Extension-generated -> captcha-killer-modified
  Resource pool: max concurrent 1, delay 500 ms
```

## 变体与关联

- 变体：用 Tesseract、cnn_captcha、第三方打码平台替代 ddddocr；验证码为算术题时先 OCR 再计算；滑块/点选验证码需图像匹配或轨迹模拟。
- 变体：验证码与 session 绑定但可复用、验证码回显在响应中、验证码不校验大小写/可重复使用。
- 关联：[[web-generic-auth-login-bruteforce-response-payload]]（响应判读与 payload 变换）、[[web-generic-auth-2fa-user-parameter-tampering-code-bruteforce]]（验证码爆破）、[[web-generic-auth-error-message-username-enumeration]]（用户名枚举）。
- 边界：账号锁定、IP/设备限速、行为验证码、验证码一次性且强绑定会话时，爆破成本显著上升。

## 检测与防御

- 防御：登录失败锁定/指数退避、IP 与账号双维度限速、设备指纹；使用行为验证码或服务端风险评分，不只依赖图形字符。
- 防御：统一登录错误文案，避免注册页/手机号登录泄露账号存在性；对高频验证码请求做风控。
- 检测：同一 IP/设备大量验证码请求与登录尝试；验证码识别后立即登录的固定时间间隔；大量账号枚举请求；WAF 对自动化 Intruder 特征告警。
