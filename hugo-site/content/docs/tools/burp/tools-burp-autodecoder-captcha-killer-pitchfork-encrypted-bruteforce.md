---
id: tools-burp-autodecoder-captcha-killer-pitchfork-encrypted-bruteforce
title: autoDecoder 接口加密与 captcha-killer-modified 双插件串联：Pitchfork 按扩展生成验证码、按脚本实时 md5 加密口令爆破加密登录口
type: scenario
domain: tools
path: tools/burp
technique: autodecoder-captcha-killer-pitchfork-encrypted-bruteforce
tags:
- burp
- autodecoder
- captcha-killer-modified
- intruder
- bruteforce
- md5
- encryption
- plugin-chain
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:31:47+08:00'
  notes: 已对照原文核对；本次核对未读取图片；两插件串联、Pitchfork+Extension-generated、8888/8887 端口冲突、按 p_md5= 正则替换、明文关键字需随目标改写均与正文一致。未验证点：安装与面板截图未读，界面项名称与识别效果无法逐项确认；原文插图未给验证码接口具体形态
url: /docs/tools/burp/tools-burp-autodecoder-captcha-killer-pitchfork-encrypted-bruteforce/
draft: false
kb_aliases:
- autoDecoder 配合 captcha-killer 爆破
- Pitchfork Extension-generated 验证码
- 加密口令爆破 md5
- Burp 双插件爆破
- 8887 端口冲突
---

## 一句话结论

当登录口同时具备「验证码」和「口令字段被前端加密（如 md5）」两个阻碍时，把 captcha-killer-modified 作为 Intruder 的 Extension-generated payload 生产验证码、把 autoDecoder 的接口加密脚本挂在请求链上把字典明文口令实时替换成密文，再用 Pitchfork 把两路 payload 一一配对，就能直接对加密登录口做字典爆破。

## 原理

- Intruder 的 payload 类型 `Extension-generated` 允许由另一个 Burp 扩展在每次请求前动态产生 payload，captcha-killer-modified 正是借此在每轮请求时抓取并 OCR 识别当前验证码；两路 payload 在 Pitchfork 模式下按索引并行取用，于是「第 i 个口令」与「第 i 个验证码」被绑进同一条请求。
- autoDecoder 在 Burp 的请求发送链路里做「明文 ↔ 密文」转换：Intruder 里写的仍是明文口令（方便字典复用），插件在发出前调用本地 `/encode` 把目标字段替换成密文。因此爆破的成败不取决于字典能否生成密文，而取决于替换点是否被正则准确锚定。
- 两个插件都必须在本机起 HTTP 服务，默认都偏爱 8888；不改端口就会互相抢占，表现为其中一个插件「连不上接口」或验证码不再刷新。把 autoDecoder 脚本改到 8887 并在插件配置里同步，是这类串联最容易踩的坑。
- md5 场景的替换逻辑必须是「按字段名取值再替换」，而不是全文替换：脚本用 `p_md5=([^&]+)` 之类正则从 `dataBody` 里取出待加密值，再 `param.replace(md5, md5_encrypt(md5))`，否则一旦字典里有与其它参数值相同的子串就会被误替换。
- 插件侧的「明文关键字」决定 autoDecoder 是否对某条流量启用加解密：它用该关键字判断当前 body 是明文还是密文。口令为 md5 十六进制时明文里既没有 `"` 也没有原关键字，若沿用上一个目标的 `"` 就会导致插件静默不生效——必须把关键字改成实际会出现在明文里的字符（如 `&`）。

## 触发条件

- 目标登录/查询接口同时要求：动态验证码（图片或接口返回）+ 某一字段为前端加密（md5/AES/DES 等），且两者的获取/加密逻辑都能在本地复现。
- 已安装 autoDecoder 与 captcha-killer-modified，且两者能各自起独立端口的本地服务（如 8888 与 8887）。
- 验证码接口可被脚本直接请求并稳定 OCR；服务端未对验证码会话与账号/IP 做严格绑定或失败次数限制。
- 目标域已在 autoDecoder 的加解密域名单内，且明文关键字与真实明文匹配。
- 仅限授权测试。

## 利用步骤

1. 抓一次登录包，确认验证码参数名、口令字段名与其加密形式（比较 `123456` 与页面上密文的对应关系，判断是 md5 还是其它算法）。
2. 在 captcha-killer-modified 里填入验证码接口请求模板，测试能否取图；选用 dddocr 模板运行本地识别服务，确认识别率可接受。
3. 在插件里点击「使用该插件」，否则验证码参数不会随请求更新（常见误判为识别失败）。
4. 写 autoDecoder 的 `/encode` 脚本：从 `dataBody` 用正则取出待加密字段值，替换为该值的 md5；`/decode` 直接原样返回。脚本服务端口改成 8887 以避开 captcha-killer 的 8888。
5. autoDecoder「接口加解密」页填 `http://127.0.0.1:8887/encode`，先在调试区粘一条真实包点加密验证替换结果正确。
6. 在「选项」页选择接口加解密、填写目标域名、把明文关键字改成明文里真实存在的字符（如 `&`），保存配置。
7. Intruder 选 Pitchfork：payload1 为口令字典（明文），payload2 选 `Extension-generated` 并指定 captcha-killer-modified。
8. 发包并在 Logger 里逐条核对：验证码已更新、口令已变成 md5 密文；再按响应长度/状态/关键字筛出成功登录。

## PoC

autoDecoder 接口脚本的关键部分（端口与正则按目标调整）：

```python
@app.route('/encode', methods=["POST"])
def encrypt():
    param = request.form.get('dataBody')
    pattern = r'p_md5=([^&]+)'
    match = re.search(pattern, param)
    md5 = match.group(1)
    return param.replace(md5, md5_encrypt(md5).strip())

@app.route('/decode', methods=["POST"])   # 响应明文，不解密
def decrypt():
    return request.form.get('dataBody')

app.run(host="0.0.0.0", port="8887")
```

Intruder 配置要点（无回显代码，属配置型 PoC）：

```text
Attack type : Pitchfork
payload1    : 口令字典（明文，如 123456）
payload2    : Extension-generated → captcha-killer-modified
```

判定：Logger 中请求体的口令字段已是 32 位十六进制、验证码参数每轮不同；成功口令对应的响应与失败响应在长度或关键字上存在稳定差异。

## 变体与关联

- 变体：口令若是 AES/DES 而非 md5，把脚本换成对应的加密函数即可，其余配置不变（见既有接口解密卡）。
- 变体：验证码可由接口直接获取且服务端不校验会话时，可省掉 captcha-killer，改用 Battering ram/Cluster bomb 加固定验证码。
- 关联：[[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]（接口脚本的 bytes/str、Base64 变体、JSON 字段等通用写法与坑）。
- 关联：[[tools-burp-autodecoder-builtin-regex-form-json-rsa-login]]（不写脚本、用内置算法 + 正则的路线）。
- 关联：[[web-generic-auth-captcha-ocr-username-enum-bruteforce]]（验证码 OCR 与账号枚举的纯 Web 侧做法）。

## 检测与防御

- 防御：登录口把验证码与一次性会话强绑定（用后即失效、与账号绑定），并对同一账号/IP 做失败次数与频率限制，使双插件配对的爆破难以放大。
- 防御：不要把「前端加密」当作安全边界；口令校验必须在服务端按明文策略执行，并配合多因素认证。
- 检测：短时间内同一来源对验证码接口与登录接口成对高频请求，且登录请求体中的口令字段恒为 32 位十六进制等固定长度密文形态。
- 检测：验证码接口被反复请求但登录成功率极低（典型 OCR 爆破特征），以及同一 UA/会话在秒级内提交数十个不同口令。
