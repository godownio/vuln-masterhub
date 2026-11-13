---
id: code-analysis-reverse-obfuscation-frontend-encryptajaxparams-pseudo-encryption
title: 前端伪加密参数逆向：encryptAjaxParams 实为 URL+Base64+URL，逆运算改包与 SM2 分支硬编码公钥重加密
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: frontend-encryptajaxparams-url-base64-pseudo-encryption
tags:
- js-reverse
- frontend-encryption
- obfuscation
- burp
- match-and-replace
- base64
- sm2
- parameter-tamper
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V694
  verified_at: '2026-11-13T17:57:23+08:00'
  notes: 已对照原文与全部29图核对：图4 搜索 encrypt 定位 frame.min.js 的 /*! encrypt */ 函数；图16 混淆行 _0x20b204[0x206](_0x20b204[0x1e5](_0x20b204[0x206](...))) 对应 encodeURIComponent(btoa(encodeURIComponent))，图17 Burp Inspector 连续 URL→Base64→URL 三层解码出 commonDto JSON，伪加密判定成立；图19/20/21 工具提示分别证实 encbody_、mini.encode、encryptSM2，图18 useSm2Encrypt=true（业务页）、图10 登录页 undefined，图22/23 显示 sm2Encrypt 以 04 开头公钥与 return '04'+encryptData；图25/26 Match and Replace 规则 Type=Response body、Match=Util.encryptAjaxParams(m.url,t)、Replace=JSON.stringify(t)，图27 浏览器实际执行被替换后的 t=JSON.stringify(t)，图28 请求体已明文；图29 为 Burp Upstream Proxy 指向本地 mitmproxy。如实性：原文仅演示到代理侧明文与断点分析，未演示服务端接受篡改/重加密参数（图1 原始加密请求与图28 替换后请求响应均为 state:error），SM2 分支重加密为公钥加密性质推论、原文未实测；mitmproxy 部分原文仅给钩子骨架且 request 为 xxx加密算法() 占位，skipped 不单独成卡的理由成立。原文无显式受影响版本，未设 affected_versions。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-frontend-encryptajaxparams-pseudo-encryption/
draft: false
kb_aliases:
- encryptAjaxParams 逆向
- frameBodySecretParam 解密
- frameUrlSecretParam 解密
- 前端伪加密
- useSm2Encrypt
- Burp 替换响应 JS 加密函数
- 新点协同办公平台加密参数
---

## 一句话结论

抓包见到 `frameBodySecretParam`/`frameUrlSecretParam` 等“加密”参数时，在混淆的 `frame.min.js` 中按参数名与 `encrypt` 关键字下断点，步进 `encryptAjaxParams` 可还原出真正的处理链：`useSm2Encrypt` 为假时只是 `encodeURIComponent(btoa(encodeURIComponent(JSON.stringify(params))))`（URL 编码 + Base64 + URL 编码，纯编码不是加密），为真时是 `"encbody_" + SM2(公钥硬编码在 JS)`。前者用 Burp Inspector 或脚本三层逆运算即可还原/重编码任意改包；后者因公钥在前端公开，同样可对任意明文重新加密。文章还用 Burp Match and Replace 把响应 JS 中的 `Util.encryptAjaxParams(m.url,t)` 替换成 `JSON.stringify(t)`，让浏览器直接发明文，便于在代理里改包。

## 原理

- **前端加密不构成安全边界**：加密与密钥都在客户端 JS 里，攻击者（或持代理的测试者）可以读算法、改 JS、调用页面自己的加密函数，因此它只能阻挡不会逆向的人，不能防篡改。
- **伪加密 = 可逆编码**：`encryptAjaxParams` 的常规分支调用 `Util.encrypt`，其本体是 `window["encodeURIComponent"](window["btoa"](window["encodeURIComponent"](value)))`——先对 JSON 字符串做 URL 编码，再 Base64，再 URL 编码。三层都是公开可逆变换，任何能抓包的人都能解出明文，也能把任意篡改后的 JSON 重新编码成服务端可接受的参数。
- **混淆不改变数据流**：源码用 `_0xbfd749(0x...)` 字符串数组访问器把属性名藏起来（如 `\x75\x73\x65\x53\x6d\x32\x45\x6e\x63\x72\x79\x70\x74` = `useSm2Encrypt`、`0x1f7` = `encbody_`、`0x223` = `encryptSM2`）；调试时在关键行看作用域变量、在 Console 里对访问器求值即可还原语义，不必先完整反混淆。
- **SM2 分支**：`window.useSm2Encrypt` 为真时走 `encbody_` 前缀 + `Util.encryptSM2(mini.encode(data))`，`sm2Encrypt` 用 JS 中硬编码的 SM2 公钥（以 `04` 开头的未压缩点）生成 `'04' + 密文`。SM2 是公钥加密，攻击者没有私钥不能解密，但公钥是公开的，**可以对任意明文重新加密**，因此同样能构造合法密文改包。
- **改 JS 让浏览器发明文**：服务端返回的 JS 也会经过代理，Burp 的 Match and Replace 可以在 Response body 里把 `Util.encryptAjaxParams(m.url,t)` 替换成 `JSON.stringify(t)`，浏览器后续就把明文 JSON 作为 data 发出，Burp 中可直接阅读和修改；若服务端强制校验密文格式则该请求会失败，需改用“明文改包 + mitmproxy 重新加密后再上行”的方式（文章将其留给后文，只给了 mitmproxy 请求/响应处理骨架）。
- **两种分支的判定**：登录页 `window.useSm2Encrypt` 为 `undefined`/false（走 Base64 分支），登录后的业务页为 `true`（走 SM2 分支）；同站不同页面的加密强度不同，测试时要在实际功能页断点确认。

## 触发条件

- 授权测试场景，目标 Web 应用把请求参数做客户端 JS 加密/编码后提交（本例为新点 Epoint 协同办公平台的 `frameBodySecretParam`/`frameUrlSecretParam`）。
- 测试者能控制浏览器与代理（Burp/mitmproxy），可下断点、查看源码并修改代理响应。
- 混淆代码仍可在浏览器中执行；关键函数没有被 wasm/远程下发等完全隐藏。
- 对“响应 JS 替换”路径，还要求服务端接受明文参数或另有重加密通道；否则只能用逆运算/公钥重加密方式构造合法密文。

## 利用步骤

1. 抓包记录加密参数名（`frameUrlSecretParam`、`frameBodySecretParam`，以及 `cmdParams` 等）与加密值形态（Base64 串、`encbody_` 前缀）。
2. 在 DevTools Sources 全局搜索参数名；搜不到时搜 `encrypt`、`decrypt`、`JSON.parse`、`JSON.stringify`、`ajax` 等关键字，定位 `frame.min.js` 中带 `/*! encrypt */` 标记的函数。
3. 在 `encryptAjaxParams` 调用处下断点，步进进入函数；观察作用域与参数对象，在 Console 对 `_0x...` 访问器求值，确认 `mini.encode`=JSON 序列化、`Util.encrypt` / `Util.encryptSM2` 两个分支及 `useSm2Encrypt` 条件。
4. 继续步进到真正加密点：常规分支识别出 `encodeURIComponent` + `btoa` + `encodeURIComponent`；SM2 分支识别出 `sm2Encrypt(str, sm2PubKey, 0)` 与硬编码公钥。
5. 解密/改包：常规分支用 `unquote → base64decode → unquote` 还原 JSON，篡改后用 `quote → base64encode → quote` 重新编码；SM2 分支在 Console 调用页面自身的 `Util.encryptSM2`（或按同算法用公钥重加密）构造新密文。
6. （可选）Burp → Proxy → Options → Match and Replace 新增规则：Type=Response body，Match=`Util.encryptAjaxParams(m.url,t)`，Replace=`JSON.stringify(t)`，刷新页面后在 Burp 中直接看到明文并改包；服务端要求密文时，把 Burp 上游代理指向 mitmproxy，由 mitmproxy 的 request 钩子对明文重新加密、response 钩子解密。

## PoC

```python
import base64, json, urllib.parse

def dec(v: str) -> dict:
    # encodeURIComponent(btoa(encodeURIComponent(json))) 的逆过程
    s = urllib.parse.unquote(v)
    s = base64.b64decode(s).decode()
    return json.loads(urllib.parse.unquote(s))

def enc(obj: dict) -> str:
    s = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
    s = urllib.parse.quote(s, safe='')          # encodeURIComponent
    s = base64.b64encode(s.encode()).decode()   # btoa
    return urllib.parse.quote(s, safe='')       # encodeURIComponent
```

```text
# Burp Proxy → Options → Match and Replace
Type:    Response body
Match:   Util.encryptAjaxParams(m.url,t)
Replace: JSON.stringify(t)
```

```python
# 文章给出的 mitmproxy 联动骨架（加密函数原文留空，属未完成部分）
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
import json

class DLNSProxy:
    @staticmethod
    def request(flow):
        if flow.request.method == 'POST':
            datas = json.loads(flow.request.get_content().decode())
            flow.request.raw_content = xxx加密算法(datas)  # 重新加密后上行
```

## 变体与关联

- **SM2 分支变体**：`encbody_` 前缀 + 硬编码 SM2 公钥，密文无法解密但可用公开公钥重加密；若服务端不校验签名/时间戳，同样可任意篡改业务参数。
- **关联**：[[code-analysis-reverse-obfuscation-js-forward-plaintext-override-burp-bridge]]（DevTools Overrides + JS-Forward 在加密前转发明文给 Burp）、[[tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt]]（Burp 透明加解密走运行时调用页面函数）、[[web-generic-auth-frontend-js-random-key-fixation-autodecoder]]（中间人替换 JS 固定随机密钥）都解决“在 Burp 中明文改加密包”的同一目标，但分别用本地桥、运行时 RPC、固定密钥实现；本卡是“识别伪加密并直接逆运算/替换加密调用”的最轻量路径。
- **边界**：文章未完成签名/时间戳问题的处理，并明确把 mitmproxy 加密实现留给后文；若目标有 HMAC/防重放签名，仅替换明文或重加密不足以通过校验，需要在页面签名函数处同步插桩。

## 检测与防御

- **原则**：不要把安全边界放在客户端 JS；前端加密只能混淆。服务端必须独立做身份认证、权限校验、关键参数签名/HMAC、时间戳/nonce 防重放与业务风控。
- **加固**：对关键接口强制校验参数格式（必须为密文/带合法签名），拒绝明文或旧格式；密钥/私钥只在服务端保存，前端仅保留公钥且定期轮换；签名覆盖全部关键字段并绑定会话。
- **检测**：监控同一会话的参数形态突然从密文变明文、密文长度/前缀异常、重放相同签名/nonce；对登录、支付、审批等关键操作做二次校验与服务端审计。
- **排查**：前端加密参数被逆向本身不是漏洞，但如果去掉加密后服务端仍正常处理，说明该加密只是“装饰”，应评估参数篡改、越权与批量爆破风险。
