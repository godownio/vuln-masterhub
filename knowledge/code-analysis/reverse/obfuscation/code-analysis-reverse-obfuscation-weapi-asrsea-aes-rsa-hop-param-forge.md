---
id: code-analysis-reverse-obfuscation-weapi-asrsea-aes-rsa-hop-param-forge
title: 网易云 weapi 参数逆向：动态栈回溯锁定 t6n.be6Y → asrsea，还原 AES-CBC 二次加密 + 自制 RSA（encText/encSecKey）并用 Python 复刻
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-dynamic-stacktrace-asrsea-aes-cbc-rsa-param-forge
aliases:
- asrsea 加密还原
- encText encSecKey 生成
- weapi params 加密
- AES CBC 两次加密 + RSA 加密随机串
- 前端加密参数 Python 复刻
tags:
- js
- reverse
- obfuscation
- aes
- rsa
- crypto
- api-automation
- stacktrace
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:49:18+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。t6n.be6Y 中 window.asrsea(JSON.stringify(i6c), bse8W(["流泪","强"]), bse8W(RR7K.md), bse8W(["爱心","女孩","惊恐","大笑"])) 与控制台求值得到的 '010001'/256 位模数/'0CoJUm6Qyw8W8jud'、内部 a(16 位随机串)/b(CryptoJS AES-CBC，iv=0102030405060708，toString 输出 base64)/c(setMaxDigits(131)+RSAKeyPair+encryptedString)/d(encText=b(b(d,g),i)、encSecKey=c(i,e,f)) 四函数以及 Python 复刻(i 反转 hexlify→pow→zfill(131))均与正文源码逐项一致；动态栈回溯定位流程与正文 send 断点+逐层看变量描述一致。dedup 首候选为自身 trigram=1.000，外部最高为单字段 encryptCode AES 卡(0.117)，算法结构不同，保留合理。已修正关联中的失效 id 前缀为 code-analysis-reverse-frontend-request-response-encryption-automation。未验证点：AES 填充——原理写 CryptoJS 默认 PKCS7(正确)，但 PoC 沿用原文 Python 的 chr(2)*pad，仅在 pad==2 时等价，卡内已注『需按实际填充调整』；『csrf_token 留空实测不校验』超出正文；PoC 未执行。原文无版本信息，未 set-versions。
---

## 一句话结论

当接口用 `params`/`encSecKey` 这类密文字段替代明文参数、且未混淆的 JS 被拆成大量压缩文件时，可以先用 DevTools 在 `XMLHttpRequest.send` 下断点、逐个放行非目标请求，命中目标请求后沿调用栈向上找"参数被赋值"的那一层，锁定发送函数（本例 `t6n.be6Y`）与加密函数（`window.asrsea`）；该函数结构为"16 位随机串 `i` + AES-CBC 用常量 key 加密再被 `i` 二次加密得到 `encText`，同一 `i` 取出后用自制 RSA 得到 `encSecKey`"，把随机串固定即可在 Python 里完全复刻出合法请求。

## 原理

- **定位靠"发送点 + 栈回溯"而不是全局搜索**：压缩/混淆后的变量名（`t6n`、`be6Y`、`bVj1x`）无法按名字搜索；但所有请求最终都经过 `XMLHttpRequest.send`，在此下断点后按 URL 判断是否目标请求，命中后调用栈上就是"业务函数 → 请求封装 → send"的真实层级，从 send 往上逐层看局部变量，就能找到组装 `params`/`encSecKey` 的那一层（本例 `t6n.be6Y`）。
- **加密函数的识别特征**：`window.asrsea(...)` 的调用参数是四个"看起来像魔法值"的表达式，逐个丢进控制台求值即可还原：`bse8W(["流泪","强"])` → `'010001'`（RSA 公钥指数）、`bse8W(RR7K.md)` → 256 位十六进制模数、`bse8W(["爱心","女孩","惊恐","大笑"])` → `'0CoJUm6Qyw8W8jud'`（AES 密钥）、第一个参数是 `JSON.stringify(明文对象)`。这四个值都是常量，因此"看起来加密很复杂"实际上只依赖一个随机串。
- **内层 AES 是标准构造**：`b(a,b)` 中 `CryptoJS.AES.encrypt(Utf8.parse(a), Utf8.parse(b), {iv: Utf8.parse("0102030405060708"), mode: CBC})`——key 由调用方传入、iv 是写死的 `0102030405060708`、模式 CBC、默认 PKCS7 填充、输出为 base64（`toString()` 的默认格式）。
- **随机串只为 `encSecKey` 服务**：`d(d,e,f,g)` 生成 `i = a(16)`（从 `[a-zA-Z0-9]` 里随机取 16 个字符），`encText = b(b(d,g), i)` 即"先用 `g` 加密、再用 `i` 加密"，`encSecKey = c(i,e,f)` 是把 `i` 反转后当大整数，做 `pow(m, e, n)` 的 RSA 加密。由于服务端需要用私钥解出 `i` 才能解第二层 AES，`encSecKey` 与 `encText` 必须成对；但 `i` 的取值对服务端没有约束（任意 16 位串都行），因此**固定一个 `i` 就能离线算出两者**。
- **RSA 是"自制"实现**：`setMaxDigits(131); RSAKeyPair(b,"",c); encryptedString(d,a)` 是经典 JS BIGINT RSA（Barrett 约减），与标准 PKCS#1 v1.5 不同——没有随机填充、直接对大整数做模幂并把结果左补零到 131 个十六进制字符。Python 里用 `pow(int(hexlify(i[::-1]),16), int(e,16), int(n,16))` 再 `format(x).zfill(131)` 即可等价。
- **为什么可行**：浏览器必须能在本地算出密文，密钥与算法一定在前端；只要把常量扣出、"随机"固定，就能脱离浏览器批量构造请求，而不需要破解任何密码学原语。

## 触发条件

- 目标接口（本例 `/weapi/song/enhance/player/url/v1`）要求 `params` + `encSecKey`（可能还有 `csrf_token`），不携带这两个字段直接请求会被拒。
- 加密逻辑由前端 JS 完成，密钥/模数/随机串生成方式都在可下载的 JS 中（无服务端签名绑定）。
- 能打开 DevTools 或在抓包工具里查看请求（若页面有反调试，可先用代理替换 JS 的方式绕过）。
- 请求只做"参数保密"，未绑定时间戳/设备指纹等一次性因子（本例 `i` 随机但不校验），因此可重放与批量构造。

## 利用步骤

1. 抓包确定目标请求与字段：XHR 筛选后找带 `params`/`encSecKey` 的 POST，记录 URL、`csrf_token`、明文参数（如 `ids`、`level`、`encodeType`）。
2. Sources → XHR/fetch Breakpoints 添加目标 URL 片段，或在 `XMLHttpRequest.send` 下断点；刷新页面触发请求，逐个放行非目标请求，直到停在目标请求的 send。
3. 观察 send 处的参数，确认已被加密（是密文字段而非明文）；沿调用栈往上逐层看局部变量，找"参数还是明文、下一步被加密"的那一层。
4. 在那一层找到 `window.asrsea(JSON.stringify(i6c), bse8W([...]), bse8W(RR7K.md), bse8W([...]))`，把四个参数逐一在控制台求值，得到 JSON 明文字符串、`'010001'`、256 位十六进制模数、`'0CoJUm6Qyw8W8jud'`。
5. 在控制台对该函数下断点/直接调用，跳入 `asrsea` 定义，抠出 `a/b/c/d` 四个内部函数：确认 AES 的 key/iv/模式与输出编码、确认 RSA 用的是 `RSAKeyPair+encryptedString`。
6. 本地固定 `i`（16 位任意字符），用 Python 复刻：`encText = base64(AES_CBC(key=i, iv=0102030405060708, data=base64(AES_CBC(key=g, ...))))`，`encSecKey = zfill(pow(int(hexlify(i[::-1]),16), 0x010001, n), 131)`。
7. 用固定 `i` 生成一组参数，先与浏览器控制台算出的值对比验证（同一 `i` 下两者必须逐字节相同），再拿去请求目标接口，确认返回正常数据。
8. 需要批量时，每首歌改明文里的 `ids` 即可，`csrf_token` 可留空（实测该接口对空 token 不校验），无需重新解 `encSecKey`。

## PoC

Python 复刻（`d/e/f/g` 即 `asrsea` 的四个入参，`i` 固定）：

```python
import json, base64, binascii
from Crypto.Cipher import AES

IV = b'0102030405060708'
G = '0CoJUm6Qyw8W8jud'          # bse8W(["爱心","女孩","惊恐","大笑"])
E = '010001'                    # bse8W(["流泪","强"])
N = '00e0b509f6259df8...22b8e7' # bse8W(RR7K.md)，256 位十六进制模数

def aes_cbc(data: str, key: str) -> str:
    pad = 16 - len(data) % 16
    data = data + chr(2) * pad            # CryptoJS 默认 Pkcs7，需按实际填充调整
    c = AES.new(key.encode(), AES.MODE_CBC, IV)
    return base64.b64encode(c.encrypt(data.encode())).decode()

def rsa_enc(text: str) -> str:
    m = int(binascii.hexlify(text[::-1].encode()), 16)
    return format(pow(m, int(E, 16), int(N, 16)), 'x').zfill(131)

i = '0123456789abcdef'                    # 固定 16 位随机串
d = json.dumps({"ids": "[1325905146]", "level": "standard",
                "encodeType": "aac", "csrf_token": ""})
encText = aes_cbc(aes_cbc(d, G), i)
encSecKey = rsa_enc(i)
print({"params": encText, "encSecKey": encSecKey})
```

浏览器侧对照（控制台）：

```javascript
asrsea(JSON.stringify({ids:"[1325905146]",level:"standard",encodeType:"aac",csrf_token:""}),
       "010001", "<模数>", "0CoJUm6Qyw8W8jud")
```

## 变体与关联

- **定位手法变体**：全局搜 `encrypt`/`aes`/`rsa` 后逐个下断点（慢但适用于没有思路时）；Network → Initiator 点进调用栈；XHR 断点按 URL 精确命中；栈回溯只忽略 `apply`/`call`/框架内部帧，业务帧通常 2–4 层就能找到。
- **加密结构变体**：单层 AES、AES 后再 base64 拼接 iv（见 `code-analysis-reverse-obfuscation-js-aes-parameter-restore`）、AES + 请求头签名（`m=md5(salt+ts)`）、或本例的"双层 AES + RSA 传随机串"；识别关键始终是"哪些参数是常量、哪个环节是随机、随机是否被服务端校验"。
- **随机串处理变体**：若服务端校验 `i` 与某字段的一致性，可在本地按相同规则重新生成；若不校验（本例），固定即可。
- **关联**：`code-analysis-reverse-obfuscation-js-aes-parameter-restore`（同一"定位-抠函数-复刻"方法论的另一案例）、`code-analysis-reverse-frontend-request-response-encryption-automation`（三种定位方法与多层加密的通用流程）、`code-analysis-reverse-obfuscation-js-config-array-console-aes-key-iv`（从配置数组里取 key/iv）。
- **边界**：密钥由服务端下发给已登录会话且每次请求变化、或服务端对 `encSecKey` 解出的 `i` 做时间/设备绑定、或页面启用 SRI + 反调试导致无法获取 JS 时，该复刻方式需要额外处理；此外前端加密只是提高爬取成本，不构成访问控制。

## 检测与防御

- **检测**：同一账号/IP 出现与浏览器不一致的请求节奏（无前置埋点/无 `weblog` 上报却直接打业务接口）、`params` 长度固定且 `encSecKey` 恒定（说明攻击者固定了随机串）、`csrf_token` 恒为空；接口成功率与 UA/指纹不一致。
- **防御**：把 `i` 与一次性 nonce/时间戳绑定并由服务端校验（固定随机串即失效）；在 `encSecKey` 中嵌入设备/会话标识并在服务端核对；对关键接口做签名 + 频控 + 行为风控；把敏感数据放在服务端权限校验后返回，不要依赖"前端加密"作为安全边界。
