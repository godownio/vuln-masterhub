---
id: code-analysis-reverse-obfuscation-frontend-d1d2d3-sm4-sm2-envelope
title: 前端 d1/d2/d3 国密信封逆向：SM4-CBC 报文 + SM2 加密随机 key/iv，响应以客户端私钥解
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: frontend-d1d2d3-sm4-sm2-envelope-reverse
aliases:
- d1 d2 d3 加密
- SM4-CBC 前端加密
- SM2 加密 key iv
- getters.rsa / getters.privatekey
- 国密前后端加解密
- sm-crypto 信封
tags:
- javascript
- reverse
- crypto
- sm2
- sm4
- sm3
- webpack
- execjs
- mitmproxy
- burp
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V557
  verified_at: '2026-11-12T00:35:49+08:00'
  notes: '已对照原文与15张截图核对：抓包 d1/d2/d3（图01）、搜索 d1: 定位 function B（图02/06）、y(32) 用 "0123456789ABCDEFabcdef"+crypto.getRandomValues 生成 32 hex（图08）、getters.rsa 值 04+128hex（图07）、模块 i("7c74") 导出 sm2/sm3/sm4（图03）、sm4.encrypt/decrypt CBC（图04/10/12）、作用域 e=32hex key/i=32hex iv（图05）、响应以 privatekey 解 d2/d3 再解 d1（图02 function k）、最终 Burp 明文（图15）——均与卡片一致。修正：一句话结论原写『RSA/SM2 公钥』，按代码改为 SM2（getter 名为 rsa，原文作者一度按 RSA/AES 猜测），与原理中『sm-crypto 纠正』一致。跳过核对：mitmdump 上下游代理部分 worker 判与既有 verified 卡 tools-burp-encrypted-api-proxy-decrypt-resign、tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce 同工程场景未单独建卡，本卡步骤6与关联已引用，成立；断点定位部分被本卡与 webpack 卡吸收，成立。dedup 首候选为自身，其余 AES-CBC/密钥固定等候选为不同算法与协议结构，非同链，保留。未执行任何 PoC。'
---

## 一句话结论

当请求与响应体都被替换成 `d1`/`d2`/`d3` 三个十六进制字段时，逆向可发现这是国密信封：`d1 = SM4-CBC(JSON(请求体), key=n, iv=o)`，`n`、`o` 各是 32 位十六进制随机数（16 字节），分别用服务端 SM2 公钥（代码 getter 名虽为 `rsa`，实际导出 `i("7c74").sm2`，原文作者一度按 RSA 理解）加密成 `d2`、`d3`；响应方向反过来用**客户端私钥**解 `d2`/`d3` 得到 n/o，再解 `d1`。因为客户端同时持有自己的私钥和服务端公钥（均可从前端断点取得），整条加解密可在本地离线复现。

## 原理

- 识别特征：抓包看到请求与响应都是 `{"d1":"...","d2":"...","d3":"..."}` 形式的长十六进制；页面 JS 中搜索 `d1:` 可定位生成函数。
- 生成函数（逆向还原后的形态）：
  ```js
  function B(t, e, i) {
      var r = a.getters.rsa;            // 服务端公钥
      var n = y(32), o = y(32);         // 两个 16 字节随机值（32 hex）
      var a1 = sm4.encrypt(JSON.stringify(t), n, { mode: 'cbc', iv: o });
      var s  = sm2.doEncrypt(n, r, 1);  // 返回带 04 前缀
      var u  = sm2.doEncrypt(o, r, 1);
      return { d1: a1, d2: s, d3: u };
  }
  ```
- 随机数 `y(32)`：从字符表 `"0123456789ABCDEFabcdef"` 生成 32 个字符（底层用 `crypto.getRandomValues`），长度 32 个十六进制字符 = 16 字节，正好是 SM4 的块长/密钥长度。
- 响应解密：页面在发送后会生成/持有一对客户端密钥（`getters.privatekey`），用 SM2 私钥分别解 `d2`、`d3` 得到 n、o，再用 `sm4.decrypt(d1, n, {mode:'cbc', iv:o})` 还原响应 JSON；若响应带 `code`/`resultValue` 等错误字段则直接返回，不进入解密。
- 算法识别为什么容易错：书写者最初按“CBC 模式”猜成 AES，实际反编译模块可见 `i("7c74").sm4` / `.sm2` / `.sm3`，即 `sm-crypto` 国密库；16 字节 IV 是 SM4 的块长，不是异常。
- 为什么可离线复现：SM4 的 key/iv 由客户端随机生成并通过 SM2 公钥封装，客户端私钥也在页面里；攻击者只要在断点处读出服务端公钥、客户端私钥（或直接复用页面函数），就能对任意报文加密、对任意响应解密，不需要服务端秘密。
- 工程化：把加密/解密函数抠到本地 JS（见关联卡），用 PyExecJS 调用，再以 mitmproxy/mitmdump 作为 Burp 的上/下游代理透明加解密，Burp 中即可按明文改包。

## 触发条件

- 前端 JS 中实现了上述 d1/d2/d3 信封（或同类「随机 key/iv + 非对称封装」结构），且能被下载/调试。
- 能读取到页面运行时使用的服务端公钥与客户端私钥（断点查看作用域，或直接从函数返回值取）。
- 本地具备 JS 运行环境（Node/PyExecJS）与 sm-crypto 等价实现（直接抠页面代码最稳）。

## 利用步骤

1. 抓包确认三个字段均为十六进制长串；DevTools 全局搜索 `d1:` 定位封装函数。
2. 在 `d1`/`d2`/`d3` 生成处下断点，刷新页面，单步进入封装函数，确认 `encrypt/doEncrypt` 的实现来自 `sm-crypto`（模块导出 `{sm2, sm3, sm4}`）。
3. 在作用域中读取 `getters.rsa`（服务端公钥）和 `getters.privatekey`（客户端私钥），并确认 `y(32)` 的字符表与长度。
4. 记录响应解密函数（`doDecrypt(d2, privatekey, 1)`、`doDecrypt(d3, privatekey, 1)`、`sm4.decrypt(d1, n, {mode:'cbc', iv:o})`）。
5. 抠出 sm-crypto 模块与封装函数，本地用相同参数复算：给定明文 t，随机 n/o，生成 d1/d2/d3；给定响应密文与私钥，解出 n/o 与明文。
6. 把本地 JS 接到 mitmdump（execjs 调用），在 Burp 上下游透明加解密；改包后按同样流程重新加密/重算字段。

## PoC

```javascript
// 断言点：页面中 sm-crypto 模块导出（module "7c74"）形如
// { sm2: {doEncrypt, doDecrypt, generateKeyPairHex}, sm3, sm4: {encrypt, decrypt} }

// 请求加密（等价复现）
var n = y(32), o = y(32);                       // 32 hex 随机
var d1 = sm4.encrypt(JSON.stringify(body), n, { mode: 'cbc', iv: o });
var d2 = '04' + sm2.doEncrypt(n, serverPubKey, 1);
var d3 = '04' + sm2.doEncrypt(o, serverPubKey, 1);
// POST {"d1": d1, "d2": d2, "d3": d3}

// 响应解密
var nn = sm2.doDecrypt(resp.d2.substring(2), clientPrivKey, 1);
var oo = sm2.doDecrypt(resp.d3.substring(2), clientPrivKey, 1);
var plain = sm4.decrypt(resp.d1, nn, { mode: 'cbc', iv: oo });
```

```text
# 原文实测：按上述流程在本地复算后，Burp 中可直接看到解密后的请求/响应 JSON，
# 并可用 SQL 注入等工具对明文参数测试（截图见原文最终效果）。
```

## 变体与关联

- 变体：`d2`/`d3` 的封装算法可能换成 RSA（PKCS#1 v1.5）或 ECIES；识别时看 `doEncrypt`/`publicEncrypt` 与密文前缀（`04` 通常是 SM2 未压缩点）。
- 变体：key/iv 的生成可能改为固定值、时间戳派生或会话密钥；只要能从前端逻辑复现即可同样解密。
- 关联：[[mobile-miniprogram-sm-crypto-protocol-burp-transparent]]（小程序场景的 SM2/SM4/SM3 协议，信封字段为 secretKey/data/smSign，与本卡 d1/d2/d3 不同但同属国密通信逆向）。
- 关联：[[code-analysis-reverse-frontend-request-response-encryption-automation]]（前端请求/响应加密的通用逆向方法）；[[tools-burp-encrypted-api-proxy-decrypt-resign]]（mitmproxy 双代理透明加解密与重签名的工程化）。
- 关联：[[code-analysis-reverse-obfuscation-webpack-runtime-module-loader-extract]]（本文用于抠出 sm-crypto 与封装函数的 webpack 模块装载器方法）。
- 边界：客户端公钥/私钥可能随页面刷新重新生成，若服务端绑定单次密钥，需在同一会话内完成加解密；一切仅在授权测试中使用。

## 检测与防御

- 认知：前端加密/国密信封只提高逆向成本，不构成安全边界；密钥与算法都在客户端，可被完整复现。
- 防御：真正的访问控制、鉴权与业务校验必须在服务端；对敏感接口做服务端风控、速率限制与行为审计，不能依赖「前端加密」防篡改。
- 检测：同一会话出现大量格式合法的 d1/d2/d3 密文、且请求方行为异常（高频、扫描特征）时告警；服务端校验 SM2 密文格式与 SM4 填充合法性，拒绝明显构造的密文。
- 加固：密钥协商使用服务端参与的双向密钥（如 TLS 客户端证书、服务端下发一次性会话密钥并校验请求签名），避免仅由客户端生成 key/iv。
