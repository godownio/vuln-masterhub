---
id: tools-burp-autodecoder-xray-encrypted-body-adapter-scan
title: 加密/自定义包装 body 的 Burp+xray 联动扫描：autoDecoder 解密并改写成纯 JSON 交给 xray，burp2 还原包装并重加密后发给服务端
type: scenario
domain: tools
path: tools/burp
technique: autodecoder-xray-encrypted-body-adapter-scan
aliases:
- autoDecoder xray 联动
- 加密流量扫描
- 密文 body 扫描
- Burp xray 串联
- body 改写 JSON 给扫描器
- 两段 Burp 解密重加密
tags:
- burp
- autodecoder
- xray
- encrypted-traffic
- scanner
- proxy-chain
- api-testing
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V691
  verified_at: '2026-11-13T16:25:22+08:00'
  notes: 已对照原文与 16 张图核对：burp1(伪装解密的加密接口)=/decode、burp2 解密=/decode 加密=/encode 与图 04/09 一致；已修正接口槽位表述与 PoC 端口冲突（Flask 7777 与 xray 7777）。原文只展示 xray sqldet 命中（图16），未手工复验该 SQLi，卡内已注明；未复跑完整链路。
---

## 一句话结论

当目标请求 body 整体 base64 编码（或加密）并被包在 `<Request><Data>{json}</Data></Request>` 这类自定义格式里时，xray 作为 MITM 扫描器既解析不出参数也无法把 payload 注入到服务端认识的字段；可以用两个 Burp 实例加 autoDecoder 组成“burp1 解密并把 body 改写成纯 JSON → xray 扫描 → burp2 把 xray 改过的 JSON 重新包装并加密 → 服务器”的三段链路，让扫描器对原本不可读的密文接口做 SQL 注入等测试。

## 原理

- **扫描器需要可解析的参数**：xray 的 sqldet 等插件按 HTTP 参数（query/body 表单/JSON 键值）注入 payload 并比较响应。原始 body 是 `base64(<Request action="..."><Data>{"KEY":"VALUE"}</Data></Request>)`：对 xray 来说 body 是一段不可解析的 Base64/自定义文本，它不知道 `KEY` 是参数，也就不会在正确位置注入。
- **burp1 的“解密”要做两件事**：先 base64 解码，再把 `<Data>` 里的 JSON 抠出来，并把 Content-Type 改成 `application/json`，让交给 xray 的请求就是一个普通 JSON API 请求。文章的解码逻辑是 `param.decode().split('{')[1].split('}')[0]` 取出第一个花括号内的内容，再补回 `{...}`（只适用于单层 JSON、内容中无 `}`；复杂 JSON 应改用正则/括号配平）。
- **xray 的位置**：xray 以 `ws --listen 127.0.0.1:7777 --plugin sqldet` 启动 MITM，burp1 的上游代理指向 xray 7777；xray 的 `http.proxy` 指向 burp2 的 8888，把改好的请求转给 burp2。这样 xray 既能看见明文 JSON，又不会直接打到服务端。
- **burp2 的“加密”负责还原**：burp2 的 autoDecoder 加密接口收到 xray 注入后的 JSON，重新拼成 `<Request ... request="JSON" response="JSON"><Data>` + JSON + `</Data></Request>`，再整体 base64 发给服务端。服务端只看到合法密文，扫描器的 payload 藏在解密后的 JSON 字段里。
- **为什么链路能成立**：解密与加密接口互为逆变换，保证“服务端格式不变、扫描器看到明文”；xray 修改的是中间明文，burp2 才负责重新包装。响应方向也可以配置解密接口，便于人工看结果；不配置时 xray 仍然比较原始响应。
- **关键配置**：Burp1 的进入端口任意（浏览器/Repeater 经它发出）→ upstream proxy 127.0.0.1:7777（xray）；xray `http.proxy` → 127.0.0.1:8888（burp2，图 09 中 burp2 的 Proxy listener 即 127.0.0.1:8888）；burp2 直连目标或走出口代理。两个 Burp 也可以是两个独立实例/两个项目，避免 autoDecoder 加解密方向互相干扰。
- **autoDecoder 的接口槽位**：插件只在“发往服务端”方向调用“加密接口”。“burp1 的下游”其实是 xray 而不是真实服务端，所以 burp1 要把**解密脚本填在“加密接口”槽**（图 04：解密接口填 …/encode（当时为直通，见图 12）、加密接口填 …/decode）；burp2 才是常规配置：解密接口=/decode、加密接口=/encode（图 09）。
- **边界**：xray 只处理 HTTP/1.1；body 若是二进制密文/自定义分隔而非“base64+文本包装”，需要先转成文本 JSON，否则无法适配；外层属性（`action`、`request` 等）如果参与服务端校验，改写时必须保留；扫描器命中可能误报，需要人工复验。文章图 16 显示 xray sqldet 报告了 Boolean/string 类型的 SQL 注入 case，但未手工复验该漏洞。

## 触发条件

- 目标请求/响应 body 经过 Base64 或加密，并包在扫描器不识别的自定义格式里，导致直接扫描无法注入。
- 已能从 JS/客户端或历史流量还原出编码/加密算法（至少能实现本地 decode/encode）。
- 有 Burp Suite（可跑两个实例或两个项目）与 autoDecoder 插件；有 xray 且支持 `ws` 监听与上游代理。
- 授权测试环境；目标允许来自扫描链路的请求。

## 利用步骤

1. 抓一个原始请求，手工 base64 解码，确认外层包装与内层 JSON 结构（如 `<Request ...><Data>{"KEY":"VALUE"}</Data></Request>`）。
2. 写 Flask/本地 HTTP 接口：
   - `/decode`：取 `dataBody` → base64 解码 → 提取内层 JSON → 返回纯 JSON（本例 `split('{')[1].split('}')[0]` 再补 `{}`）；
   - `/encode`：取 `dataBody`（xray 改过的 JSON）→ 包回 `<Request ...><Data>...</Data></Request>` → base64 → 返回。
3. burp1 的 autoDecoder“接口加解密”页：**加密接口**填 `http://<flask>/decode`、解密接口填 `http://<flask>/encode`（文章原话：插件貌似只做了自动加密发送到服务端，所以解密脚本要写在加密接口里；图 04）；burp2：解密接口填 `/decode`、加密接口填 `/encode`（图 09）。在插件里用“解密>>>/<<<加密”按钮验证。
4. burp1 设置上游代理到 xray（127.0.0.1:7777）；xray 启动：`xray.exe ws --listen 127.0.0.1:7777 --html-output test.html --plugin sqldet`，其 `http.proxy` 指向 burp2（127.0.0.1:8888）；burp2 直连目标。
5. 从 burp1 的 Repeater 发请求，观察 xray 控制台出现 `detected sqldet based case`，burp2 发出的 body 已恢复为密文包装。
6. 在 xray HTML 报告/控制台查看命中参数与 payload，再回到 burp1 手工改包复验，避免误报。

## PoC

Flask 解密接口（提取 `<Data>` 内 JSON，适用于单层 JSON）：

```python
from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/decode', methods=["POST"])
def decrypt():
    param = request.form.get('dataBody')
    param = base64.b64decode(param.encode()).decode()
    param = param.split('{')[1].split('}')[0]   # 取第一个 {...} 内的内容
    param = '{' + param + '}'
    return param

@app.route('/encode', methods=["POST"])
def encrypt():
    param = request.form.get('dataBody')        # xray 注入后的 JSON
    param = '<Request action="..." request="JSON" response="JSON"><Data>' + param + '</Data></Request>'
    return base64.b64encode(param.encode()).decode()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="8000")   # 不要用 7777，避免与本机 xray 监听端口冲突
```

xray 启动与代理方向：

```text
burp1 (进入端口任意；upstream -> 127.0.0.1:7777)
  -> xray ws --listen 127.0.0.1:7777 --plugin sqldet --html-output test.html
     (http.proxy -> 127.0.0.1:8888)  # 这里的 8888 是 burp2
  -> burp2 (127.0.0.1:8888; autoDecoder 解密接口 /decode、加密接口 /encode)
  -> 目标服务器
```

说明：原文脚本写 Flask 监听 7777，而 xray 也监听 7777；文中接口 URL 实际是带 `:80` 的地址（图 09），说明 Flask 与 xray 并非同机同端口，复现时两者端口需错开。Content-Type 在 burp1 解密侧改成 `application/json` 才能让 xray 按 JSON 参数解析；`<Request>` 的属性、`<Data>` 标签与 base64 编码必须与目标完全一致，否则服务端拒绝。复杂 JSON（含多个 `}` 或嵌套对象）不能直接用 `split('}')`，应改用正则或括号配平提取。

## 变体与关联

- **autoDecoder 脚本约定与编码细节**：见 [[tools-burp-autodecoder-flask-custom-encrypt-decrypt-script]]（dataBody/dataHeaders、bytes/str、Base64 变体、PKCS 填充、JSON 字段处理）。
- **不还原算法而运行时调用前端函数**：Sekiro/JSRPC 方案见 [[tools-burp-autodecoder-flask-sekiro-jsrpc-body-encrypt-decrypt]]、[[tools-burp-galaxy-jsrpc-auto-encrypt-decrypt-sign]]。
- **单 Burp 的解密-重签代理**：见 [[tools-burp-encrypted-api-proxy-decrypt-resign]]；mitmproxy + yakit 双链路见 [[tools-burp-mitmproxy-dual-chain-aes-cbc-yakit-hotload-phone-bruteforce]]。
- **扫描器替换**：xray 可换 Burp Scanner（需自定义扩展改写 body）或 sqlmap（`--proxy` 指向 burp2，并在 burp1 侧解密）；核心是“明文给扫描器、密文给服务端”。
- **响应加密**：给 burp2 或 burp1 的响应方向也配解密接口，便于人工看回显；不配置时 xray 仍可用响应长度/状态做差异比较。
- **边界**：外层属性参与签名/校验时需同步改签名；xray 只支持 HTTP/1.1；扫描器 payload 可能触发业务风控，需控制速率。

## 检测与防御

- **服务端**：不要用“body 加密/自定义包装”代替输入校验；网关/服务端解密后仍要做参数化查询、类型校验与 WAF 规则；加密只增加扫描成本，不阻止攻击者自建解密层。
- **检测**：监控解密后出现扫描器特征 payload（如 sqldet 的 `and '1'='1`、`to_char` 等）；同一来源短时间大量相似请求；上游代理链路特征（xray 默认 UA/证书、burp 默认证书）——TLS 指纹与证书异常。
- **防御**：对加密接口做请求签名/时间戳/nonce，防止重放与随意改包；限制单 IP 频率；在服务端解密后记录完整明文用于审计（注意合规）。
- **测试侧提醒**：本卡是授权渗透的流量适配方法；扫描器命中后必须手工复验，不能直接把 xray 报告当漏洞结论。
