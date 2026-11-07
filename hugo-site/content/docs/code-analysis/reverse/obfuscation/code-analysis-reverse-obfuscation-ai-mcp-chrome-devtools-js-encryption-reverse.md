---
id: code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse
title: AI + Chrome DevTools MCP 辅助前端加密 JS 逆向：自然语言定位加密参数并生成验证脚本
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: ai-mcp-chrome-devtools-js-encryption-reverse
tags:
- javascript
- reverse
- frontend-encryption
- mcp
- chrome-devtools
- ai-assisted
- aes
- login
- brute-force
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V142
  verified_at: '2026-11-06T06:23:12+08:00'
  notes: 已对照原文 45 张图逐张核对：InitMmEncrypt 的 KEY=1A2B3C4D5E6F7G8H、IV=BITDXY_ZYKJ_5818、AES-CBC+ZeroPadding+Base64、Chrome DevTools MCP 配置、Trae/Node/npm 环境、mitmproxy 与 Burp Intruder 上游代理链均一致。已修正 PoC 中 ZeroPadding 对齐块行为（CryptoJS 对齐时不补块）。未验证点：按截图 KEY/IV+ZeroPadding 计算 123456 得不到原文截图密文 61ATFuXJ23WTHA0Y7tvkeQ==（该密文用同 Key/IV 解出为 '1/3456'+零填充），原文密文一致性未能复现；PoC 未跑通目标站；原文未标受影响版本，未设置 affected_versions；frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse/
draft: false
kb_aliases:
- AI 辅助 JS 逆向
- Chrome DevTools MCP
- 一句话逆向
- 前端加密参数定位
- Trae MCP
- AES 登录参数还原
---

## 一句话结论

把 Chrome 以远程调试模式交给 Chrome DevTools MCP，再在支持 MCP 的 AI IDE 里用一句自然语言要求“分析登录页 mm 参数的加密逻辑并生成 Python 验证脚本”，AI 可自动打开页面、检索 JS、定位加密函数并产出可运行的加密脚本；用同一明文对比浏览器请求密文即可验证还原是否正确，随后可把脚本接入 mitmproxy 为 Burp Intruder 自动加密。

## 原理

- 前端加密不是安全边界：浏览器必须能算出密文，因此算法、Key、IV 一定存在于 JS 中或可在页面运行时调用。逆向的目标是复用浏览器已有的计算，而不是“破译”。
- Chrome DevTools MCP 把页面打开、DOM/网络快照、JS 执行等能力暴露给 AI IDE（如 Trae 的 Builder with MCP），模型可以按自然语言指令在真实登录态页面中定位加密代码，而不需要人工逐文件搜索。
- 环境链路：Chrome 用 `--remote-debugging-port=9222 --user-data-dir=<临时目录>` 启动（隔离日常数据且保留登录态）；Node.js > v20.19 与 npm 用于运行 `npx chrome-devtools-mcp@latest`；在 AI IDE 的 MCP 设置中填入配置 JSON 即可。
- 典型定位过程：打开目标 URL → 获取页面/网络快照 → 在 JS 中搜索 `encrypt`、`encryptedData`、`setpublickey`、`Crypto`、`AES`、`RSA`、`CryptoJS`、`key` 等关键字 → 找到加密函数（案例为 `InitMmEncrypt`，AES-CBC + ZeroPadding + Base64，Key/IV 硬编码）→ 生成 Python 脚本。
- 验证方法：让 Python 对已知明文（如 `123456`）加密，与浏览器登录请求中的 `mm` 字段比对；密文完全一致才说明算法、Key、IV、padding、编码均还原正确。
- 后续放大：把验证过的加密逻辑写成 mitmproxy 脚本，Burp Intruder 发送明文口令，脚本在转发前实时加密 `mm`，即可对“前端加密登录”做自动化爆破。

## 触发条件

- 目标为授权测试的 Web 登录页，密码/参数由前端 JS 加密（AES/RSA/混合），且能在浏览器中正常触发加密。
- 本机可安装并运行 Chrome、Node.js（> v20.19）、npm，以及支持 MCP 的 AI IDE（如 Trae）。
- Chrome 能以远程调试模式启动，并保留目标站点的登录态；MCP 服务可访问该调试端口。
- 接受 AI 生成结果必须用已知明文/密文对照验证，不能直接信任。

## 利用步骤

1. 安装 Node.js（> v20.19）与 npm，验证 `node -v`、`npm -v`。
2. 以远程调试模式启动 Chrome：`chrome.exe --remote-debugging-port=9222 --user-data-dir=C:\temp\chrome-debug`，在该实例中登录目标站点。
3. 在 AI IDE 的 MCP 设置中添加 `chrome-devtools-mcp`（市场安装或手动粘贴 JSON）。
4. 选择 Builder with MCP，发送指令：“`http://target/` 这个登录页面，帮我分析 `mm` 参数对应的加密逻辑，并在当前目录生成一个 Python 加密脚本用于验证”。
5. 让 AI 打开页面、检索 JS、定位加密函数；检查其给出的算法、Key、IV、padding、编码是否与源码一致。
6. 运行生成的 Python 脚本，对已知明文加密；在浏览器输入同一明文抓包，对比 `mm` 密文是否一致。
7. 验证通过后，让 AI 生成 mitmproxy 脚本：站点 → Burp（8080）→ mitmproxy（8081）→ 服务器，脚本把 Burp Intruder 发出的明文密码加密为 `mm` 后转发。
8. 配置 Burp 上游代理指向 mitmproxy，安装 mitmproxy CA 证书，用 Intruder 对密码字段爆破；在 mitmproxy 日志中确认每次请求的 `mm` 已按预期加密。

## PoC

```json
{
  "mcpServers": {
    "Chrome DevTools MCP": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"],
      "env": {}
    }
  }
}
```

```python
from Crypto.Cipher import AES
import base64

KEY = b"1A2B3C4D5E6F7G8H"   # 案例中硬编码于 JS
IV  = b"BITDXY_ZYKJ_5818"

def init_mm_encrypt(pwd: str) -> str:
    data = pwd.encode()
    # CryptoJS.pad.ZeroPadding：补零到块大小整数倍（已对齐时不补）
    data += b"\x00" * ((-len(data)) % 16)
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(data)
    return base64.b64encode(ct).decode()

print(init_mm_encrypt("123456"))  # 与浏览器请求中的 mm 对比
```

```python
# mitmproxy 脚本思路（简化）：拦截 Burp 发来的明文密码并加密 mm
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    if "login_verifyUser" in flow.request.path:
        form = flow.request.urlencoded_form
        if "mm" in form:
            form["mm"] = init_mm_encrypt(form["mm"])
```

## 变体与关联

- 变体：手工逆向可用全局搜索、XHR/fetch 断点、Initiator 调用栈；也可用 AntiDebug_Breaker 等浏览器插件 Hook CryptoJS 直接吐出 Key/IV/密文。
- 变体：加密算法可能是 AES 固定 Key、RSA、AES+RSA 混合、自定义 Base64/Hex；AI 生成脚本后必须逐一核对 padding 与编码。
- 变体：不接 mitmproxy 时，可用 PyExecJS 直接调用扣出的 JS，或用 Burp 插件在 Intruder payload 处理阶段加密。
- 关联：[[tools-burp-encrypted-api-proxy-decrypt-resign]]（mitmproxy 加解密/重签代理链）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（手工 JS 逆向与 PyExecJS）、[[code-analysis-reverse-obfuscation-js-aes-parameter-restore]]（AES 参数还原）。

## 检测与防御

- 服务端不要把客户端加密当作安全边界；密钥/IV 硬编码在前端等同于公开，应使用服务端签发的一次性挑战、会话绑定与速率限制。
- 对登录接口做失败次数/频率限制、验证码、设备指纹与异常检测；前端加密只能提高自动化成本，不能阻止代理重算。
- 使用 MCP 浏览器控制时注意：页面内容可能包含提示注入，AI 可能被诱导执行非预期操作；应限制 MCP 的浏览器范围与权限，关键操作人工确认。
- 检测：同一账号短时间大量登录请求且密文格式合法、来源 IP/设备异常；mitmproxy 类代理链可通过 TLS 指纹、请求时序与客户端环境一致性辅助识别。
