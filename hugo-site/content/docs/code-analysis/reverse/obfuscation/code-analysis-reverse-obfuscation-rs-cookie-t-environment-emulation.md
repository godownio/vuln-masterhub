---
id: code-analysis-reverse-obfuscation-rs-cookie-t-environment-emulation
title: 瑞数 6 代 cookie_t 扣代码补环境：抽取 page_url 动态 JS 与 VM 生成逻辑，在浏览器化环境执行后带 cookie_s/cookie_t 直连
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: rs-cookie-t-extract-environment-emulation
tags:
- js-reverse
- obfuscation
- rs
- bot-defense
- anti-bot
- cookie-t
- environment-emulation
- vm
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:18:26+08:00'
  notes: 已对照幻灯片核对：图16 第一次请求 Set-Cookie FSSBB... 与响应 HTML 内联自执行函数、图17 第二次外链 JS $_ts=window['$_ts'];$_ts.scj=[];$_ts['dfe1675']=... 后第三次带 cookie_s+cookie_t 返回 200、图18 扣代码(page_url 源码部分+VM 生成 cookie_t 部分)+补环境+get_cookie(){return document.cookie}+Python get_data 带 cookie 请求返回 JSON，均与卡内一致；文中 cookie_s 值 FSSBB... 与 cookie_t 名后缀 _80_RS 属两份 Cookie 的命名/值细节，卡内行文略有压缩但主结论正确；未实测。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-rs-cookie-t-environment-emulation/
draft: false
kb_aliases:
- 瑞数补环境
- 扣代码补环境
- RS cookie_t 生成
- cookie_s cookie_t
- $_ts.scj
- 瑞数 6 代 bypass
- Botgate 绕过
---

## 一句话结论

瑞数（RS）6 代/VMP 站点的页面访问要求同时携带首次响应下发的 cookie_s 和由混淆 JS 现场计算的 cookie_t；把页面返回的动态 JS（读取 `window['$_ts']`、构建 `$_ts.scj` 的自执行部分）以及 VM 中生成 cookie_t 的逻辑“扣”出来，在补好 window/document/navigator 等浏览器环境的执行器里运行并读取 `document.cookie`，就能批量生成可用的 cookie_t，随后用 Python 带 cookie_s+cookie_t 直接请求页面/接口。

## 原理

- **RS 的两段式挑战**：第一次请求返回 HTML，响应头 `Set-Cookie` 下发 cookie_s（形如 `FSSBB...`），HTML 中嵌入一段高度混淆的自执行 JS（外链 JS 内容固定，动态部分在页面内）；浏览器执行后把中间状态写入 `window['$_ts']`（如 `$_ts.scj=[]`），并生成 cookie_t。
- **为什么需要两次/三次请求**：第二次请求加载外链 JS（内容固定，可缓存），第三次请求同时携带 cookie_s 与 cookie_t（形如 `<FSSBB..._80_RS>` 与随机值），Botgate 校验两份 Cookie 与浏览器环境信息一致后才返回正常页面（状态码 200，而不是 400 Bad Request）。
- **扣代码**：把页面源码中的动态 JS 部分（page_url 源码）与 VM 中负责生成 cookie_t 的部分提取出来，去掉无关的页面业务代码，保留会写 cookie 的核心逻辑。
- **补环境**：这些 JS 依赖浏览器的 window、document、navigator、location、screen、setTimeout、Canvas/WebGL 等对象和 API，缺一个就可能抛错或生成错误值。用 Node + jsdom 或自写的 Proxy 沙箱按需伪造这些对象（“补环境”），让脚本以为自己在真实浏览器中执行，从而产出与真实浏览器一致的 cookie_t。
- **可离线批量**：cookie_t 由确定性算法 + 环境输入生成，只要环境参数稳定，生成的 Cookie 在有效期内可被服务端接受；因此适合在 Python 自动化测试/扫描前先跑一次生成器，再带上两份 Cookie 发请求。

## 触发条件

- 目标使用瑞数 6 代或 VMP 防护，页面/接口要求 cookie_s+cookie_t。
- 能获取首次响应（cookie_s 与动态 JS），并能执行 JS（Node/jsdom、Playwright/Selenium 或浏览器控制台）。
- 防护未把 cookie_t 与 IP/UA 强绑定，或执行器能复现相同环境参数；cookie 有有效期，过期需重新生成。
- 仅用于授权测试。

## 利用步骤

1. 用 requests/curl 发起第一次页面请求，保存响应头中的 cookie_s 与响应体 HTML。
2. 从 HTML 中提取动态自执行 JS（搜索 `$_ts`、`window['$_ts']`、`document.cookie`、`setTimeout` 等特征），区分“固定外链 JS”和“页面内动态 JS”；VM 版本还需定位生成 cookie_t 的虚拟机入口。
3. 扣代码：只保留动态 JS 与生成 cookie_t 所需的最小子集，删除业务逻辑和无关依赖。
4. 补环境：在 Node 中用 jsdom 或 Proxy 沙箱提供 window/document/navigator/location/screen 等对象，按报错逐个补齐缺失 API（这是“补环境”的主要工作量）。
5. 执行脚本，劫持 `document.cookie` 的 setter 或执行后读取，得到 cookie_t；与 cookie_s 一起写入 Cookie 头。
6. 用 Python requests 带 `cookie_s=<...>; cookie_t=<...>` 请求目标页面/API，确认返回 200 与正常内容；后续请求复用该 Cookie，过期后重复 1-5 步。
7. 若只是想快速验证，也可直接用 Playwright/Selenium 打开页面，等待挑战完成后再导出浏览器 Cookie 交给 Python，省去手工补环境（本质相同）。

## PoC

```python
# 1) 首次请求：拿 cookie_s 与动态 HTML
import re, requests
s = requests.Session()
r = s.get("https://target.example/page", headers={"User-Agent": "<真实 UA>"})
cookie_s = r.cookies.get("FSSBB") or r.cookies.get_dict()   # 名称按实际 Set-Cookie 调整
html = r.text
js = re.search(r"<script[^>]*>(.*?\$_ts.*?)</script>", html, re.S).group(1)  # 示意
open("rs_dynamic.js", "w").write(js)
```

```javascript
// 2) Node + jsdom 补环境执行（示意）：伪造 window/document 后执行扣出的 JS
const { JSDOM } = require("jsdom");
const fs = require("fs");
const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://target.example/page" });
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;
global.location = dom.window.location;
global.setTimeout = setTimeout;
eval(fs.readFileSync("rs_dynamic.js", "utf8"));
console.log(document.cookie);   // 取出 cookie_t
```

```python
# 3) 带 cookie_s + cookie_t 直连
cookies = {"<cookie_s_name>": cookie_s, "<cookie_t_name>": "<上一步生成>"}
print(requests.get("https://target.example/api/data", cookies=cookies,
                   headers={"User-Agent": "<真实 UA>"}).text)
```

## 变体与关联

- 变体：最省事的“补环境”是直接用真实浏览器（Playwright/Selenium）执行挑战后导出 Cookie；纯 Node 沙箱适合批量与无头环境，但需要持续对抗环境检测（Canvas/WebGL/字体/时区）。
- 变体：瑞数 3/4/5/6 代与 VMP 版本的混淆方式不同，扣代码入口与 VM 结构也不同；先确认版本再选对应资料。
- 变体：若目标仅页面有挑战、API 未接入防护，可先用 [[web-generic-rs-hidden-api-direct-xhr-bypass]] 直连接口，无需补环境。
- 关联：[[code-analysis-reverse-obfuscation-js-forward-plaintext-override-burp-bridge]]（明文点转发改包）、[[code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate]]（JS 加密定位）、[[code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation]]（JS 逆向自动化）。
- 边界：cookie 有效期短、绑定 IP/UA/指纹时复现成本高；环境补得不全时生成值会被 Botgate 拒绝（400 Bad Request）；该手法只解决“通过页面挑战”，不绕过服务端登录与授权。

## 检测与防御

- 服务端：不要把 JS 挑战作为唯一防线；结合 IP/UA/指纹一致性、行为序列、频率与账号风险评分；对 cookie 绑定会话并设置短有效期。
- 监测：同一 IP 短时间内大量首次请求、Cookie 生成后立即发起高频 API 访问、无正常静态资源加载的会话，均可作为自动化特征。
- 前端：持续更新混淆与 VM 只能提高逆向成本，无法阻止有能力的攻击者；敏感操作仍需服务端二次校验。
