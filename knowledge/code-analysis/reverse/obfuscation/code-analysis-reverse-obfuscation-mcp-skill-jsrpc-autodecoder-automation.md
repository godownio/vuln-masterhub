---
id: code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation
title: MCP + Skill 模板驱动 JS 逆向自动化：AI 定位加密入口并生成 JSRPC/Flask/autoDecoder 工件
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: mcp-skill-jsrpc-autodecoder-automation
aliases:
- MCP JS 逆向自动化
- Skill 模板 JS 逆向
- chrome-devtools-mcp 实战
- JSRPC 自动生成
- Flask autoDecoder 代理
- Codex JS 逆向
- 前端加密参数自动化
tags:
- javascript
- reverse
- frontend-encryption
- mcp
- chrome-devtools
- skill
- jsrpc
- autodecoder
- burp
- ai-assisted
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:21+08:00'
  notes: 已对照 content.md 与 21 张图核对：codex mcp add/config.toml、/mcp 显示 chrome-devtools enabled、9222 远程调试、Skill 三模板、MD5 登录案例、JSRPC 12080 register/rpc连接成功、Flask /encode 回填 96e792...、autoDecoder 配置均一致。原文 MCP 连接真实浏览器失败后回退 requests，AI 流程未全程由 MCP 完成；目标域名已用占位符。未在本机执行 PoC。frontmatter 无 sources/source_url。
---

## 一句话结论

把 Codex 一类的 AI 客户端接到 `chrome-devtools-mcp`，再用三份 Skill 模板（主流程、JSRPC 注入、Flask 代理）约束输出，可以让 AI 自动完成“定位前端加密/签名字段 → 生成 JSRPC 注入代码 → 生成 Flask `/encode` 代理 → 给出 Burp autoDecoder 配置”的整条链路；原文用一个 MD5 密码登录页验证了 AI 生成的四个工件可以端到端跑通。

## 原理

- **传统 JS 逆向的四类手段**：
  1. 直接改变量：在断点/控制台把明文赋给加密前的变量；
  2. JS-Forward：在明文点插入脚本，经 AJAX 把值发给 Burp，改完再写回；
  3. JSRPC：在页面注入客户端，通过 WebSocket 暴露页面里的 JS 函数，本地 Python/Flask 远程调用；
  4. 原生还原：反混淆、补环境、本地重跑 JS。
  原文选 JSRPC 作底座，因为它直接复用浏览器里的真实函数，既不用人工还原混淆逻辑，也不受纯算法重写的环境差异影响。
- **MCP 提供浏览器能力**：`chrome-devtools-mcp` 通过 Chrome DevTools Protocol 把 `click`、`evaluate_script`、`get_network_request`、`list_network_requests`、`new_page` 等封装成 MCP 工具；AI 客户端（原文 Codex）配置后即可在真实登录态页面里执行 JS、看网络请求、读控制台。
- **Skill 约束 AI 输出**：Skill 是带 `name`/`description` 与工作流的 Markdown（主技能 + 按需加载的补充模板）。原文把流程拆成：
  - `js-reverse-automation`：编排“连接浏览器 → 定位入口 → 生成 JSRPC → 生成 Flask → 输出 autoDecoder 配置”；
  - `jsrpc-injection-template`：规定 `actionName`、`entry`（global/object/resolver）、`bindThis`、`async`、输入输出规范化与错误兜底；
  - `flask-jsrpc-proxy-template`：规定 `/encode` 接收 `dataBody`/`dataHeaders`、解析 JSON/表单、调 JSRPC、回填签名字段并修正 `Content-Length`。
  这样 AI 不是“自由发挥”，而是按固定接口生成可拼接的工件。
- **端到端数据流**：Burp（autoDecoder）把请求体交给 Flask `/encode` → Flask 调 JSRPC `/go?group=&action=&param=` → 页面中的注入代码调用原生加密函数 → 返回密文/签名 → Flask 回填 → Burp 发出合法请求。浏览器始终持有真实运行环境，因此混淆/动态密钥/`this` 绑定等难题被绕过。
- **为什么 MD5 案例可行**：登录页在提交前执行 `password: $.md5($.trim($password.val()))`，MD5 实现来自 `jquery.md5.js`；JSRPC 只需注册一个 resolver，优先取 `$.md5`/`jQuery.md5`，把明文密码传进去即可得到与浏览器一致的 32 位 hex。注意这只是客户端哈希，不构成机密性——MD5 本身可被彩虹表/暴力破解，前端加密不能替代 TLS 与服务端校验。
- **AI 的不确定性**：原文 MCP 连接真实浏览器时遇到“已有 profile 占用”而失败，AI 回退到 `requests` 直接抓页面与 JS 定位入口；这说明流水线需要 fallback，且 AI 生成结果必须用已知明文/密文对照验证。

## 触发条件

- 授权测试目标的前端 JS 对参数做加密/签名（MD5、AES、RSA 等），且能在浏览器中正常触发。
- 本机可运行 Chrome（远程调试端口，如 9222）、Node.js/npm、支持 MCP 的 AI 客户端（Codex/Trae 等）。
- 目标页面允许注入 JSRPC 客户端脚本（控制台/插件），且浏览器与本地 JSRPC（默认 12080）/Flask（如 8888）网络互通。
- 已有 Burp + autoDecoder 插件；测试者能修改请求参数并观察响应。
- 接受 AI 生成代码需要人工核对，不能直接信任。

## 利用步骤

1. 配置 MCP：`codex mcp add chrome-devtools -- npx -y chrome-devtools-mcp@latest`，或在 `~/.codex/config.toml` 写 `[mcp_servers.chrome-devtools]`；用 `/mcp` 确认 `chrome-devtools` 为 enabled。
2. 启动带远程调试的 Chrome：`chrome --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0`，登录目标站点并保持会话。
3. 准备 Skill：主技能 `skill.md` + `JSRPC.md` + `flask.md` + `burp-autodecoder.md`，写清输入（URL、加密参数名、fetch 示例）、输出（4 个工件）和验收标准。
4. 向 AI 发送“按 skill.md 流程执行”，按提示填入 URL、参数名、环境限制与 fetch 示例。
5. AI 通过 MCP 打开页面、抓网络请求、在 JS 中定位加密入口；若 MCP 失败，让它回退到抓取 HTML/JS 静态分析。确认入口类型（全局函数/对象方法/resolver）与算法。
6. 注入 JSRPC 的 `JsEnv_Dev.js`，再注入 AI 生成的 `jsrpc_*.js`；在控制台确认 `register func_name` 与 `rpc连接成功`。
7. 访问 `http://127.0.0.1:12080/go?group=<g>&action=<a>&param=<plain>` 验证返回与浏览器一致。
8. 运行 AI 生成的 Flask `/encode`，用 `curl` 发 `dataBody`（JSON 或 form）验证密文/签名字段被正确回填。
9. 在 Burp autoDecoder 中把加密接口指向 `http://127.0.0.1:8888/encode`，用原始请求测试“解密/加密”双向转换。
10. 对修改后的请求做重放/爆破/越权测试，确认每次都由页面原生函数生成合法参数。

## PoC

MCP 配置：

```bash
codex mcp add chrome-devtools -- npx -y chrome-devtools-mcp@latest
```

```toml
[mcp_servers.chrome-devtools]
command = "npx"
args = ["-y", "chrome-devtools-mcp@latest"]
```

JSRPC 注入核心（resolver 方式，按目标函数调整）：

```javascript
var client = new Hlclient("ws://127.0.0.1:12080/ws?group=demo&name=burp");
var cfg = {
  actionName: "generate_password_md5",
  entry: { type: "resolver", resolver: function () {
    if (window.$ && typeof $.md5 === "function") return $.md5;
    if (window.jQuery && typeof jQuery.md5 === "function") return jQuery.md5;
    return null;
  }},
  bindThis: null, async: false,
  normalizeInput: function (p) { return String(p == null ? "" : p); },
  normalizeOutput: function (r) { return r; },
  onError: function (e) { return "ERROR_" + Date.now(); }
};
client.regAction(cfg.actionName, function (resolve, param) {
  try {
    var fn = cfg.entry.resolver();
    if (typeof fn !== "function") throw new Error("function not found");
    resolve(cfg.normalizeOutput(fn.call(cfg.bindThis, cfg.normalizeInput(param))));
  } catch (e) { resolve(cfg.onError(e)); }
});
```

Flask `/encode` 核心（按 autoDecoder 约定）：

```python
from flask import Flask, request
import requests, json
from urllib.parse import parse_qs, urlencode

app = Flask(__name__)
JSRPC = "http://127.0.0.1:12080/go"

def jsrpc(action, value):
    r = requests.get(JSRPC, params={"group": "demo", "action": action, "param": value}, timeout=5)
    return r.json().get("data", "")

@app.post("/encode")
def encode():
    body = request.form.get("dataBody", "")
    headers = request.form.get("dataHeaders", "")
    try:
        data = json.loads(body)
        data["password"] = jsrpc("generate_password_md5", str(data.get("password", "")))
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    except json.JSONDecodeError:
        form = parse_qs(body, keep_blank_values=True)
        form["password"] = [jsrpc("generate_password_md5", form.get("password", [""])[0])]
        body = urlencode(form, doseq=True)
    return headers + "\r\n\r\n\r\n\r\n" + body
```

自动生成的工件通常包括 `jsrpc_*.js`、`flask_proxy_*.py`、`burp_autodecoder_config.md`、`*_encrypt_logic.js`。本卡 PoC 按原文流程整理，未在本机执行；AI 生成代码需按目标函数签名、`this` 绑定、异步/Promise 与字段名调整。

## 变体与关联

- 变体：入口类型改为全局函数（`window.sign`）或对象方法（`crypto.sign`，需 `bindThis`）；异步函数用 `async: true` 并处理 Promise。
- 变体：Burp 之外也可接 mitmproxy/Yakit 的自动加解密；Flask 可换成任意 HTTP 服务，只要实现 autoDecoder 的 `dataBody`/`dataHeaders` 协议。
- 变体：AI 客户端可用 Trae/Cursor/Claude 等支持 MCP 的工具；MCP server 也可换成 Playwright MCP，能力集不同。
- 关联：[[web-generic-auth-js-signature-jsrpc-autodecoder]]（JSRPC+autoDecoder 的签名逆向细节）、[[code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse]]（AI+MCP 定位加密并生成脚本）、[[code-analysis-reverse-frontend-request-response-encryption-automation]]（请求/响应双层加密与 PyExecJS 自动化）。
- 边界：目标有严格 CSP/反调试/环境检测、JSRPC 无法注入、加密依赖 WebAssembly/原生插件、MCP 无法连接浏览器且静态抓取也失败、AI 生成的入口定位错误时，需要人工介入或换方案。

## 检测与防御

- 定位：这是测试/逆向工作流，不是单一漏洞；前端加密/签名只是提高分析成本，不能作为安全边界。
- 防御：不要把密钥、签名算法当作机密；服务端必须做真正的认证、授权、限流与参数校验；使用 TLS 防止中间人；对登录/敏感接口做风控、设备指纹与异常请求检测。
- 检测：页面出现非官方 WebSocket（`/ws?group=...&name=...`）连接、控制台注入的 `Hlclient`/`regAction`、本地 12080/8888 端口的异常流量；Burp 请求的加密参数与浏览器正常值不一致或高频重放。
- 响应：发现前端加密被绕过并不代表服务端被攻破，重点检查服务端是否只依赖前端校验；对敏感操作增加二次校验与服务端签名。
