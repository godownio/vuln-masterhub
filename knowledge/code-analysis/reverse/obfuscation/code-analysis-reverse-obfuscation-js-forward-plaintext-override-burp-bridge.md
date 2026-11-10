---
id: code-analysis-reverse-obfuscation-js-forward-plaintext-override-burp-bridge
title: JS-Forward 明文点插桩改包：DevTools 本地替换注入同步 XHR，把加密前变量经本地桥转给 Burp 修改后回写
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: js-forward-plaintext-override-burp-bridge
aliases:
- JS-forward 改包
- JSForward 明文转发 Burp
- 本地替换注入改包
- 明文点插桩
- DevTools Overrides 改 JS
- 浏览器明文转发 burp
tags:
- js-reverse
- js-forward
- devtools-overrides
- burp
- frontend-encryption
- plaintext-point
- request-tamper
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T07:58:12+08:00'
  notes: 已对照原文与图片核对：JS-Forward输入t.data/json/REQUEST后生成同步XHR注入码，Overrides替换JS并在函数首行插入，28080转发Burp、38080回写，Burp收到明文REQUEST后修改放行，均与原文一致；Chrome CORS/Edge正常及同步XHR限制已在卡中说明
---

## 一句话结论

在明文点所在 JS 文件上用 DevTools 的本地替换（Overrides）注入一段脚本：脚本在加密/签名之前把当前明文变量通过同步 XHR 发给本地 JS-Forward 服务（28080），服务端把它转给 Burp 供人工修改，再从 38080 以响应返回，脚本把响应写回原变量；浏览器后续的签名与加密都基于 Burp 改过的明文，于是所有改包操作都能统一在 Burp 完成，且与浏览器是否走 Burp 代理无关。

## 原理

- **JS-Forward 是浏览器与 Burp 之间的双向桥**：注入代码向 `http://127.0.0.1:28080/<标识>` 发同步 POST，JS-Forward 把该请求当普通 HTTP 流量转给 Burp（默认 8080）；Burp 放行/修改后，JS-Forward 把最终请求体从 38080 作为响应返回页面。
- **同步 XHR 保证时序**：`xhr.open(..., false)` 会阻塞页面 JS 线程直到 Burp 放行，注入代码在 `xhr.send` 之后拿到的一定是修改后的内容；若用异步请求，加密函数可能先执行，改动丢失。
- **为什么能改被加密的请求**：篡改发生在明文点，之后由页面自己的加密/签名函数处理修改后的值，服务端收到的是合法密文与签名；浏览器看到的流程完全正常。
- **本地替换的机制**：线上 JS 不能直接编辑，DevTools 的 Overrides 允许选择一个本地文件夹，把修改后的 JS 版本保存在本地并在刷新时优先加载；在明文点函数第一行插入转发代码即可，无需重新部署或写代理插件。
- **优点与边界**：改动统一在 Burp，适合人工分析参数、增删字段、绕过前端校验；明文只在本地环回传输。限制是只作用于浏览器发起的请求；同步 XHR 在主线程逐步受限；原文在 Chrome 上会报 CORS 错误而 Edge 正常；本地替换需重新授权文件夹，且页面更新后可能失效。

## 触发条件

- 能在 DevTools → 源代码 → 替换中启用本地替换并授权一个本地文件夹。
- 已定位加密/签名前的明文点与变量名（如 `t.data`）及数据类型（json/string）。
- 本机运行 JS-Forward（监听 28080/38080）与 Burp（8080），浏览器可访问环回地址。

## 利用步骤

1. 确认明文变量名（如 `t.data`）与类型（json），并确保其位于加密/签名之前。
2. 启动 JS-Forward，依次输入变量名、数据类型、请求标识（如 `REQUEST`，仅用于区分请求/响应），生成注入代码；服务开始监听 28080/38080。
3. DevTools → 源代码 → 替换 → 选择放置替换项的本地空文件夹，浏览器弹出授权时选择允许，勾选「启用本地替换」。
4. 在目标 JS 文件上右键「替换内容」，把生成的注入代码粘贴到明文点函数第一行，Ctrl+S 保存。
5. 关闭调试器/F12，刷新页面，再次提交表单。
6. 在 Burp 中拦截标识为 `REQUEST` 的明文请求，修改 JSON 字段后放行；页面收到修改后的值继续执行签名与加密并发出业务请求。
7. 若需改响应，可在 JS-Forward 的响应方向用同样方式接入（反向标识），或改用解密类工具。

## PoC

注入代码由工具生成，核心逻辑等价于：

```js
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://127.0.0.1:28080/REQUEST", false); // 同步，等待 Burp 放行
xhr.send(JSON.stringify(t.data));
t.data = JSON.parse(xhr.responseText);                      // 回写 Burp 修改后的明文
```

插入位置为请求拦截器（如 `interceptors.request.use(function(t){...})`）第一行，位于 `t.data = l(n)` 与签名计算之前。Burp 中看到的是明文 JSON，修改后放行即可。原文实测成功；本卡未复跑。

## 变体与关联

- **作用域改值**：断点处直接改 Scope，单次生效、无需工具。
- **JS-RPC**：把加密/签名函数暴露给外部工具自动生成密文，适合批量化与扫描器。
- **前端加密自动化**：XHR 断点定位后扣函数到本地 Node 复现，适合长期自动化。
- **响应侧**：JS-Forward 同样支持把响应转给 Burp 修改后回写页面（如改权限字段做前端越权展示），但服务端接口仍按真实权限返回。

## 检测与防御

- 客户端插桩无法被服务端直接检测；防御核心仍是服务端授权与业务校验，不能依赖前端显示或前端校验。
- 关键操作服务端二次验证（原密码、验证码、MFA），敏感字段做服务端取值范围校验。
- 风控监测异常参数组合与高频敏感操作；前端可加完整性校验/反调试提高成本，但无法根治。
