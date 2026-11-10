---
id: code-analysis-reverse-anti-debug-proxy-js-replacement-bypass
title: 抓包代理替换 JS/HTML 绕过前端反调试：反调试代码必须经网络下发，用 Fiddler/Burp 改包去掉 disable-devtool、无限 debugger、框架内嵌检测
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: proxy-js-html-replacement-frontend-antidebug-bypass
aliases:
- 代理改包绕过反调试
- Fiddler 替换 JS 去 debugger
- Burp 改 JS 绕过 disable-devtool
- 反调试代码可被中间人替换
- 前端反调试通用绕过
tags:
- anti-debug
- js
- reverse
- proxy
- fiddler
- burp
- devtools
- obfuscation
- bypass
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:49:00+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。正文核心论点『反调试代码必须先下发到浏览器才能执行，用 Charles/Fiddler 等代理替换 JS 与 HTML 逐步绕过』与三类手段（disable-devtool 禁 DevTools、eval/Function/setInterval 无限 debugger、反调试混入 jQuery 等框架需与官方版本 diff）均与案例一/二/三一致；SRI/CSP 边界为合理补充。dedup 首候选为自身 trigram=1.000，外部最高为 DevTools 内 Never pause/条件断点卡(0.178)，绕过层次不同（网络层 vs DevTools 内），保留合理。已修正关联中失效 id code-analysis-reverse-obfuscation-frontend-request-response-encryption-automation 为 code-analysis-reverse-frontend-request-response-encryption-automation。未验证点：结论称代理替换是『唯一稳定路径』属超出正文的断言；未实际抓包替换。原文无版本信息，未 set-versions。
---

## 一句话结论

前端反调试（`disable-devtool` 这类强制关 DevTools 的库、`setInterval(debugger)` 无限断点、把检测逻辑塞进 jQuery 等框架文件里的做法）无论如何实现，代码都必须先从服务器下发到浏览器才能执行；用 Fiddler/Burp 做中间人，把响应里的 JS/HTML 备份后改掉反调试片段再回注给浏览器，就能恢复原生 DevTools 调试与后续的算法逆向——这比逐个找 DevTools 里"一律不在此处暂停"更通用，也是对付"禁止打开开发者工具"类方案的唯一稳定路径。

## 原理

- **反调试代码在到达浏览器之前不可执行**：检测 DevTools 是否打开、禁用右键/F12、循环 `debugger` 的代码本身是 HTTP 响应体里的 JS/HTML。在"服务器 → 浏览器"这一段，代理可以读、改、重放响应，而这段代码在代理处尚未运行，因此任何"运行时检测 DevTools"的逻辑都无法反制代理改写。
- **三类常见反调试都可从响应侧移除**：
  1. `disable-devtool` 一类库通过时间差、窗口内外宽高差、`console` 对象探测判断 DevTools 是否打开，命中即跳空白页或中断页面；把该库的 `<script>` 从 HTML 里删掉、或改写其检测函数直接 `return false`，页面就恢复正常。
  2. 无限 `debugger`（直接写、`eval` 拼接、`Function` 构造、重写 `constructor`/`setInterval` 注入）只要在响应里删掉 `debugger` 语句、或把 `eval`/`Function` 的字符串参数改空，断点就不再触发。
  3. 把检测代码混进 `jquery.js` 等第三方框架文件的，靠"下载框架源码 + 与官方版本 diff"识别被插入的片段，再在代理里回注干净版本。
- **为什么比 DevTools 内的绕过更强**：DevTools 内手段（Never pause here、条件断点、Local Overrides）都要求先把 DevTools 打开；而"禁止打开 DevTools"类方案的目标正是让这一步不成立。代理替换不依赖 DevTools 已打开（可先开 DevTools 再导航，但更彻底的是先把反调试改掉）。
- **为什么必须逐步替换、保留备份**：前端脚本之间有依赖，一次性整体替换容易让页面跑不起来，反而无法判断是"绕过成功"还是"改坏了"；逐段改、每改一段刷新验证，才能把反调试逻辑与业务逻辑隔离开。

## 触发条件

- 目标页面把反调试逻辑放在可从网络层修改的 JS/HTML 里（几乎总是如此），且未使用 Subresource Integrity（SRI）或签名校验响应体。
- 攻击者能把浏览器流量导到可控代理（系统代理、插件代理、移动端代理），并可修改响应。
- 需要调试的加密/业务逻辑与反调试代码在同一页面或可独立加载的 JS 中。
- 页面没有额外的"关键逻辑放在 WASM/服务端"设计（否则改 JS 只能恢复调试，改动不了算法）。

## 利用步骤

1. 打开代理（Fiddler/Burp）并让浏览器走代理，先完整浏览一遍目标页面，把加载的所有 JS/HTML 响应保存到本地（这一步同时备份了原始代码）。
2. 在保存的 JS 里搜索反调试特征：`debugger`、`disable-devtool`、`devtools`、`setInterval`、`Function(`、`eval(`、`constructor`、`outerWidth`/`innerWidth`、`console` 相关探测。
3. 对每一处判断类型：属于反调试的（循环 `debugger`、DevTools 检测、事件拦截）删掉或改成 `return false`；属于业务逻辑的保留。框架文件用"与官方同版本 diff"定位被插入的片段。
4. 在代理里为对应 URL 建立 AutoResponder/替换规则，把改后的文件回注；先只改一个文件，刷新页面确认功能正常、断点可控。
5. 逐步替换其余反调试文件，直到页面不再跳空白页、不再无限断住，DevTools 的 Sources/Network 恢复正常。
6. 恢复调试后按常规路径定位加密：Sources 全局搜索参数名 → 在 `XMLHttpRequest.send` 下断点 → 逐个放行非目标请求 → 命中目标请求后看调用栈（动态栈回溯），从 `send` 往上逐层看变量，找到参数被赋值/加密的那一层函数。
7. 把加密函数与它依赖的常量扣出来，在本地 Node/浏览器控制台验证输入输出，再决定用 Python 复刻还是直接调用 JS。

## PoC

代理侧的替换目标示意（以 Fiddler AutoResponder 为例，具体脚本按目标改动）：

```text
原始（目标响应）:
<script src="/static/disable-devtool.min.js"></script>
<script>
  setInterval(function(){ debugger; }, 500);
</script>

替换后（回注给浏览器）:
<!-- 移除 disable-devtool.min.js，删除循环 debugger -->
<script>/* anti-debug removed for analysis */</script>
```

框架文件被插入反调试时先做 diff：

```bash
# 另取官方同版本 jquery（本地包管理器/镜像均可），与线上文件比对，定位被插入的片段
diff <(fold -w 200 jquery.official.js) <(fold -w 200 jquery.online.js) | head -50
```

## 变体与关联

- **改包层次变体**：Charles Map Local、Chrome Local Overrides、mitmproxy 的 `response` 脚本、企业代理的响应重写规则；本质相同，选能改响应体的即可。
- **改法变体**：删脚本标签、注释 `debugger`、把 `eval(...)`/`new Function(...)` 的参数改成空串、把检测函数体改成 `return false`、把 `setInterval` 的回调替换成空函数。
- **反调试形态变体**：DevTools 时间差/宽高差检测、`console` 对象探测、`toString` 环境检测、`window.outerWidth=0` 一类；与既有卡 `code-analysis-reverse-anti-debug-js-dynamic-debugger-hook`、`js-tostring-environment-bypass`、`js-window-size-detection-bypass` 描述的手段互补（可先按本卡改包，再配合这些手段做二次绕过）。
- **关联**：`code-analysis-reverse-anti-debug-js-infinite-debugger-bypass`（DevTools 内 Never pause/Local Overrides 的轻量绕过，适用于 DevTools 还能打开的场景）、`code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass`（只拦 F12/右键时改快捷键）、`code-analysis-reverse-frontend-request-response-encryption-automation`（恢复调试后定位加密的下一步）。
- **边界**：站点启用 SRI（`integrity` 属性）或对响应做签名校验时改包会失败；关键脚本走 `document.write`/动态拼接且校验哈希；页面禁止一切脚本调试（如检测到断点即清空内存/跳转）时需配合条件断点或替换更强；改包只影响本地浏览器，不改变服务端算法。

## 检测与防御

- **检测（站方视角）**：前端资源被改写无法从服务端直接感知，只能通过"行为异常"侧面判断——同一会话内 DevTools 打开却无对应断点命中、页面加载的 JS 与本机构建产物哈希不符（可用 SRI + 上报校验失败的 `onerror`）、反调试埋点未按预期触发上报。
- **防御**：关键 JS 使用 SRI（`<script integrity="sha384-...">`）并在 CSP 中限定来源，代理改包会因哈希不匹配被浏览器拒绝执行；把真正敏感的算法与密钥放到服务端（前端加密只能提高成本，不能构成安全边界）；对响应做签名并校验；反调试只作为提高成本的辅助手段，不承担安全职责。
