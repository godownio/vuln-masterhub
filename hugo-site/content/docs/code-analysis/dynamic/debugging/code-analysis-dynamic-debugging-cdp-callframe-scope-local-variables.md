---
id: code-analysis-dynamic-debugging-cdp-callframe-scope-local-variables
title: CDP 读取 JS 调用栈局部变量：Debugger.paused 的 callFrames/scopeChain + Runtime.getProperties(objectId)
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: cdp-callframe-scope-local-variables
tags:
- chrome
- cdp
- devtools
- javascript
- debugging
- callstack
- scope
- pychrome
- automation
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:18:10+08:00'
  notes: 已对照原文与图02/19-30核对：Debugger.paused 返回 callFrames，帧内 scopeChain type=local 的 object.objectId（-5775538314643851262.2.1）经 Runtime.getProperties(ownProperties=false/accessorPropertiesOnly=false/nonIndexedPropertiesOnly=false/generatePreview=true) 得到 e/t/o/i/s 等局部变量，与 DevTools Scope 面板（图23）一致；图25 确认 callFrameId/functionName/scopeChain 结构，图26/27 为 Scope/CallFrame 文档；setAsyncCallStackDepth(maxDepth) 后 asyncStackTrace 出现（图28/30），此前无（图29）；getStackTrace 需 stackTraceId 而 paused 不含，与原文一致。原文未给组件版本，affected_versions 留空正确；PoC 未实测。与 websocket 抓包卡为方法↔用例互补，非重复；与 JS 动态 debugger Hook 反调试卡目的不同。dup-scan.json 早于建卡且无本篇 pair。
url: /docs/code-analysis/dynamic/debugging/code-analysis-dynamic-debugging-cdp-callframe-scope-local-variables/
draft: false
kb_aliases:
- CDP 获取调用栈变量
- Debugger.paused callFrames
- scopeChain local
- Runtime.getProperties
- pychrome 调试
- asyncStackTrace
- setAsyncCallStackDepth
---

## 一句话结论

不要用 `Debugger.getStackTrace`（它需要 `Debugger.paused` 里通常不存在的 `stackTraceId`）：在 `Debugger.paused` 的返回中遍历 `callFrames`（栈顶→栈底），对每个 frame 的 `scopeChain` 中 `type == "local"` 的 scope 取 `object.objectId`，再调用 `Runtime.getProperties(objectId, ownProperties=false, generatePreview=true, ...)`，即可拿到该层调用栈的局部变量；再用 `Debugger.enable(maxScriptsCacheSize)` 与 `Debugger.setAsyncCallStackDepth(maxDepth)` 补上异步栈。

## 原理

- 断点/异常/XHR 断点触发时，浏览器发送 `Debugger.paused` 事件，`params.callFrames` 是调用栈帧数组（按栈顶到栈底排序）。每个 `CallFrame` 含 `callFrameId`（只在暂停期间有效）、`functionName`、`location`、`scopeChain`、`this`、`returnValue` 等。
- `scopeChain` 是 `Scope` 数组，`Scope.type` 可为 `global`/`local`/`with`/`closure`/`catch`/`block`/`script`/`eval`/`module` 等；除 global 外，`object` 是一个临时的 `Runtime.RemoteObject`，其属性枚举的是该作用域里的变量；要读变量值就对它的 `objectId` 调 `Runtime.getProperties`。
- `Runtime.getProperties` 返回 `PropertyDescriptor` 数组（`name`/`value`/`writable`/`configurable`/`enumerable`/`isOwn`）；`value` 若还是对象会带新的 `objectId`，可继续递归展开。参数 `ownProperties=false` 允许返回原型链属性，`generatePreview=true` 让返回带预览。
- 异步栈：`Debugger.paused` 的 `asyncStackTrace` 只有在开启 `Debugger.setAsyncCallStackDepth(maxDepth=N)` 后才出现；`Debugger.enable(maxScriptsCacheSize=...)` 提高脚本缓存，保证 DevTools/客户端能按 scriptId 解析源码位置。
- 常见坑：`Debugger.getStackTrace` 是 experimental 且需要 `Runtime.StackTraceId`，而 `paused` 事件默认只给 `callFrames` 与可选的 `asyncStackTrace`，直接查文档容易走错路；正确做法是先 enable 调试域、设置断点，再从 paused 事件自顶向下取每帧的 local scope。
- 该能力是 DevTools Scope 面板的底层实现：Scope 面板展示的 Local/Closure/Global 变量与 `Runtime.getProperties` 的返回一一对应。

## 触发条件

- Chrome/Chromium 以 `--remote-debugging-port` 启动，客户端（pychrome/CDP 库/自写 WebSocket）能连接。
- 已在目标页面设置断点（XHR/fetch、DOM、事件监听或 `debugger` 语句）并触发暂停。
- 调试目标未被 DevTools 独占或支持多客户端（CDP 允许多会话）。

## 利用步骤

1. 连接远程调试并新建标签页；`Page.enable()`、`Debugger.enable()`、`Runtime.enable()`。
2. 配置：`Debugger.enable(maxScriptsCacheSize=10000000)`、`Debugger.setAsyncCallStackDepth(maxDepth=50)`。
3. 设置断点：例如 `DOMDebugger.setXHRBreakpoint(url="")` 拦截任意 XHR/fetch，或 `Debugger.setBreakpointByUrl`。
4. 导航到目标页面；在 `Debugger.paused` 回调中遍历 `callFrames`：
   - 对每个 frame 取 `scopeChain`，筛 `type == "local"`；
   - 取 `scope.object.objectId`，调用 `Runtime.getProperties(objectId=..., ownProperties=False, accessorPropertiesOnly=False, generatePreview=True, nonIndexedPropertiesOnly=False)`；
   - 把结果按 `callFrameId` 归档保存。
5. `Debugger.resume()` 继续执行；需要异步栈时确认 `asyncStackTrace` 已在事件中出现。
6. 对复杂对象递归展开 `value.objectId`，或用 `Runtime.callFunctionOn` 求值。

## PoC

```python
import pychrome

browser = pychrome.Browser(url="http://127.0.0.1:9222")
tab = browser.new_tab(); tab.start()
tab.Page.enable(); tab.Debugger.enable(); tab.Runtime.enable()
tab.Debugger.enable(maxScriptsCacheSize=10000000)
tab.Debugger.setAsyncCallStackDepth(maxDepth=50)

def get_props(object_id):
    return tab.Runtime.getProperties(
        objectId=object_id, ownProperties=False, accessorPropertiesOnly=False,
        generatePreview=True, nonIndexedPropertiesOnly=False)["result"]

def on_paused(**kw):
    result = {}
    for frame in kw["callFrames"]:                 # 栈顶 -> 栈底
        cid = frame["callFrameId"]
        result[cid] = {}
        for scope in frame["scopeChain"]:
            if scope["type"] == "local":           # 只取局部变量
                oid = scope["object"]["objectId"]
                result[cid][oid] = get_props(oid)
    tab.Debugger.resume()

tab.Debugger.paused = on_paused
tab.DOMDebugger.setXHRBreakpoint(url="")
tab.Page.navigate(url="https://example.com/")
```

## 变体与关联

- 关联 [[code-analysis-dynamic-debugging-devtools-websocket-cdp-traffic-reverse]]：本卡的调用序列正是通过抓包 DevTools 流量反推出来的。
- 关联 [[code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse]]：用 DevTools/MCP 做 JS 逆向；本卡提供直接取栈上变量的底层配方。
- 变体：遍历 `closure`/`global`/`block` 等所有 scope 类型；用 `Runtime.callFunctionOn` 在暂停帧上执行表达式；用 `Debugger.evaluateOnCallFrame` 读取/修改变量；对 Promise 异步链用 `asyncStackTrace` 还原调用来源。
- 边界：`callFrameId`/`objectId` 只在暂停期间或对象存活期内有效，resume 后失效；某些作用域（eval/with）变量枚举可能不完整；DevTools 已连接时多客户端会有会话差异。

## 检测与防御

- 远程调试端口等于可对页面执行任意 JS、读取变量与网络数据的控制面；禁止在生产环境开放，尤其是 0.0.0.0。
- 检测：`--remote-debugging-port` 参数、9222/9229 监听、非 DevTools 进程的 WebSocket 连接与高频 `Runtime.getProperties` 调用。
- 防御：仅受控环境/临时 profile 使用；对含敏感凭据的页面禁用远程调试；用应用层 CSP/隔离降低被调试页面中的敏感数据暴露。
