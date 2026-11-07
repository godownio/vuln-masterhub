---
id: code-analysis-reverse-anti-debug-js-tostring-environment-bypass
title: JS Function.prototype.toString 环境检测的干净 iframe 绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: js-tostring-environment-bypass
aliases:
- toString 环境检测绕过
- 干净 iframe 窃取 toString
- 原生函数检测绕过
- DevTools 检测 toString
- clean room iframe
tags:
- javascript
- anti-debug
- devtools
- reverse-engineering
- browser
- iframe
- tostring
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:25:21+08:00'
  notes: 已对照原文核对隐藏 about:blank iframe 取原生 Function.prototype.toString、替换后移除 iframe 的步骤与脚本一致；原文未附运行结果，PoC 未在本机执行。
---

## 一句话结论

当页面通过比较 `Function.prototype.toString()` 的返回值差异（正常带空格源码 vs 调试模式压缩/native code）判断 DevTools 是否打开时，可创建一个隐藏的 `about:blank` iframe，从干净环境取出原生 `toString` 替换当前页面的方法，再移除 iframe，恢复真实的函数源码。

## 原理

- `Function.prototype.toString` 返回函数源码字符串。某些浏览器/调试模式下，DevTools 打开后返回值会变化（如压缩空格、返回 `native code` 占位），反调试脚本据此判断是否被调试。
- 当前页面的 `Function.prototype.toString` 可能已被反调试脚本 Hook；直接在页面里读不到“原生”行为。
- 新建一个 `about:blank` 的隐藏 iframe，会得到一个全新的 JS 环境：其内置对象（`Function`、`Object` 等）及原型链未被页面脚本污染。
- 从 iframe 的 `contentWindow` 取出 `Function.prototype.toString`，用 `call/apply` 绑定到当前页面的函数上，即可绕过页面 Hook，返回浏览器原生的真实源码。
- 替换完成后移除 iframe，减少 DOM 痕迹和被检测脚本发现“补环境”行为的概率。
- 该手法不只适用于 `toString`；任何被 Hook 的内置方法（`Function.prototype.apply`、`Object.getOwnPropertyDescriptor` 等）都可以用干净 iframe 取原生实现。

## 触发条件

- 目标页面使用 `Function.prototype.toString` 差异检测 DevTools 或检测函数是否被 Hook。
- 分析者能在页面脚本之后/之前注入脚本（Console、Snippets、扩展）。
- 页面允许创建 iframe（未被 CSP `frame-src`/`child-src` 完全禁止；`about:blank` 通常允许）。
- 检测脚本没有进一步校验 `toString.toString()`、函数属性的 `name`/`length` 或属性描述符。

## 利用步骤

1. 创建隐藏 iframe，`src='about:blank'`，追加到 `document.documentElement`。
2. 取 `iframe.contentWindow.Function.prototype.toString` 作为干净的原生方法。
3. 用 `Function.prototype.toString = function(){ return cleanToString.call(this); }` 覆盖当前页面方法。
4. 移除 iframe。
5. 触发页面的环境检测，确认其读到真实源码、不再误判。
6. 若检测还校验 `toString` 自身，可进一步伪造 `toString.toString` 或使用 Proxy。

## PoC

```javascript
(function () {
  var iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  iframe.src = 'about:blank';
  document.documentElement.appendChild(iframe);

  var cleanWin = iframe.contentWindow || iframe.contentDocument.defaultView;
  if (!cleanWin) return;

  try {
    var cleanToString = cleanWin.Function.prototype.toString;

    Function.prototype.toString = function () {
      try {
        return cleanToString.call(this);
      } catch (e) {
        return 'function () { /* toString restored */ }';
      }
    };

    console.log('[anti-tostring] restored Function.prototype.toString');
  } catch (e) {
    console.warn('[anti-tostring] failed:', e);
  }

  document.documentElement.removeChild(iframe);
})();
```

```javascript
// 验证：替换后打印函数源码
function demo(a, b) { return a + b; }
console.log(demo.toString()); // 应返回原始源码，而非页面 Hook 的结果
```

## 变体与关联

- 变体：对 `Object.prototype.toString`、`Function.prototype.apply/call`、`Object.getOwnPropertyDescriptor` 等被 Hook 的内置方法，用同样的干净 iframe 取原生实现。
- 变体：CSP 禁止 iframe 时，可用 `Worker`/`MessageChannel` 或新开的 `about:blank` 窗口获取干净环境；也可用浏览器扩展在隔离世界执行。
- 变体：检测脚本校验 `toString.toString()` 时，需要同时伪造该方法的字符串表示，或使用 Proxy 统一处理。
- 关联：[[code-analysis-reverse-anti-debug-js-window-size-detection-bypass]]（另一类环境检测绕过）；[[code-analysis-reverse-anti-debug-js-dynamic-debugger-hook]]（Hook 动态 debugger）。
- 边界：`about:blank` iframe 在严格 CSP 下可能被阻止；页面若在 Worker/iframe 内做检测，需分别处理；替换可能被 `Object.freeze(Function.prototype)` 或属性描述符校验阻断。

## 检测与防御

- 检测/分析侧：在 Console 中比较 `Function.prototype.toString.toString()` 与原生值；检查页面是否创建了隐藏 iframe。
- 防御侧：`toString` 差异检测只是提高逆向成本，不是安全控制；不要把授权/秘密逻辑放在前端。
- 加固：若使用该检测，可组合完整性校验与多种信号，但应接受可被干净环境绕过；避免影响正常用户与框架。
