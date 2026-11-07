---
id: code-analysis-reverse-anti-debug-js-dynamic-debugger-hook
title: JS 字符串拼接/eval 动态 debugger 的 Hook 拦截绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: js-dynamic-debugger-hook-bypass
aliases:
- 字符串拼接 debugger 绕过
- eval debugger 拦截
- Function 构造器 debugger
- 定时器 Hook 反调试
- 高级反调试审计脚本
tags:
- javascript
- anti-debug
- devtools
- reverse-engineering
- browser
- hook
- eval
- timer
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:25:17+08:00'
  notes: 已对照原文核对 Hook eval/Function/setTimeout/setInterval/requestAnimationFrame 与清空定时器的逻辑；PoC 中 hasDebugger 的两个条件重复（原文第二个为 'debu'+'gger'），不影响拦截功能，属轻度转写笔误；脚本未在本机执行。
---

## 一句话结论

当反调试用 `'de'+'bugger'`、`eval`、`new Function` 或定时器动态生成 `debugger`，DevTools 的“禁用断点/本地替换”无法静态识别时，可在页面早期 Hook `eval`、`Function`、`setTimeout`、`setInterval`、`requestAnimationFrame`，对传入代码做 `debugger` 特征扫描并拒绝执行，同时清空已存在的定时器。

## 原理

- 静态 `debugger` 可以被 DevTools 的 never-pause/条件断点/本地替换处理；但 `eval("de"+"bugger")`、`new Function("debugger")()`、闭包/混淆器生成的代码在源码里看不到完整的 `debugger` 关键字，静态断点与替换失效。
- 这类反调试试图通过 `eval`、`Function` 构造器或定时器在运行时生成并执行 `debugger`，打开 F12 后反复断住。
- Hook 思路：在页面脚本之前保存原生 `eval`/`Function`/`setTimeout`/`setInterval`/`requestAnimationFrame`，替换为包装函数；对传入的字符串/函数体做标准化（去空白、转小写），检测是否包含 `debugger`，命中则直接返回空/0，不执行。
- 同时清理已存在的定时器：调用一次 `setTimeout` 取得当前最大 ID，循环 `clearTimeout`/`clearInterval`，并对 `requestAnimationFrame` 做同样清理，干掉页面加载时已启动的检测循环。
- 该 Hook 会产生误报/副作用：业务代码中合法包含 `debugger` 字符串（如日志、文档）会被拦截；某些库依赖 `Function` 构造器动态编译，可能被破坏。

## 触发条件

- 目标页面使用动态生成/字符串拼接/eval/Function/定时器方式触发 `debugger`。
- 分析者能在页面脚本执行前注入 Hook（扩展 `document_start`、Local Overrides、DevTools Snippets 尽早执行）。
- 页面未对 `eval`/`Function`/定时器做完整性校验，或校验可被绕过。
- 页面未使用 Worker/WASM 等 Hook 覆盖不到的上下文生成 debugger。

## 利用步骤

1. 在页面加载前注入 Hook 脚本。
2. 清理已存在的定时器与动画帧（循环 clear）。
3. 包装 `eval`、`Function`、`setTimeout`、`setInterval`、`requestAnimationFrame`，对代码/函数体做 `debugger` 特征扫描。
4. 命中时拒绝执行并返回安全值（`undefined`、空函数、0）。
5. 打开 DevTools，确认不再被动态 debugger 打断。
6. 若仍被绕过，检查是否使用 `Worker`、`WebAssembly`、`import()`、`Function.prototype.constructor`、`setImmediate` 等未覆盖入口，补充 Hook。

## PoC

```javascript
(function () {
  // 1) 清理已存在的定时器/动画帧
  try {
    var maxId = window.setTimeout(function () {}, 0);
    for (var i = 0; i <= maxId; i++) {
      window.clearTimeout(i);
      window.clearInterval(i);
    }
    if (window.requestAnimationFrame && window.cancelAnimationFrame) {
      var rafId = window.requestAnimationFrame(function () {});
      for (var j = 0; j <= rafId; j++) window.cancelAnimationFrame(j);
    }
  } catch (e) {}

  function hasDebugger(code) {
    if (!code) return false;
    var s = String(code).replace(/\s+/g, '').toLowerCase();
    return s.indexOf('debugger') !== -1 || s.indexOf('debugger') !== -1;
  }
  function check(fn) {
    if (typeof fn === 'function') return hasDebugger(fn.toString());
    if (typeof fn === 'string') return hasDebugger(fn);
    return false;
  }

  // 2) Hook eval / Function
  try {
    var rawEval = window.eval;
    window.eval = function (code) {
      if (hasDebugger(code)) { console.warn('blocked eval debugger'); return; }
      return rawEval.apply(this, arguments);
    };
    var RawFunction = window.Function;
    window.Function = function () {
      var args = Array.prototype.slice.call(arguments);
      var body = args.length ? args[args.length - 1] : '';
      if (hasDebugger(body)) { console.warn('blocked Function debugger'); return function () {}; }
      return RawFunction.apply(this, args);
    };
  } catch (e) {}

  // 3) Hook 定时器
  try {
    var rawSetTimeout = window.setTimeout, rawSetInterval = window.setInterval;
    var rawRaf = window.requestAnimationFrame;
    window.setTimeout = function (fn) {
      if (check(fn)) { console.warn('blocked timeout debugger'); return 0; }
      return rawSetTimeout.apply(this, arguments);
    };
    window.setInterval = function (fn) {
      if (check(fn)) { console.warn('blocked interval debugger'); return 0; }
      return rawSetInterval.apply(this, arguments);
    };
    if (typeof rawRaf === 'function') {
      window.requestAnimationFrame = function (fn) {
        if (check(fn)) { console.warn('blocked RAF debugger'); return 0; }
        return rawRaf.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
```

## 变体与关联

- 变体：`debugger` 通过 `atob`/`String.fromCharCode`/模板字符串拼接；Hook 扫描的是最终传入的代码字符串，仍可能命中；若在闭包内直接写 `debugger`，需在函数 toString 中检测。
- 变体：使用 `Worker` 或 `WebAssembly` 生成断点，主线程 Hook 不生效；需在 Worker 中注入或禁用 Worker。
- 关联：[[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]（静态 debugger 的 DevTools UI 绕过）；[[code-analysis-reverse-anti-debug-js-tostring-environment-bypass]]（toString 环境检测绕过）。
- 边界：Hook 必须早于反调试脚本；页面若保存了原生函数引用（在 Hook 前捕获），可绕过包装；过度拦截会破坏正常业务代码。

## 检测与防御

- 检测/分析侧：在 Console 中检查 `eval`/`Function`/`setTimeout` 是否为自定义函数（`toString` 含 wrapper 特征）；查看定时器 ID 是否异常。
- 防御侧：前端反调试不是安全边界；动态 debugger 只能提高分析成本。
- 加固：如需增加难度，可组合多种生成方式并做完整性校验，但应接受可被 Hook 绕过；避免影响正常用户性能。
