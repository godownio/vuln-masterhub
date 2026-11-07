---
id: code-analysis-reverse-anti-debug-js-window-size-detection-bypass
title: JS 窗口尺寸检测反调试的 Hook 绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: js-window-size-detection-bypass
aliases:
- 窗口尺寸检测绕过
- innerWidth 锁定
- resize 监听拦截
- DevTools 尺寸检测
- visualViewport 伪造
tags:
- javascript
- anti-debug
- devtools
- reverse-engineering
- browser
- hook
- defineproperty
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:25:15+08:00'
  notes: 已对照原文与图 09 核对：采样尺寸、defineProperty 劫持 getter、visualViewport、拦截 resize 与 onresize 的 Hook 脚本与原文一致；Media Queries 检测无法覆盖的边界已写明；脚本未在本机执行。
---

## 一句话结论

页面通过定时比较 `innerWidth`/`outerWidth` 等尺寸变化来探测 DevTools 时，可在脚本加载初期采样尺寸，用 `Object.defineProperty` 劫持这些属性的 getter 返回固定值，并拦截 `resize` 监听与 `onresize`，让检测永远看到“未打开控制台”的尺寸。

## 原理

- DevTools 以 docked 模式打开时会压缩页面视口，`window.innerWidth`/`innerHeight` 发生变化；反调试脚本记录初始尺寸，定时比较，异常则刷新、清空页面或卡死。
- 在页面脚本运行前（或尽早）采样 `innerWidth`、`innerHeight`、`outerWidth`、`outerHeight`，作为“正常状态”的标准答案。
- `Object.defineProperty(window, 'innerWidth', { get: () => fixed })` 覆盖原生属性；后续任何读取都返回固定值，拖拽窗口或打开 DevTools 都不会改变。
- 对 `window.visualViewport` 的 `width`/`height` 同样处理，防止高级检测交叉校验。
- 重写 `window.addEventListener`，当 `type === 'resize'` 时直接返回、不注册；并把 `window.onresize = null`，覆盖 DOM0 级监听。
- 该 Hook 只能欺骗基于 JS 属性读取的检测；如果检测使用 CSS Media Queries（如 `@media (max-width: 500px)` 改变隐藏元素样式，再用 `getComputedStyle` 判断），Hook 拦截不到。

## 触发条件

- 目标页面使用窗口尺寸变化作为 DevTools 检测信号。
- 分析者能在页面脚本之前注入 Hook（DevTools Snippets、扩展、Local Overrides、Console 尽早执行）。
- 页面未使用 Media Queries 等 Hook 覆盖不到的检测，或未对 `Object.defineProperty` 做完整性校验。
- 浏览器允许重新定义 `window` 尺寸属性（多数环境允许，`configurable: true`）。

## 利用步骤

1. 在页面加载前准备 Hook 脚本（扩展 `document_start`、Local Overrides 或 DevTools Snippets）。
2. 采样当前 `innerWidth/innerHeight/outerWidth/outerHeight` 及 `visualViewport` 尺寸。
3. 用 `Object.defineProperty` 把上述属性替换为固定 getter，setter 静默失败。
4. 重写 `window.addEventListener`，拦截 `resize`；设置 `window.onresize = null`。
5. 打开 DevTools，观察页面不再刷新/卡死；继续调试。
6. 若仍被检测，检查是否使用 Media Queries、`screen`、`devicePixelRatio` 等其他信号，按同样思路补充 Hook。

## PoC

```javascript
(function () {
  var w = window.innerWidth, h = window.innerHeight;
  var ow = window.outerWidth, oh = window.outerHeight;

  function lock(obj, prop, value) {
    if (!obj) return;
    try {
      Object.defineProperty(obj, prop, {
        configurable: true,
        enumerable: true,
        get: function () { return value; },
        set: function () {}
      });
    } catch (e) {}
  }

  lock(window, 'innerWidth', w);
  lock(window, 'innerHeight', h);
  lock(window, 'outerWidth', ow);
  lock(window, 'outerHeight', oh);

  if (window.visualViewport) {
    lock(window.visualViewport, 'width', window.visualViewport.width);
    lock(window.visualViewport, 'height', window.visualViewport.height);
  }

  var rawAdd = window.addEventListener;
  window.addEventListener = function (type, listener, options) {
    if (type === 'resize') {
      console.warn('[anti-resize] blocked resize listener');
      return;
    }
    return rawAdd.call(this, type, listener, options);
  };
  window.onresize = null;
})();
```

## 变体与关联

- 变体：同时锁定 `screen.width/height`、`devicePixelRatio`、`document.documentElement.clientWidth` 等；检测脚本可能读取多个来源做交叉校验。
- 变体：用 `Proxy` 包裹 `window` 或重写 `Object.getOwnPropertyDescriptor` 对抗属性校验。
- 变体：检测使用 Media Queries 时，Hook 失效；可注入 CSS 覆盖媒体查询或改用 undocked DevTools/独立窗口。
- 关联：[[code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass]]（先打开 DevTools）；[[code-analysis-reverse-anti-debug-js-tostring-environment-bypass]]（另一类环境检测绕过）。
- 边界：Hook 必须早于检测脚本；页面若在 Worker/iframe 中检测，需分别注入；`Object.defineProperty` 可能被检测脚本校验 `toString` 或属性描述符，需配合其他反反调试手段。

## 检测与防御

- 检测/分析侧：在 Console 中检查 `Object.getOwnPropertyDescriptor(window, 'innerWidth')` 是否为自定义 getter；查看 `getEventListeners(window).resize`。
- 防御侧：窗口尺寸检测只是提高逆向成本，不是安全控制；不要把授权/秘密逻辑放在前端。
- 加固：若使用该检测，组合多种信号并做完整性校验，但需接受可被 Hook 绕过的事实；避免因误判影响正常用户。
