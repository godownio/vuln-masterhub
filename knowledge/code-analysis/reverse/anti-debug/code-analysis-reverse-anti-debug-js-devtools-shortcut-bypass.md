---
id: code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass
title: JS 禁用 F12/右键/选择的前端限制绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: js-devtools-shortcut-bypass
aliases:
- 禁用 F12 绕过
- 禁用右键绕过
- 禁用选择绕过
- onkeydown 反调试
- 新标签页绕过
tags:
- javascript
- anti-debug
- devtools
- reverse-engineering
- browser
- frontend
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:25:12+08:00'
  notes: 已对照原文与图 08 核对：oncontextmenu/onkeydown/onselectstart 返回 false 的反调试原理，新标签页先开 DevTools 与自定义快捷键两种绕过均一致；原文未给出实际绕过截图验证，PoC 为按原文构造。
---

## 一句话结论

页面通过监听 `oncontextmenu`、`onkeydown`、`onselectstart` 等事件返回 `false` 来禁用右键、F12 和文本选择时，可先在普通页面打开 DevTools 再切换到目标 URL，或在浏览器设置里自定义一个 F12 之外的 DevTools 快捷键，直接绕过事件监听。

## 原理

- 前端禁用 F12/右键通常依赖 DOM 事件：`document.oncontextmenu = () => false`、`document.onkeydown` 检测 `keyCode === 123`（F12）或 `Ctrl+Shift+I`、`document.onselectstart = () => false`。
- 这些监听只作用于当前页面的键盘/鼠标事件；DevTools 的打开动作本身由浏览器处理，不经过页面 JS。
- 方法一：先在一个无限制页面打开 DevTools，再把地址栏 URL 替换为目标页面（或在 DevTools 已打开的状态下导航）。DevTools 已处于打开状态，目标页面的键盘监听无法阻止。
- 方法二：在 Chrome/Edge 的 DevTools 设置 → 快捷键（Shortcuts）中，把“打开 DevTools”绑定到 F12 之外的组合（如 `Alt+D`），再用该快捷键打开；页面监听的是 F12/Ctrl+Shift+I，不会拦截自定义组合。
- 本质上，禁用 F12 是“提高门槛”的客户端脚本，不是安全边界；任何能控制浏览器的人都能绕过。

## 触发条件

- 目标页面注册了 `contextmenu`/`keydown`/`selectstart` 等事件并返回 `false`，阻止默认行为。
- 分析者使用 Chrome/Edge/Firefox，且能打开 DevTools 设置或新标签页。
- 页面未配合其他检测（如窗口尺寸、toString、debugger）阻断 DevTools。

## 利用步骤

1. 新建标签页，打开任意网站并按下 F12（此时 DevTools 已打开）。
2. 在地址栏输入目标 URL 并回车，或把目标 URL 粘贴到当前标签页；DevTools 保持打开。
3. 若仍被拦截，打开 DevTools 设置 → Shortcuts，把“Open DevTools”改为 `Alt+D` 等自定义快捷键。
4. 回到目标页面，用自定义快捷键打开 DevTools。
5. 在 Console 中可直接执行 JS、读取变量、Hook 函数，不受页面键盘监听影响。

## PoC

```javascript
// 常见的禁用 F12/右键/选择实现
document.oncontextmenu = function () { return false; };
document.onselectstart = function () { return false; };
document.onkeydown = function (e) {
  if (e.keyCode === 123 || (e.ctrlKey && e.shiftKey && e.keyCode === 73)) {
    return false;
  }
};
```

```text
# 绕过步骤：
# 1) 新标签页打开任意站点 -> F12 打开 DevTools
# 2) 地址栏替换为目标 URL -> DevTools 仍保持打开
# 3) 或在 DevTools 设置 -> Shortcuts 中把打开 DevTools 改为 Alt+D
# 4) 回到目标页按 Alt+D
```

## 变体与关联

- 变体：监听 `keyup`/`keypress`、检测 `Ctrl+Shift+C/J`、禁用复制/粘贴；用自定义快捷键或 DevTools 菜单打开即可。
- 变体：`beforeunload` 阻止关闭、`onblur` 检测 DevTools；可禁用页面 JS 或用无痕窗口/新 profile。
- 变体：使用浏览器扩展/油猴脚本在页面加载前移除事件监听（`document.oncontextmenu = null`）。
- 关联：[[code-analysis-reverse-anti-debug-js-infinite-debugger-bypass]]（打开 DevTools 后的 debugger 绕过）；[[code-analysis-reverse-anti-debug-js-window-size-detection-bypass]]（DevTools 打开后的尺寸检测绕过）。
- 边界：如果页面还使用窗口尺寸/toString/定时 debugger 检测，单独绕过 F12 不足以稳定调试；需要组合多种反反调试手段。某些企业策略可能禁用 DevTools，此时需要其他分析环境。

## 检测与防御

- 检测/分析侧：在 Console 中检查 `document.oncontextmenu`、`document.onkeydown` 等是否为自定义函数；用 `getEventListeners` 查看监听器。
- 防御侧：前端禁用 F12 不是安全控制，不能保护代码或接口；敏感逻辑必须放在服务端。
- 加固：若仅为提高爬虫/逆向成本，可组合多种检测，但应避免影响可访问性；不要依赖客户端限制做授权。
