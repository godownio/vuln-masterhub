---
id: code-analysis-reverse-anti-debug-js-infinite-debugger-bypass
title: JS 定时 debugger 反调试的 DevTools 绕过
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: js-infinite-debugger-devtools-bypass
aliases:
- 无限 debugger 绕过
- 定时 debugger 反调试
- 一律不在此处暂停
- 条件断点 false
- 本地替换绕过 debugger
tags:
- javascript
- anti-debug
- devtools
- reverse-engineering
- debugger
- browser
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:25:10+08:00'
  notes: 已对照原文与图 01-07 核对：Never pause here、条件断点 false、Local Overrides 替换、Firefox 取消在 debugger 语句上暂停四种方法均一致；PoC 未在本机浏览器执行。
---

## 一句话结论

页面用 `setInterval` 反复执行 `debugger` 让 F12 一打开就断住时，可在 DevTools 中对 `debugger` 行选择“一律不在此处暂停”、添加条件为 `false` 的条件断点、或用 Local Overrides 把该语句注释掉，从而恢复调试。

## 原理

- `debugger` 是 JS 语句，DevTools 打开且启用断点时会在此暂停。反调试脚本通常用 `setInterval(() => { debugger; }, 1000)` 或递归 `setTimeout` 定时触发，使分析者每次继续执行都再次断住。
- DevTools 的“Never pause here / 一律不在此处暂停”会对该源码位置设置永久忽略，后续命中不再暂停。
- 条件断点（Conditional breakpoint）在命中时先求值条件，条件为 `false` 则不暂停；把条件设为 `false` 等价于禁用该断点但保留其他断点。
- Local Overrides（本地替换）允许把线上 JS 保存到本地目录并替换响应；注释掉 `debugger` 后刷新，浏览器执行的是修改后的脚本。
- Firefox 的调试器有“在调试器语句上暂停 / Pause on debugger statement”开关，取消勾选即可全局忽略 `debugger`。
- 这些方法只处理“静态可见的 debugger 语句”；若 debugger 由字符串拼接、`eval`、`Function` 动态生成，静态断点/替换会失效，需要改用 Hook 脚本。

## 触发条件

- 目标页面在打开 DevTools 后反复触发 `debugger`，导致无法正常单步/查看调用栈。
- 分析者使用 Chrome/Edge DevTools 或 Firefox 调试器，且能访问 Sources 面板。
- `debugger` 语句在源码中可见（未经过度混淆/动态生成）。
- 页面未使用额外的 DevTools 检测（窗口尺寸、toString 等）配合阻断。

## 利用步骤

1. 打开 DevTools，等待在 `debugger` 处暂停；在 Sources 面板找到对应行。
2. 方法一：在行号上右键 → “Never pause here / 一律不在此处暂停”。
3. 方法二：行号右键 → “Add conditional breakpoint / 添加条件断点”，条件填 `false`。
4. 方法三：在 Sources 的 Overrides 面板选择一个本地文件夹并允许；右键目标 JS → “Save for overrides / 替换内容”；在本地副本中注释/删除 `debugger`，保存并刷新。
5. 方法四（Firefox）：DevTools 设置中取消 “Pause on debugger statement / 在调试器语句上暂停”。
6. 继续调试，确认不再被定时断点打断。

## PoC

```javascript
// 典型的定时 debugger 反调试
setInterval(function () {
  debugger;
}, 1000);
```

```text
# Chrome/Edge：
# Sources -> 找到 debugger 行 -> 右键
#   1) Never pause here
#   2) Add conditional breakpoint -> 条件填 false
#   3) Save for overrides -> 注释掉 debugger -> 保存刷新

# Firefox：
# DevTools 设置 -> 取消勾选 "Pause on debugger statement"
```

## 变体与关联

- 变体：`setTimeout` 递归、`requestAnimationFrame` 循环、事件回调中触发 `debugger`；对每个触发点分别设置忽略/条件断点。
- 变体：`debugger` 被包裹在 `if`/`try` 中或由定时器间接调用；可在调用栈上层对定时器回调设置忽略。
- 关联：[[code-analysis-reverse-anti-debug-js-dynamic-debugger-hook]]（字符串拼接/eval 动态 debugger 需要 Hook 脚本）；[[code-analysis-reverse-anti-debug-js-devtools-shortcut-bypass]]（F12 被禁用时的进入方式）。
- 边界：Local Overrides 只影响当前浏览器且需要重新加载；如果脚本使用 CSP/完整性校验或 Service Worker 缓存，替换可能不生效。Firefox 的全局开关会忽略所有 debugger 语句，可能影响正常断点调试。

## 检测与防御

- 检测/分析侧：这是逆向分析手段，不针对服务端；可在浏览器中观察反调试脚本的定时器与调用栈。
- 防御侧：前端反调试不是安全边界，不能防止有决心的分析者；不要把秘密逻辑只放在前端。
- 加固：若确需增加分析成本，可组合多种检测（动态 debugger、窗口尺寸、toString），但应视为混淆而非安全控制；同时避免影响正常用户性能。
