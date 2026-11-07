---
id: ctf-forensics-chrome-heap-snapshot-flag-search
title: Chrome DevTools 堆快照中搜索泄漏的 flag
type: scenario
domain: ctf
path: ctf/forensics
technique: chrome-heap-snapshot-search
tags:
- ctf
- forensics
- chrome
- heap-snapshot
- browser-memory
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:32:02+08:00'
  notes: 已对照原文与图04核对：Chrome DevTools Memory → Heap snapshot → Take snapshot、搜索 vishwactf{、图04 高亮 VishwaCTF{h34p_5n4p5h0t_1s_D3ep_M3m0ry} 均一致；卡片补充了保存 .heapsnapshot 后 grep 的方法。未验证点：未本机抓取堆快照复现；原文无版本信息；frontmatter 无 sources/source_url。
url: /docs/ctf/forensics/ctf-forensics-chrome-heap-snapshot-flag-search/
draft: false
kb_aliases:
- Heap of Secrets
- Chrome 堆快照
- DevTools Memory
- 浏览器内存取证
---

## 一句话结论

网页把敏感字符串（如 flag）留在 JavaScript 堆对象中时，用 Chrome DevTools 的 Memory → Heap snapshot 抓取堆快照并保存，再在快照文本中搜索 `VishwaCTF{` 等前缀，即可直接找到泄漏的 flag。

## 原理

- Chrome 堆快照（`.heapsnapshot`）是 JSON 文本，包含所有存活对象的类型、字符串与引用关系；页面加载过的字符串会以明文出现在字符串表中。
- 即使页面上不显示 flag，只要 JS 变量、DOM 属性、闭包或缓存引用过它，堆中就可能保留。
- DevTools 的搜索框可以在快照中按字符串过滤；也可把快照保存后用 `grep`/文本编辑器搜索。
- 该方法不依赖页面 UI，适合“flag 藏在页面内存”类 Web/取证题。

## 触发条件

- 目标页面在浏览器中运行，且 flag 曾被 JS 读取/存储（即使未渲染）。
- 能打开 DevTools 并抓取堆快照。
- 快照未被加密/压缩，字符串以明文存在。

## 利用步骤

1. 用 Chrome 打开题目页，等待加载完成。
2. F12 → Memory → Heap snapshot → Take snapshot。
3. 在快照搜索框输入 flag 前缀（如 `VishwaCTF{`），或保存快照后用 `grep -a` 搜索。
4. 找到完整字符串，提交 flag。

## PoC

```text
DevTools: F12 -> Memory -> Heap snapshot -> Take snapshot -> 搜索 "VishwaCTF{"
或保存 .heapsnapshot 后：
grep -ao 'VishwaCTF{[^}]*}' heap.heapsnapshot
```

## 变体与关联

- 也可用 `window.performance`、`localStorage`、`sessionStorage`、IndexedDB 检查残留数据。
- 快照较大时用 `strings`/`grep` 比 DevTools 搜索更快。
- 关联：[[defense-forensics-chromium-artifact-offline-decrypt]]（Chromium 本地数据取证）、[[ctf-misc-v8-d8-dynamic-import-syntax-error-file-read]]（V8 相关）。

## 检测与防御

- 不要把敏感数据长期留在 JS 堆/全局变量中；使用后及时清空引用。
- 对敏感字符串做加密/分片，避免明文出现在内存快照。
- 检测：页面 JS 中出现 flag 前缀或敏感常量。
