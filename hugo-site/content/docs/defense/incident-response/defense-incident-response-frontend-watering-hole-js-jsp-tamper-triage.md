---
id: defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage
title: 首页弹窗诱导下载木马的应急排查：按提示文案反查被篡改的门户模板/JS，用同名 .js1 备份与 mtime 定位注入点，再解 cookie 门控与假 Flash 提示
type: scenario
domain: defense
path: defense/incident-response
technique: frontend-watering-hole-js-jsp-tamper-locate-cookie-gate-fake-flash
tags:
- incident-response
- watering-hole
- web-tampering
- javascript
- jsp
- cookie
- flash
- file-integrity
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:39:06+08:00'
  notes: 已对照原文核对；本次核对未读取图片；login.jsp 本体无内容而模板目录同名文件被插入、同目录 loginPreview.js1 与 mtime 异常、var config={downloadUrl:install.exe,cookieName:xxxxxx}、render_installer 内联 base64 GIF 与 \uXXXX 转义公告、judge_status/collect_status 的 ONLINE 30 天与 inself 100 天 cookie 门控均与原文一致。更正 cards.json 的一处说明：本篇 content.md 实为正常可读中文（仅个别叙述段落，如「翻阅模板文件」「时间过去了半小时」前后，存在少量 OCR/错字），并非整段双重编码乱码，抽取方「叙述段全部乱码」的判断不成立，但未影响成卡证据。排查命令（grep 文案 / find mtime / 找 .js1 与压缩包）为按原文排查逻辑编写的示意。未验证点：未实际执行巡检命令，PoC 未复跑
url: /docs/defense/incident-response/defense-incident-response-frontend-watering-hole-js-jsp-tamper-triage/
draft: false
kb_aliases:
- 水坑挂马排查
- 首页弹窗下载木马
- 假 Flash 更新提示
- login.jsp 被插入 JS
- loginPreview.js1 备份
- inself cookie 门控
- ONLINE cookie 标记
---

## 一句话结论

用户一打开门户首页就被弹窗要求“下载弱口令扫描工具/更新 Flash”，通常是攻击者拿到 WebShell 后篡改了前端文件。排查的关键不是翻遍全站，而是拿弹窗里的**提示文案**去检索：先在模板目录（而非 `login.jsp` 本体）里找到被插入的 JS，再从同目录的 `xxx.js1` 备份文件与 mtime 差异锁定被改文件；注入代码往往用 `inself`/`ONLINE` 一类 cookie 做“只弹一次”的门控，并把木马地址写成同目录的 `install.exe`。

## 原理

- **门户页不一定是登录页本身**：应用常用模板文件拼装门户（`login.jsp` 只是壳，真正渲染来自模板目录下的同名文件），所以直接检查 `login.jsp` 会看不到注入内容——必须顺着 `login.jsp` 里引用的模板/JS 往下找。
- **`xxx.js1` 是典型的“复制后改”痕迹**：攻击者改文件前常做一次备份（`cp loginPreview.js loginPreview.js1` 或编辑器生成的 `~`/`.bak`），备份与本体 mtime 相邻、内容只差注入段，是定位的强信号；反过来看，`mtime` 排序能把“最近被动过的前端文件”直接排到前面。
- **假 Flash 提示是标准话术**：页面用 `render_installer(file_url)` 动态插入一层全屏遮罩 + 内联 base64 GIF + “Flash Player 已于 2020 年 12 月 31 日终止服务，请点击下载”的文案，链接指向服务器本地的 `install.exe`；中文用 `\uXXXX` 转义写死，避免明文关键字被静态扫描发现。
- **cookie 门控降低暴露面**：`judge_status()` 判断 `getCookie(config.cookieName) == ""` 才渲染弹窗，渲染后或用户点击时写入 `ONLINE`（30 天）/`inself=true`（100 天），同一个用户不会反复看到弹窗——这既减少受害者警觉，也让“复现问题”的应急人员换浏览器/清 cookie 才看得到。
- **为什么要按文案检索**：注入代码可能被塞进任意被引用的 JS、模板片段或 HTML；提示文案（“【重要通知】”“Flash Player 已终止服务”）是唯一稳定、跨文件一致的锚点，比逐个读文件快得多。

## 触发条件

- 应用存在可写的 Web 目录，攻击者已获得 WebShell/后台文件管理权限。
- 门户首页由模板/JS 拼装，且这些文件对 Web 进程可写（运维习惯、权限过宽、无文件完整性监控）。
- 用户从浏览器访问被篡改页面，页面加载即执行注入脚本。

## 利用步骤

（应急侧，按顺序执行）

1. **记录现象**：用户看到什么弹窗、文案原文、下载的文件名与来源路径；用无痕窗口再访问一次，确认是否能复现（cookie 门控会让老用户看不到）。
2. **按文案全局检索**：在 Web 根与模板目录中检索弹窗里的关键字符串（中文可用 `\u` 转义形式一并检索，如 `Flash`、`\u0046\u006c\u0061\u0073\u0068`、`【重要通知】`），命中即得到被篡改文件。
3. **按引用链下钻**：若首页是 `login.jsp`/`index.jsp`，先看它 `include`/`script src` 了哪些模板与 JS，再逐个检查这些被引用文件，而不是只看入口页。
4. **按 mtime 排序**：`find <webroot> -type f -newermt '<入侵时间窗>' -printf '%T@ %p\n' | sort -rn` 把最近改动的文件排在最前；重点看与业务无关的 JS/模板。
5. **找备份与残留**：同目录下 `*.js1`、`*.bak`、`*~`、`.swp`、zip/rar 打包文件（攻击者常用压缩包暂存木马），并与本体做 diff 确认差异就是注入段。
6. **还原注入内容行为**：读注入 JS，提取 `downloadUrl`、`cookieName`、外链域名/IP、被写入的 cookie 名与有效期，判断是“诱导下载”还是“进一步挂马/钓鱼”。
7. **定位托管的恶意文件**：按 `downloadUrl` 相对路径在服务器上找到 `install.exe` 一类文件，计算哈希并送检；同时确认该文件是否被其他页面引用（可能不止一处水坑）。
8. **确认入口**：结合 Web 访问日志查该文件被写入前后的 POST/上传请求、WebShell 访问记录，定位初始入侵点；清除后重装/比对全站文件完整性。

## PoC

```javascript
// 被注入的典型门控 + 假 Flash 提示（结构示意）
var config = { downloadUrl: 'install.exe', cookieName: 'xxxxxx' };

function judge_status() {                       // 首次访问才弹，避免重复暴露
  if (getCookie(config.cookieName) == '') render_installer(config.downloadUrl);
}

function render_installer(file_url) {            // 全屏遮罩 + 内联 base64 GIF + 假公告
  // ... css / style 注入 ...
  var htmldoc = '<div class="notice"><div class="content">' +
    '   <img src="data:image/gif;base64,R0lGODlh...">' +
    "   <p>\u0046\u006c\u0061\u0073\u0068 ... \u7ec8\u6b62\u670d\u52a1\uff0c\u8bf7 <a href='" + file_url + "'>...</a></p>" +
    '</div></div>';
  document.body.appendChild(child);
}

function collect_status() { setCookie(config.cookieName, 'ONLINE', 30); }  // 30 天标记
window.addEventListener('load', function () { judge_status(); });
```

```bash
# 按提示文案定位被篡改文件（含 \u 转义形式）
grep -rIl --include='*.js' --include='*.jsp' --include='*.html' -e '【重要通知】' -e 'Flash Player' -e 'u0046.u006c.u0061.u0073.u0068' /path/to/webroot

# 按修改时间锁定最近被动过的前端文件
find /path/to/webroot -type f -newermt '2026-11-01' -printf '%T@ %p\n' | sort -rn | head -50

# 找攻击者留下的同名备份 / 编辑器残留 / 打包暂存
find /path/to/webroot \( -name '*.js1' -o -name '*.bak' -o -name '*~' -o -name '.swp' -o -name '*.zip' -o -name '*.rar' \) -ls
```

## 变体与关联

- **注入位置变体**：模板片段（`*.ftl`/`*.vm`/`*.tpl`）、被引用的公共 JS、`index.jsp` 直接内联、错误页/404 页、第三方统计脚本。
- **话术变体**：假 Flash 更新、假“弱口令扫描工具”、假 Chrome/钉钉/税务软件安装包、假“系统升级通知”、假“安全证书过期”。
- **门控变体**：cookie 名随机化、用 `localStorage`/`sessionStorage`、按 UA/Referer 只对特定来源弹窗（规避内部排查）。
- **关联**：[[pentest-initial-access-fake-chrome-update-watering-hole]]（攻击侧的假更新投递视角）、[[defense-incident-response-supply-chain-phishing-fake-login-attribution]]（仿冒登录页的取证与溯源）、[[defense-incident-response-hidden-dotfile-base64-decode]]（Web 根隐藏文件排查的另一种形态）。
- **边界**：注入内容只存在于数据库/缓存（CMS 模板存库）时，文件检索无命中，需从后台模板管理与数据库导出中查；若攻击者已还原原文件并删除木马，只能靠日志与备份比对。

## 检测与防御

- **文件完整性**：对 Web 目录做基线哈希并定期校验（AIDE/Wazuh/自建 diff），出现新增 `*.js1`、`*.bak`、可执行文件时告警；发布走 CI 而非手工改线上文件。
- **权限**：Web 进程与部署目录分离，运行用户对代码目录只读；上传目录禁执行、禁解析脚本。
- **检测（流量/日志）**：门户 JS 中出现外部可疑域名、`data:image/gif;base64` 大块内联资源、`install.exe`/`.scr`/`.msi` 下载链接；同一 IP 高频下载同一个小体积 exe；Web 日志中对 `.js`/`.jsp` 的非业务写入请求（PUT/上传接口）。
- **响应**：立即下线或替换被篡改文件、阻断恶意文件与外链、重置服务器凭据；对已下载用户做终端排查（查 `install.exe` 落地、计划任务/服务/启动项新增）；统计受影响用户范围并通知。
