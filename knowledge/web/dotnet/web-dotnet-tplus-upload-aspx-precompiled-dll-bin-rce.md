---
id: web-dotnet-tplus-upload-aspx-precompiled-dll-bin-rce
title: 畅捷通 T+ Upload.aspx 仅校验 Content-Type：路径穿越上传 + 预编译站点投 bin 程序集拿 RCE
type: scenario
domain: web
path: web/dotnet
technique: tplus-upload-precompiled-dll-bin-rce
aliases:
- 畅捷通 T+ 文件上传
- Upload.aspx 上传
- 预编译站点 上传 dll
- aspnet_compiler 生成 bin
- bin 目录 DLL 上传
- /SM/SetupAccount/Upload.aspx
tags:
- dotnet
- aspnet
- file-upload
- precompiled
- bin-dll
- rce
- tplus
- chanjet
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V543
  verified_at: '2026-11-11T20:40:51+08:00'
  notes: 已对照原文与图01-04、10-13核对：Upload.aspx 为预编译页，Page_Load 只校验 ContentLength<=204800 与 Content-Type image/gif|png|jpeg，fileName 仅按最后一个反斜杠截断，filename=../../../1.aspx 前向斜杠穿越可写到上传目录外；直接访问上传的 aspx 返回'未预编译文件，不能请求该文件'（图11）；aspnet_compiler.exe -v / -p c:\3 c:\4 -fixednames 生成 App_Web_*.dll 与 .compiled（图12）并投放到 bin 的链与原文一致。原文未给 T+ 版本，无 affected_versions 正确。上传+预编译投 bin 为同一利用链，原子；与 UEditor/JHSoft 等仅 Content-Type 校验上传卡不同（关键变体为预编译站点投程序集），dedup 无 duplicate。原文未实际展示 bin 上传报文，卡内步骤为按原文描述的复现编排，已注明预期。未执行上传。
---

## 一句话结论

畅捷通 T+ 的 `/tplus/SM/SetupAccount/Upload.aspx` 的 `Page_Load` 只校验上传文件的 `Content-Type` 是否属于 `image/gif|image/png|image/jpeg`，不校验扩展名，且文件名只取最后一个反斜杠后的部分，前向斜杠路径穿越仍然生效；虽因站点为预编译而无法直接解析上传的 `.aspx`，但可先把 aspx 马用 `aspnet_compiler` 预编译成程序集，再把生成的 DLL 与 `.compiled` 文件上传到 `bin` 目录，访问对应页面即可执行代码。

## 原理

- `Upload.aspx` 是预编译页面，代码在 `bin` 下 `upload.aspx.<hash>.dll` 中；`Page_Load` 读取 `File1`，检查 `ContentLength <= 204800` 和 `File1.PostedFile.ContentType` 是否等于 `image/gif`/`image/png`/`image/jpeg`，通过后执行 `File1.PostedFile.SaveAs(imageUrl + "/" + fileName)`。
- 文件名处理为 `fileName = substring(fileName.lastIndexOf("\\") + 1)`：只剥离 Windows 反斜杠路径，`../`、`..\` 中的前向斜杠未被清理；因此 `filename="../../../1.aspx"` 会把文件写到上传目录之外。
- 默认保存目录为 `/SM/SetupAccount/image`（代码/页面逻辑暗示），路径穿越可写到 web 根或其他可写目录；上传 `.aspx` 后访问返回“未预编译文件，不能请求该文件”，说明该 ASP.NET 站点是预编译部署，磁盘上的 aspx 不会被动态编译。
- 绕过预编译限制：把攻击者 aspx 马放到本地目录，用 `aspnet_compiler.exe -v / -p <aspx目录> <输出目录> -fixednames` 预编译，输出目录的 `bin` 下会生成 `App_Web_*.dll` 与对应的 `.compiled` 标记文件；把这两个文件上传到目标站点的 `bin` 目录，ASP.NET 会按 `.compiled` 中的虚拟路径映射到该程序集，请求原 aspx 路径时由程序集中的页面类执行。
- 之所以成立：上传端只信任 MIME；文件名过滤只处理反斜杠；预编译站点的 `bin` 是代码加载目录，写入程序集等价于写入可执行代码；应用池重启/触碰 web.config 后加载新程序集。
- 前置未授权：该上传页的登录校验可被 `preload=1` 或 `;/login` 短路（见关联卡）。

## 触发条件

- 目标为畅捷通 T+ 且 `/tplus/SM/SetupAccount/Upload.aspx` 可达。
- 登录校验可被 Global.asax 短路绕过（`preload=1` 或 URL 含 `login` 等关键字）。
- Web 进程对 `bin` 或可加载目录有写权限（通过路径穿越到达）。
- 站点为预编译部署（需用预编译程序集而非直接上传源码 aspx）。
- 上传大小限制（约 200KB）足够容纳精简的预编译程序集/compiled 文件。

## 利用步骤

1. 确认上传点：访问 `/tplus/SM/SetupAccount/Upload.aspx`，观察是否要求登录；用 `?preload=1` 或 `;/login` 绕过。
2. 先上传一个测试 `.aspx`（`filename="../../../test.aspx"`，`Content-Type: image/jpeg`）验证路径穿越与写入位置；访问确认提示“未预编译文件，不能请求该文件”。
3. 本地准备 aspx 马（如输出字符串/执行命令的最小页面），执行 `C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\aspnet_compiler.exe -v / -p c:\payload c:\out -fixednames`，在 `c:\out\bin` 得到 `App_Web_*.dll` 与 `.compiled`。
4. 通过同一上传接口，把 DLL 上传到目标 `bin` 目录（文件名含 `../` 穿越到 web 根下的 `bin`），再把 `.compiled` 上传到对应路径；注意 Content-Type 设为图片类型。
5. 访问 `/<virutalPath>.aspx`（与预编译时的虚拟路径一致）触发程序集加载与执行，验证命令回显。
6. 若未生效，检查上传目录、bin 写权限、应用池是否重启，必要时再上传一个 web.config 触碰或等待回收。

## PoC

```http
POST /tplus/SM/SetupAccount/Upload.aspx?preload=1 HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=9df1c9e8486b0bf2a2a1bf99e7fbeb02
Content-Length: 180

--9df1c9e8486b0bf2a2a1bf99e7fbeb02
Content-Disposition: form-data; name="File1"; filename="../../../1.aspx"
Content-Type: image/jpeg

test
--9df1c9e8486b0bf2a2a1bf99e7fbeb02--
```

```bat
:: 本地把 aspx 马预编译为程序集
C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727\aspnet_compiler.exe -v / -p c:\payload c:\out -fixednames
:: c:\out\bin\App_Web_*.dll 与 *.compiled 一并上传到目标 bin
```

```text
# 预期：上传 .aspx 直接访问报“未预编译文件，不能请求该文件”；
# 上传预编译 DLL+.compiled 到 bin 后，访问对应 aspx 执行页面代码。
```

## 变体与关联

- 变体：上传 `.asmx`/`.ashx` 对应的预编译程序集，或上传 IIS Managed Module DLL 并改 web.config（需可写 web.config）。
- 变体：若 `bin` 不可写，可尝试上传到 `App_Code`、`App_WebReferences` 等可被编译加载的目录，或利用其他文件写入点。
- 变体：Content-Type 校验可用图片头 + 双扩展名/`;` 绕过；路径穿越用 `..%2f`、`..\` 等编码形式。
- 关联：[[web-dotnet-tplus-global-asax-preload-url-whitelist-auth-bypass]]（前置鉴权绕过）、[[web-dotnet-iis-managed-module-backdoor-bin-webconfig]]（bin 投放 IIS 模块）、[[web-dotnet-aspnet-webshell-compiled-assembly-evasion]]（预编译程序集形态的 webshell 与免杀）。
- 边界：上传目录不可写、`bin` 只读/受监控、AppLocker/WDAC 限制程序集加载、站点非预编译或禁用了动态加载、上传大小不足以容纳程序集时，本场景不成立或需改用其他写入点。

## 检测与防御

- 检测：上传请求的 `Content-Type` 与文件头/扩展名不一致；文件名含 `..`、`/`、`\`；`bin` 目录出现新增 DLL/`.compiled`；应用池重启后异常程序集加载；访问刚上传的 aspx 路径。
- 修复：上传白名单校验扩展名 + 文件头 + 重命名 + 固定目录；规范化为绝对路径并校验仍在目标目录；`bin` 目录对 Web 进程只读；禁用不必要的上传端点。
- 加固：AppLocker/WDAC 限制 `bin` 下未签名程序集加载；文件完整性监控（bin/web.config）；升级 T+ 到修复版本并移除登录短路。
