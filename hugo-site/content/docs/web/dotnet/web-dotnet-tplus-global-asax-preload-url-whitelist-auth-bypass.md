---
id: web-dotnet-tplus-global-asax-preload-url-whitelist-auth-bypass
title: 畅捷通 T+ Global.asax 鉴权短路：preload=1 直接 return，URL 含 login/token/静态后缀关键字也放行
type: scenario
domain: web
path: web/dotnet
technique: tplus-global-asax-preload-url-keyword-auth-bypass
tags:
- dotnet
- aspnet
- auth-bypass
- global-asax
- whitelist
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
  verified_at: '2026-11-11T20:40:50+08:00'
  notes: 已对照原文与图05-10、13核对：Global.asax Inherits=Ufida.T.Web.Http.Global，Application_PreRequestHandlerExecute 中 flag=QueryString['preload']=='1' 且 IsBaseRquest(Url) 关键字白名单(login/token/.js/.css/.jpg/.png...)，任一命中直接 return 跳过 LoginManager 会话校验；?preload=1（图10）与 Upload.aspx/;/login（图13）两种绕过与 PoC 一致。已按截图把方法名修正为原代码拼写 IsBaseRquest（非 IsBaseRequest）。原文未给 T+ 版本，无 affected_versions 正确。单点鉴权短路，原子；与既有 T+ REST IsFree=1 卡机制不同，dedup 无 duplicate，dup-scan 无 pair。未执行请求。
url: /docs/web/dotnet/web-dotnet-tplus-global-asax-preload-url-whitelist-auth-bypass/
draft: false
kb_aliases:
- 畅捷通 T+ 未授权访问
- preload=1
- IsBaseRquest 绕过（原代码拼写，亦常写作 IsBaseRequest）
- 畅捷通 Global.asax
- T+ 登录绕过
- URL 关键字白名单绕过
---

## 一句话结论

畅捷通 T+ 的 `Global.asax` 指向 `Ufida.T.Web.Http.Global`，其 `Application_PreRequestHandlerExecute` 在请求带 `preload=1`、或 URL 包含 `login`/`token`/`.js`/`.css`/`.jpg`/`.png`/`.bmp` 等任一关键字时直接 `return`，跳过后面的会话与权限校验；攻击者给任意受保护端点加 `?preload=1` 或在路径后附加 `;/login`，即可未授权访问该端点的完整功能。

## 原理

- ASP.NET 的 `Global.asax` 声明 `Inherits="Ufida.T.Web.Http.Global"`，请求进入处理器前会执行 `Application_PreRequestHandlerExecute`，T+ 把登录与会话校验放在这个钩子里。
- 该方法开头构造两个短路条件：`flag = Request.QueryString["preload"] == "1"`；`empty = Request.Url.ToString()`；随后 `if (flag || RequestChecker.IsBaseRquest(empty)) return;`（方法名原代码拼写如此，即 IsBaseRequest 的笔误）。一旦 return，后面的 `LoginManager` 会话检查、`Session["UserInfo"]` 判断都不会执行。
- `RequestChecker.IsBaseRquest(url)` 把 URL 转小写后，只要 `IndexOf("login") >= 0`、`IndexOf("token") >= 0`、或以 `.js`/`.css`/`.jpg`/`.png`/`.bmp` 等静态资源后缀出现，就返回 true——设计意图是放行登录页与静态资源，但用了**子串匹配**而非精确路径匹配。
- 因此两种稳定绕过：
  1. 任意受保护 URL 追加 `?preload=1`，命中第一个短路条件；
  2. 在路径后附加 `;/login`（ASP.NET/IIS 的 path-info 参数形式），`Request.Url` 含 `login` 命中白名单，但实际处理器仍按 `Upload.aspx`/`ajaxpro/*.ashx` 路由。
- 之所以成立：鉴权钩子把“URL 里出现关键字”当成“这是登录相关基础请求”，与真实处理器映射解耦；攻击者可以同时控制 URL 文本和实际命中的处理器。

## 触发条件

- 目标为使用该 `Ufida.T.Web.Http.Global` 鉴权逻辑的畅捷通 T+ 版本。
- `preload` 查询参数或 URL 关键字短路逻辑未被修复。
- 目标端点存在且未被其他独立鉴权/授权保护（如 Upload.aspx、ajaxpro 处理器等）。
- IIS/ASP.NET 接受带 `;` 的 path-info 形式（默认常见）。

## 利用步骤

1. 访问任意 T+ 页面，观察是否返回“没有登录，请登录”的提示（说明命中 Global 校验）。
2. 在原 URL 后追加 `?preload=1` 重放；若返回业务页面/表单而非登录提示，即绕过成功。
3. 若端点已带查询参数或对 `preload` 有过滤，改在路径后附加 `;/login`（如 `/tplus/SM/SetupAccount/Upload.aspx/;/login`），利用 URL 关键字白名单。
4. 用绕过后的请求访问上传、ajaxpro、文件读取等端点，继续后续利用（见关联卡）。
5. 验证时对比无绕过参数的响应，确认差异来自鉴权短路而非缓存。

## PoC

```http
# 方式一：preload=1 短路
POST /tplus/SM/SetupAccount/Upload.aspx?preload=1 HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=X
Content-Length: ...

--X--
```

```http
# 方式二：URL 关键字白名单（login 子串），实际仍命中 Upload.aspx
POST /tplus/SM/SetupAccount/Upload.aspx/;/login HTTP/1.1
Host: target:8080
Content-Type: multipart/form-data; boundary=X
Content-Length: ...

--X--
```

```text
# 预期：无参数时返回 JS alert("没有登录，请登录")；
# 带 preload=1 或 ;/login 后返回 Upload.aspx 的上传表单/业务响应。
```

## 变体与关联

- 变体：白名单还包含 `token`、`.js`、`.css`、`.jpg`、`.png`、`.bmp` 等；可尝试在路径/参数中带入这些子串（如 `/x.js/..` 形式需结合服务器归一化）。
- 变体：查询参数已在 URL 中时用 `&preload=1`；若被 WAF 拦 `preload`，改用 path-info 形式。
- 关联：[[web-dotnet-tplus-upload-aspx-precompiled-dll-bin-rce]]（本卡绕过后的上传链）、[[web-dotnet-deser-ajaxpro-cve-2021-23758-objectdataprovider]]（本卡绕过后的反序列化链）、[[web-generic-auth-weaver-e9-islogin-xsslist-regex-bypass]]、[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（同类的 URL 子串白名单问题）。
- 边界：修复为精确路径匹配、在处理器级别强制鉴权、移除 `preload` 短路或对 `;` 路径做归一化后，本场景失效。

## 检测与防御

- 检测：访问日志中出现 `preload=1`、路径含 `;/login`、`/login` 出现在非登录端点、静态后缀出现在动态处理器路径中；同一 IP 在未登录状态下访问 Upload.aspx/ajaxpro 等敏感端点。
- 修复：删除 `preload` 查询参数短路；`IsBaseRquest` 改为精确路径/前缀白名单并对 URL 做归一化（拒绝 `;`、`..`、编码绕过）；在处理器内部对敏感功能再做独立鉴权。
- 加固：WAF 对 `preload`、`;/`、path-info 形式加规则；对未授权访问敏感端点告警；升级到修复版本。
