---
id: code-analysis-source-audit-multi-version-dotnet-deployment-diff
title: 多版本/多客户 .NET 部署源码对比审计：bin.rar 反编译后按版本 diff 授权特性、saveas 上传与配置开关，定位版本特有漏洞
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: multi-version-dotnet-deployment-diff-audit
aliases:
- 多版本 .NET 代码审计
- 多客户部署源码对比
- bin.rar 反编译审计
- 版本差异找漏洞
- 企业定制漏洞
- dnSpy 导出 VS 审计
tags:
- code-analysis
- audit
- dotnet
- aspnet
- mvc
- version-diff
- source-audit
- decompile
- multi-tenant
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T21:05:04+08:00'
  notes: 已对照原文与15张图核对：老版本mobileController未授权（GetModuleList/GetModuleTreeList/GetPersonInfo，图01-03）、UploadFile/Import 的 str2+uid+file.FileName 拼接 SaveAs（图04代码）与 uid=/ + filename ../../test.ashx 穿越至根目录并成功执行（图05请求/响应，已放大确认请求行为 POST /CompositePortal/Mobile/UploadFile?uid=/）、中版本 AllowAnonymous+ImgFile 配置默认关闭、新版本 [AllowAnonymous] SaveMobileImg 上传 b021a.ashx 执行（图09）、string.Format SQL 拼接注入（图10-13）均与卡内一致；多版本/多客户diff审计方法论与原文'版本不同/供应商个性化开发'结论一致。与既有单版本 .NET MVC 审计卡为不同技术原子，dedup top候选 related/new，非重复。原文未给系统名/版本，affected_versions 留空正确。未验证点：方法论卡无单一PoC，未在本机复现各版本差异。frontmatter 无 sources/source_url/文章ID/URL/长段摘录。注：worker notes 将图04/05描述对调（实为04代码、05请求响应），不影响卡片内容。
---

## 一句话结论

同一 .NET 产品在不同客户、不同发布版本之间会发生功能分叉（重构、授权特性变化、配置开关、企业定制），只审计单一部署或只对一个站点跑扫描器会漏掉大量漏洞；拿到多个版本的 `bin.rar`/部署源码，用 dnSpy/ILSpy 导出到 VS 后按版本对比控制器、`saveas` 上传、授权特性与配置开关，可以定位某版本/某企业特有的未授权、上传、注入与任意登录。

## 原理

- **多客户部署的现实**：供应商给每个企业做个性化开发并分别部署，同一产品的多个站点可能运行不同年代、不同定制分支的代码；漏洞集合随版本漂移，而不是一个固定版本决定。
- **版本漂移的三种表现**（原文实测）：
  - 老版本：`mobileController` 下多个方法未授权，可直接读取人员通讯录/账号/电话；上传接口 `UploadFile` 把可控的 `uid` 与原始 `FileName` 拼进保存路径，可用 `uid=/` + `../../test.ashx` 穿越到站点根目录 getshell。
  - 中版本：重构后改为使用 `AllowAnonymous` 授权，上传接口 `ImgFile` 配置默认关闭，老的上传洞不可用。
  - 新版本：其他洞被修掉，但新增了 `[AllowAnonymous] SaveMobileImg()` 上传功能，且没有后缀/路径限制，直接上传 `b021a.ashx` 即可执行（“系统贴心的加了一个功能”）。
- **为什么单站审计会漏**：对第一个站点做 nuclei/黑盒扫描只覆盖了该部署的版本；换一个客户站点，同一个产品可能还停留在带洞的老版本，或带有该客户定制的特有接口。
- **可复用的差异维度**：控制器/Area 路由的增删；`[Authorize]`/`[AllowAnonymous]` 等授权特性；上传入口与保存路径拼接方式（`saveas`/`MapPath`/`FileName`/`uid`）；SQL 拼接方式（`string.Format` 直接嵌入参数）；登录/认证 Action 是否有硬编码口令或免登录标注；配置项默认值（如 `ImgFile` 开关）。
- **审计入口**：`bin.rar` 解压得到 DLL，dnSpy/ILSpy 反编译并导出 VS 工程；从 `Global.asax`/`AreaRegistration` 还原路由，再全局搜索危险 sink（`saveas`、`MapPath`、`FileName`、`string.Format`、`Login(`、`AllowAnonymous`）并按版本对齐比较。

## 触发条件

- 能获得同一产品的多个部署版本（不同客户站点的 `bin.rar`、部署包、备份或 DLL 下载）。
- 具备 .NET 反编译与工程导出能力（dnSpy/ILSpy），以及运行/调试目标版本的环境。
- 各版本之间存在重构或企业定制差异（多数商业 .NET 产品都是如此）。
- 具备授权测试条件，可对目标站点验证发现的接口。

## 利用步骤

1. 收集多个版本/客户部署的 `bin.rar`，记录版本号、部署时间、企业标识与功能差异。
2. 用 dnSpy/ILSpy 反编译 DLL，导出为 VS 工程；从 `Global.asax`、`AreaRegistration`、路由配置还原控制器与 Action 清单。
3. 对每个版本做危险 sink 全局搜索：`saveas`、`MapPath`、`FileName`、`string.Format`、`Login(`、`AllowAnonymous`、`[Authorize]`。
4. 按版本对齐控制器/Action，做 diff：找出新增/删除的接口、授权特性变化、上传保存路径变化、配置开关默认值变化。
5. 优先审计“某企业特有”的新增功能与老版本遗留的未授权 Controller（定制功能往往缺少安全评审）。
6. 对候选接口构造最小请求验证：未授权数据读取、任意密码登录、`uid`+文件名穿越上传、参数拼接注入。
7. 把验证结果回填到各版本矩阵，输出“版本 × 漏洞”清单；对同一产品的其他客户站点复测老版本遗留漏洞。

## PoC

无单一漏洞 PoC（方法论卡）。审计时可用的最小检查清单：

```text
# 反编译后全局搜索（VS/Notepad++）
saveas / SaveAs / MapPath / FileName / uid
string.Format(...{0}...)
[AllowAnonymous] / [Authorize]
Login( / FormsAuthentication / hardcoded string literal
# 配置默认值
ImgFile / UploadPath / AllowUpload 等开关
```

原文验证到的版本差异证据：老版本 `UploadFile`（`~/Resources/Attachment/` + `uid` + `FileName`）可穿越上传 `.ashx`；中版本 `ImgFile` 默认关闭；新版本 `SaveMobileImg` 标注 `[AllowAnonymous]` 且上传 `.ashx` 执行；老版本 `mobileController` 多个方法未授权返回人员数据。

## 变体与关联

- **变体**：只拿到一个版本时，可对比同一产品的公开旧版本/补丁版本（官方更新包、客户备份），用二进制 diff 找修复与新增功能的窗口。
- **变体**：企业定制代码常以插件/Area/独立 Controller 形式存在，优先审计非通用模块。
- 关联：[[code-analysis-source-audit-dotnet-mvc-ilspy-route-search]]（单版本 .NET MVC 路由与 SQL 搜索）、[[pentest-recon-dotnet-dll-download-decompile-audit]]（通过任意文件下载获取 DLL 转白盒）、[[code-analysis-source-audit-feature-code-reuse-sibling-sink-mining]]（功能代码复用与兄弟 sink 挖掘）。
- 边界：强混淆/加壳/动态加载会降低反编译可读性；客户定制差异过大导致 diff 噪声高；没有多版本样本时退化为单版本审计。

## 检测与防御

- **供应商侧**：对每个客户分支/版本做统一安全基线（默认鉴权、上传白名单与固定目录、参数化 SQL、禁止硬编码凭据）；定制功能必须走安全评审；发布前对多版本做差异审计与回归。
- **客户侧**：不要假设“最新版就安全”或“别人测过就安全”；对自己的部署版本单独做白盒/黑盒验证；关注 `bin` 目录与部署包的访问控制，避免 `bin.rar`/DLL 被下载。
- **检测信号**：同一产品不同站点版本指纹不一致；老版本遗留的未授权接口与上传入口仍在线上；定制新增的 `[AllowAnonymous]` 接口；登录接口任意密码成功。
