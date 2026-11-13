---
id: web-generic-file-inclusion-mcms-5-3-1-template-delete-slash-dotdot-bypass
title: MCMS 5.3.1 模板删除路径穿越：fileName=`/..` 绕过 `../`/`..\` 黑名单删除整个 template 目录
type: scenario
domain: web
path: web/generic/file-inclusion
technique: mcms-template-delete-slash-dotdot-blacklist-bypass
tags:
- java
- mcms
- mingsoft
- springboot
- path-traversal
- arbitrary-delete
- blacklist-bypass
cve: []
affected_versions: MCMS 5.3.1
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V681
  verified_at: '2026-11-13T13:44:33+08:00'
  notes: 已对照原文正文与15张图核对：图12/15 delete 源码为 if (fileName == null || !fileName.contains("../") && !fileName.contains("..\\")) 后拼接 BasicUtil.getRealTemplatePath(...) 并 FileUtils.deleteDirectory；@PostMapping("/delete")、@RequiresPermissions("basic:template:del")；调试变量 fileName="/.."、uploadTemplatePath="template"、path="D:\MCMS\src\main\webapp\template\1\.."；图13 Burp 返回 {"result":true,"code":200}；图14 模板目录被清空。修正：接口路径由 /ms/template/delete 改为 /ms/basic/template/delete.do——原文请求行被滚动遮挡，依据同控制器 writeFileContent.do 的 /ms/basic/template 前缀与 Referer /ms/basic/template/index.do 推定（/ms/template/delete 是 5.2.8 旧卡的抓包）；删除原步骤中原文未出现的“先传 2.txt 验证”（该细节抄自 5.2.8 旧卡）。未复跑 PoC；删除结果由目录消失截图佐证。dedup 与 5.2.8 无检查版本非同一条触发链，append_scenario 理由成立；dup-scan 无涉及本卡 pair。
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-mcms-5-3-1-template-delete-slash-dotdot-bypass/
draft: false
kb_aliases:
- MCMS 5.3.1 任意目录删除
- TemplateAction#delete
- /ms/basic/template/delete.do
- fileName=/..
- 删除 template 模板目录
---

## 一句话结论

MCMS 5.3.1 后台模板删除接口 `/ms/basic/template/delete.do`（与 writeFileContent 同属 `net.mingsoft.basic.action.TemplateAction`，原文 Referer 为 `/ms/basic/template/index.do`）在拼接 `fileName` 前只检查其是否包含 `../` 与 `..\`；把 `fileName` 传成 `/..` 即可同时避开这两个子串，拼接出的路径 `template/<appId>/..` 经文件系统解析后落到 `template` 根目录，`FileUtils.deleteDirectory` 会把整个模板目录（所有模板文件）递归删除。

## 原理

- **删除路径**：`net.mingsoft.basic.action.TemplateAction#delete` 取 `fileName = request.getParameter("fileName")`，拼成 `BasicUtil.getRealTemplatePath(uploadTemplatePath + File.separator + appId + File.separator + fileName)`，再调用 `FileUtils.deleteDirectory(new File(path))` 递归删除。
- **黑名单**：代码在删除前判断 `fileName` 是否包含 `../` 或 `..\`，命中则返回"非授权路径"错误；它只匹配带尾部分隔符的两种写法，没有做 `getCanonicalPath`/`normalize` 后校验路径是否仍在模板根目录内。
- **`/..` 绕过**：`fileName=/..` 的字符串既不含 `../` 也不含 `..\`，检查放行；拼接结果形如 `template\1\/..`，Windows/Linux 文件系统解析 `..` 后等价于 `template`（应用模板根目录），`deleteDirectory` 递归删除整个 template 目录。原文调试截图显示 `uploadTemplatePath="template"`、`fileName="/.."`、`path="...\template\1\.."`，Burp 请求返回 `{"result":true,"code":200}`。
- **危害**：删除全部模板文件导致前台页面/后台渲染不可用，配置与自定义模板丢失，业务中断；删除操作不可逆，需依赖备份恢复。
- **权限**：接口带 `@RequiresPermissions("basic:template:del")`（原文截图），需要后台会话且具备模板删除权限；文章未给出未授权访问方式。

## 触发条件

- 目标为 MCMS 5.3.1（原文标注该版本，提交后已修复）。
- 已登录后台且账号具备模板删除权限（`basic:template:del`）。
- `fileName` 可控且只经过 `../`/`..\` 黑名单检查。
- 目标目录对应用进程可删除；删除不可逆，测试需在可恢复环境。

## 利用步骤

1. 登录后台，进入 系统设置-模板管理，点击删除并抓包，确认接口 `POST /ms/basic/template/delete.do` 与参数 `fileName`（原文 Burp 请求行被滚动遮挡，路径按同控制器 writeFileContent.do 与 Referer `/ms/basic/template/index.do` 推定）。
2. 把 `fileName` 改为 `/..`（或 `1/..`，按 appId 层级调整），发送请求；黑名单不匹配，路径解析到 `template` 根目录。
3. 返回 `{"result":true,"code":200}` 后，模板目录及其下所有模板文件被递归删除。
4. 通过页面访问/文件系统确认删除结果；恢复需依赖备份。

## PoC

```http
POST /ms/basic/template/delete.do HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Cookie: SHIRO_SESSION_ID=<后台会话>; rememberMe=<...>

fileName=/..
```

原文请求中 `fileName` 以 URL 编码提交，服务端解码后为 `/..`；返回结果 `{"result":true,"code":200}`。

## 变体与关联

- **同接口旧版本无检查**：MCMS 5.2.8 的 `TemplateAction#delete` 直接拼接并删除、连 `../` 都不检查，见 [[web-generic-file-inclusion-mcms-template-delete-traversal]]；本卡是 5.3.1 增加黑名单后的绕过（`/..`），版本与触发条件不同。
- **同类 CMS 模板删除/读写穿越**：[[web-generic-file-inclusion-jfinalcms-template-controller-traversal-read-write-delete]]。
- **相关联的 MCMS 模板写入**：[[web-generic-ssti-mcms-5-3-1-writefilecontent-ads-ftl-rce]]（同文章另一条链，写模板 RCE）。

## 检测与防御

- **检测**：后台请求 `fileName` 含 `..`、`/..`、`%2f..` 等穿越片段；模板目录被批量删除、页面渲染突然失败；审计日志中的删除操作与返回成功记录。
- **防御**：升级修复版本；对拼接后的路径取 `getCanonicalPath`/`normalize` 并校验前缀必须位于模板根目录内，拒绝任何 `..` 段（不要只匹配 `../`/`..\`）；模板删除加二次确认与回收站/备份；模板管理权限收敛并审计。
