---
id: web-php-cmseasy-image-deleteimg-dir-traversal-file-delete
title: CmsEasy 后台 image deleteimg：dir 参数未过滤的路径穿越 unlink 任意文件删除
type: scenario
domain: web
path: web/php
technique: cmseasy-image-deleteimg-dir-traversal-unlink
aliases:
- CmsEasy 任意文件删除
- image_admin deleteimg_action
- dir 参数目录穿越
- imgname 过滤 dir 未过滤
- unlink 任意文件删除
tags:
- php
- cmseasy
- arbitrary-file-delete
- path-traversal
- unlink
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
  verified_at: '2026-11-09T22:11:25+08:00'
  notes: 已对照原文核对：图02 源码与卡内一致（deleteimg_action 仅对 imgname 做 .___/#/.././ 四次 str_replace，dir 直接拼进 ROOT+html_prefix+/upload/images/<dir>/<imgname> 后 unlink；is_dir(dir) 为假时继续），图04-05 front::$get=$_GET、front_class.php:457，图06 Burp 删 cn/1.php 成功。affected_versions 原文环境 CmsEasy_7.7.7_UTF-8_20240105 明确，已 set-versions 为 CmsEasy 7.7.7；原文称 CVE+2 但未给编号，cve 留空正确；未实测。
---

## 一句话结论

CmsEasy 后台 `lib/admin/image_admin.php` 的 `deleteimg_action` 把 `front::get('dir')`（即 `$_GET['dir']`）原样拼进 `ROOT/html_prefix/upload/images/<dir>/<imgname>` 后 `unlink`，而代码只对 `imgname` 过滤了 `../`、`./`、`.___`、`#`，没有过滤 `dir`；因此后台用户可用 `dir=../../../cn` 从 `upload/images` 逐级跳出，删除 Web 目录下的任意文件。

## 原理

- **路由**：CmsEasy 按 `index.php?case=<控制器>&act=<方法>&admin_dir=admin` 分发；`case=image` 进入 `lib/admin/image_admin.php`，`act=deleteimg` 调用 `deleteimg_action`。
- **参数来源**：`front::get($var)` 在 `front_class.php` 中直接返回 `self::$get[$var]`，而 `self::$get = $_GET`，所以 `dir`、`imgname` 都是用户完全可控的 GET 参数。
- **危险拼接**：
  ```php
  $img = ROOT . rtrim(config::get('var','html_prefix'),'/')
       . '/upload/images/' . front::get('dir') . '/' . $imgname;
  if (file_exists($img)) { if (unlink($img)) { ... } }
  ```
  只有 `$imgname` 经过 `str_replace('.___','.')`、`str_replace('#','')`、`str_replace('../','')`、`str_replace('./','')` 四道替换；`dir` 未做任何规范化或白名单校验。
- **为什么过滤 `imgname` 不生效**：只要把穿越段放在 `dir` 里，`imgname` 保持纯文件名（如 `1.php`）即可通过全部替换；`is_dir(front::get('dir'))` 对 `../../../cn` 这类字符串返回 false，不会中断流程。
- **影响**：可删除站点任意可写文件（测试文件、模板、缓存、上传文件、安装锁等）；后台权限被攻陷后可用于破坏、抹除痕迹，或删除安装锁/配置为后续重装、重置或二次利用创造条件（原文仅演示删除测试文件，未验证后续链）。

## 触发条件

- 攻击者拥有 CmsEasy 后台管理员会话（请求需带 `admin_dir=admin` 与登录 Cookie）。
- 目标版本存在该 `deleteimg_action` 实现（原文环境 CmsEasy 7.7.7，2024-01-05）。
- Web 进程对目标文件有删除权限（通常上传目录与站点目录同用户）。

## 利用步骤

1. 登录后台，确认 `case=image` 图片管理功能可用，抓取其请求格式与 Cookie。
2. 在站点目录下创建一个测试文件（如 `cn/1.php`）验证删除效果。
3. 发送构造请求：`dir` 用 `../` 跳出 `upload/images`，`imgname` 只填目标文件名；按目录深度调整 `../` 数量。
4. 观察响应跳转（302）与文件是否消失；`html_prefix` 可按原文通过参数覆盖为 `../`（默认值可能使基路径不同）。
5. 命中后按目标价值选择删除对象：测试文件、模板缓存、安装锁、配置文件等（注意删除核心配置可能导致站点不可用）。

## PoC

```http
GET /index.php?case=image&act=deleteimg&admin_dir=admin&html_prefix=../&dir=../../../cn&imgname=1.php HTTP/1.1
Host: 127.0.0.1
Cookie: PHPSESSID=<后台会话>; login_username=admin; login_password=<登录校验值>
Connection: close
```

## 变体与关联

- 变体：`imgname` 的过滤可被 `dir` 绕过；若 `dir` 被后续版本加过滤，可尝试其他拼接点（`image_admin.php` 其他使用 `dir` 的动作）。
- 变体：删除 `install` 目录下的安装锁/配置文件后，部分 CMS 会重新进入安装流程，可能被用于重置管理员或重新安装（原文未验证，需按版本确认）。
- 关联：[[web-php-cmseasy-template-editcategorytemplate-module-name-unlink]]（同版本另一处 unlink 任意文件删除，入口与参数解析不同）、[[web-php-zentao-backup-editor-arbitrary-file-delete]]（同类后台路径穿越删除）、[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]（同产品文件写入 RCE，可组合成“删配置 + 写文件”）。
- 边界：需要后台权限；目标文件不存在或无删除权限时失败；`open_basedir` 可能限制跨目录删除。

## 检测与防御

- 代码层：对 `dir` 做 `basename`/白名单校验，拼接后用 `realpath` 确认仍在 `upload/images` 下；禁止把用户输入直接拼进 `unlink`。
- 权限层：Web 进程只对上传目录有写/删权限，站点核心目录只读；后台与前台分权运行。
- 监测：后台出现含 `../` 的 `dir` 参数、短时间内大量 `deleteimg` 请求、关键文件（安装锁、配置、模板）消失时告警；对站点目录做文件完整性监控。
- 修复：升级到厂商修复版本；无法升级时在 WAF/反代拦截 `dir` 中的 `../` 与绝对路径。
