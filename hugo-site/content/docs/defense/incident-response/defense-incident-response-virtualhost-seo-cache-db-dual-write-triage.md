---
id: defense-incident-response-virtualhost-seo-cache-db-dual-write-triage
title: 虚拟主机黑帽 SEO 应急：UA 分流 JS + CMS runtime 缓存与数据库 config 表双写注入的定位与清理
type: scenario
domain: defense
path: defense/incident-response
technique: virtualhost-seo-ua-cloaking-cache-db-dual-write-triage
tags:
- incident-response
- seo-poisoning
- defacement
- user-agent
- cms
- runtime-cache
- database-config
- virtual-hosting
- webshell
- triage
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V631
  verified_at: '2026-11-12T23:42:24+08:00'
  notes: 已对照原文与21张截图逐张核对：01手机色情落地页、02源码 UA 分流 if(!navigator.userAgent.match(/baiduspider|sogou|360spider|yisou/i)) 改 title + 外链 common.js、03西部数码虚拟主机面板、04 wwwroot 打包下载与 test.php 47.76K、05 config_cn.php 返回 WEB_NAME/WEB_URL/WEB_ICP/TITLE 数组且被注入 script、06 youdian_config 表 SEO 行（WEB_NAME/WEB_URL/WEB_ICP/WEB_CLOSE_REASON/TITLE 等）、07业务恢复、08 YouDianCMS 后台、09 admin 表多用户 MD5、10基本设置、11上传后缀 php/php3/php5/phtml、12/13 test.php 大马、14-21大厂协助/SaaS WAF CNAME 接入与 WTS-WAF 拦截。修复过程（先删缓存仍跳转→再清数据库才恢复）与卡片“双处清理”结论一致；卡片“缓存由数据库重建”为合理推断并以'可能'表述，confidence medium 恰当。dedup 报告 5 候选均判 new，最近候选 defense-incident-response-web-defacement-proxy-js-ua-redirect-triage（cos 0.8513）为 index.php/1.js 静态注入型，持久化位置与处置不同，非重复；dup-scan.json 无涉及本篇 pair。原文未写 YouDianCMS 版本，不设 affected_versions 正确。未验证点：grep/find/SQL 排查命令未在本机执行；CMS 缓存重建顺序未实测（推断）。
url: /docs/defense/incident-response/defense-incident-response-virtualhost-seo-cache-db-dual-write-triage/
draft: false
kb_aliases:
- 色情 SEO 劫持应急
- UA 分流跳转排查
- runtime 缓存 SEO 注入
- 数据库 config 表 SEO 注入
- 虚拟主机网页篡改
- youdiancms SEO 劫持
---

## 一句话结论

虚拟主机站点被黑帽 SEO 劫持、手机访问跳到色情页时，首页往往先输出一段按 User-Agent 分流的 JS（放过 baiduspider/sogou/360spider 等爬虫，对普通/手机 UA 改标题或跳转）；SEO 关键词与跳转配置不只写在源码里，还会同时写入 CMS 的 runtime 缓存文件（如 `Data/runtime/Data/config_cn.php` 返回配置数组）和数据库配置表（如 `youdian_config` 的 WEB_NAME/WEB_URL/WEB_ICP/TITLE 等行），只删一处会因缓存/配置重建而复发，必须两处同时清理；溯源通常落到 CMS 后台弱口令（MD5 可查）与被篡改的上传后缀白名单（加 php/php3/php5/phtml）→ 任意 PHP 上传拿 WebShell。

## 原理

- **黑帽 SEO 的 UA 分流**：页面被注入 `<script>` 或用 `src` 引用外部 `common.js`，脚本用 `navigator.userAgent` 判断：命中 `baiduspider|sogou|360spider|yisou` 等爬虫时不改标题/不跳转（避免被搜索引擎发现），普通访客改 `document.title` 写入色情关键词，进一步判断手机 UA 后 `window.location` 跳到色情站。这样 PC 直接看可能“空白”，右键源码才看得到注入内容。
- **为什么同时改缓存与数据库**：CMS 把站点配置缓存到 `runtime` 目录（PHP 数组文件），页面渲染优先读缓存、缓存缺失时再从数据库 `config` 表重建。攻击者把 SEO 内容写进数据库配置行，同时改缓存文件，保证立即生效；运维只清理缓存文件后，下一次请求可能由数据库重新生成缓存，跳转复发。因此必须按“源码/缓存 + 数据库”两条线同时排查。
- **定位思路**：虚拟主机通常只提供 FTP/文件管理/数据库管理，没有服务器 shell 与访问日志，无法看系统日志；处置时先关停站点、在控制台把 `wwwroot` 打包下载，再本地全目录搜索近期修改文件与 SEO 关键词，随后在数据库里查配置表。
- **重写配置文件排除**：先看 `.htaccess`、`web.config`、`httpd.ini` 是否被加 Rewrite/跳转规则；本例三者正常，排除配置层劫持。
- **溯源到后台**：CMS 后台 `admin` 表存在多个管理员，密码为无盐 MD5 且可在 cmd5 等站点反查；弱口令登录后在“基本设置/上传设置”里可改 SEO 内容，并把 `php/php3/php5/phtml` 加入允许上传后缀，随后直接上传 `test.php` 大马（文件列表可见 47KB 的可写文件）。
- **虚拟主机下的防护补救**：无主机权限时无法装 agent/看日志，可把域名 CNAME 切到 SaaS WAF，按源站 IP 做回源限制，并修改所有管理员口令、删除 WebShell、收紧上传白名单。

## 触发条件

- 网站运行在虚拟主机/共享空间，只有 FTP/文件管理与数据库面板，无服务器 shell 与访问日志。
- 站点被用于黑帽 SEO：手机访问跳色情/博彩页，PC 源码含 UA 判断脚本。
- CMS 使用 runtime 缓存 + 数据库配置表保存站点 SEO 配置。
- 管理员使用弱口令（或 MD5 可反查），上传设置允许 PHP 系列后缀。

## 利用步骤

1. 关停站点（控制台“主机状态”停止），避免继续对外跳转与扩大影响；对 `wwwroot` 全量打包下载，保留证据。
2. 检查 `.htaccess`、`web.config`、`httpd.ini` 等重写配置，确认是否被加入跳转/403 规则；本例均正常。
3. 本地全目录搜索 SEO 关键词、`navigator.userAgent`、`window.location`、`baiduspider|sogou|360spider` 与近期修改时间，定位被改文件；本例仅 `Data/runtime/Data/config_cn.php` 被改（返回含 WEB_NAME/WEB_URL/WEB_ICP 的配置数组）。
4. 在数据库配置表（如 `youdian_config`）中 `SELECT` 排查 WEB_NAME/WEB_URL/WEB_ICP/WEB_CLOSE_REASON/TITLE 等行的值，确认 SEO 内容同时写入了数据库。
5. 同时清理：删除/还原缓存文件中的注入内容，并在数据库中删除或还原被注入的配置行；两处都清完再恢复站点访问，验证不再跳转。
6. 溯源：检查 `admin` 表用户与密码（MD5 反查弱口令）、最近登录时间/IP；检查上传设置是否被加入 php/php3/php5/phtml，上传目录与根目录是否存在 `test.php` 等大马并删除。
7. 加固：修改全部管理员口令为强口令、移除危险上传后缀、删除未知可写文件；无主机权限时把域名 CNAME 接入 SaaS WAF 并限制回源 IP；持续观察是否复发。

## PoC

排查/清理命令与 SQL（按实际 CMS 结构调整，未在本机执行）：

```bash
# 全目录搜索 UA 分流与 SEO 注入特征
grep -rniE "navigator\.userAgent|window\.location|baiduspider|sogou|360spider|yisou" wwwroot/
# 按修改时间找近期被改文件
find wwwroot/ -type f -mtime -3 -printf '%TY-%Tm-%Td %TH:%TM %p\n'
```

```sql
-- 查配置表中的 SEO/跳转内容（表名/列名按 CMS 调整）
SELECT ConfigID, ConfigName, ConfigValue FROM youdian_config
WHERE ConfigValue LIKE '%<script%' OR ConfigValue LIKE '%http%' OR ConfigValue LIKE '%色情%';

-- 还原/删除被注入的配置行（示例，先备份）
UPDATE youdian_config SET ConfigValue = '<原值>' WHERE ConfigID = ?;
```

```php
// 被篡改的 runtime 缓存文件通常形如：
return array('WEB_NAME' => '...', 'WEB_URL' => 'http://...', 'WEB_ICP' => '<a href=...>...');
```

## 变体与关联

- 静态文件注入型网页篡改（首页 `index.php` 末尾 echo `<script src=...>`、1.js 按 UA 分流）的排查见 [[defense-incident-response-web-defacement-proxy-js-ua-redirect-triage]]；本卡的差异是注入点同时位于 runtime 缓存与数据库配置表，必须双处清理且涉及虚拟主机无日志环境。
- 隐藏暗链（页面正常但 DOM/meta 中藏外链）的排查见 [[defense-incident-response-hidden-link-source-dom-triage]]；本卡是主动跳转型 SEO 劫持。
- 溯源到的“后台改上传设置加 php 后缀直接上传 WebShell”模式与 WordPress 同类：
  [[web-generic-file-upload-wordpress-misc-allow-php-extension-upload]]；通用文件上传绕过见 [[web-generic-file-upload-ueditor-net-controller-contenttype-aspx]]。
- 变体：SEO 内容可写入模板缓存、Redis/Memcached、CDN 边缘配置或 `.htaccess`/Nginx 规则；UA 分流可换 Referer、时间、地域；清理时必须找到所有持久化位置，否则会复发。
- 变体：无 SaaS WAF 条件时，可临时下线站点、限制管理入口 IP、修改 FTP/数据库口令并持续监控文件完整性。

## 检测与防御

- **检测**：监控 `runtime`/缓存目录与站点配置文件的哈希和修改时间；页面源码中出现 UA 判断 + `window.location` 组合；数据库中配置值出现 `<script>`、`http://`、色情/博彩关键词；管理员异常登录与上传目录新增可执行文件。
- **防御**：CMS 与插件及时更新；管理员强口令、禁用无盐 MD5 存储；上传白名单只保留业务必需类型并禁止 PHP 系列；站点目录最小权限、关闭不需要的写权限；虚拟主机无法加固时用 SaaS WAF/云 WAF 做前置防护并限制回源 IP。
- **响应**：先关站保全证据，再双处清理缓存与数据库，删除 WebShell、修改全部凭据，最后恢复业务并持续观察复发。
