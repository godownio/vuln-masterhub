---
id: web-php-rce-phpyun-backend-config-index-fwrite-webshell
title: PHPYUN 后台配置任意键值 + 首页生成路径可控：fwrite 写 PHP Webshell（绕过括号替换过滤）
type: scenario
domain: web
path: web/php/rce
technique: phpyun-backend-config-index-generation-fwrite-webshell
aliases:
- PHPYUN 后台 getshell
- PHPYUN 配置写马
- make_index_url 路径可控
- webindex fwrite
- 首页生成写入 PHP
- setConfig 任意键值
- 网站名称写 PHP
tags:
- php
- phpyun
- cms
- backend
- code-audit
- file-write
- webshell
- rce
- path-traversal
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V535
  verified_at: '2026-11-11T17:38:32+08:00'
  notes: 已对照原文全文与13张截图核对(原图均<1200px，直接读原图，无读取失败)：图01 后台网站设置网站名称填PHPYUN人才招聘系统<?php echo `ls`;?>，顶栏版本V5.0.1；图02 工具-生成-首页生成首页保存路径../robots.php；图03 view-source http://目标/robots.php 输出admin/announcement/api等目录列表，证明命令已执行；图04 Burp抓包POST /admin/index.php?m=model_config&c=save；图05 config.class.php第83行$this->MODEL('config')；图06 MODEL()包含.model.php；图07 admin/index.php的m/c路由与require controller；图08 setConfig先select_all('admin_config',...,'name')再in_array判断upInfo/addInfo；图09 admin_config表数据；图10 cache_controller::index_action调用webindex($_POST['make_index_url'])；图11 Burp POST m=cache&c=index；图12 webindex渲染模板后fopen($path,'w')+fwrite；图13 db.safety.php将\"(\"替换为中文\"（\"及Delete/insert等敏感词替换。卡中路由、函数、参数名、sink与截图逐一对上；网站名称payload截图可辨为反引号命令执行(否则robots.php不会输出目录列表)，卡内对绕过过滤的解释成立。原文未声明受影响版本区间(仅界面V5.0.1为目标环境)，未设affected_versions符合不猜测原则。dedup top候选CmsEasy模板保存路径穿越/PbootCMS站点信息copy/DedeCMS首页生成/SeaCMS admin_ping等均为不同CMS与不同接口/sink，非同链；dup-scan无涉及pair。卡内关联链接经核对均存在(Discuz卡在web/php/framework路径但ID有效)。卡片原子，保留verified。未对真实目标执行请求。
---

## 一句话结论

PHPYUN 人才招聘系统后台的 `m=model_config&c=save` 保存配置时，`setConfig()` 对 POST 参数只做“已存在则更新、不存在则新增”，没有限制可写入的配置键；随后 `m=cache&c=index` 的 `webindex($_POST['make_index_url'])` 直接把 `make_index_url` 当作 `fopen($path,'w')` 的路径，把模板渲染后的站点配置内容写入该文件。攻击者（需后台权限）把网站名称改为 `<?php echo \`ls\`;?>` 一类 PHP 代码、把路径设为 `../robots.php`，即可在 Web 根目录生成可解析的 PHP 文件并执行命令；后台 `global.php` 的敏感词过滤会把英文括号转成中文，因此用反引号/不带括号的语句绕过。

## 原理

- **后台路由按 m/c 加载控制器**：`admin/index.php` 用 `$_GET['m']` 决定模型类文件（`require("model/".$model.".class.php")`），`$_GET['c']` 决定调用的方法；因此 `m=model_config&c=save` 进入配置保存逻辑，`m=cache&c=index` 进入首页生成逻辑。
- **setConfig 只做“存在即更新、否则新增”**：`config.class.php` 的 `save_action()` 调用 `$this->MODEL('config')`（加载 `config.model.php`），再把 POST 交给 `setConfig()`：先 `select_all('admin_config', ..., 'name')` 得到已有配置名数组 `$allList`，遍历 POST 时 `if(in_array($key,$allList))` 则 `upInfo` 更新，`else` 则 `addInfo` 新增。问题在于没有对 `$key` 做白名单校验——攻击者可以向 `admin_config` 表写入任意新配置项，而不只是修改现有项。
- **首页生成路径完全来自 POST**：`cache_controller::index_action()` 在 `madeall` 非真时执行 `$fw=$this->webindex($_POST['make_index_url'])`，随后把该值存回配置并刷新缓存。
- **webindex 用可控路径 fopen/fwrite**：`webindex($path)` 先用 `$phpyun->fetch(TPLPATH.$this->config['style'].'/index/index.htm', ...)` 渲染首页模板，模板会带入站点基本设置（网站名称等），得到 `$content`；然后 `$fp = fopen($path,'w'); fwrite($fp,$content);`。`$path` 未做目录限制/规范化，传 `../robots.php` 即可写到 Web 根目录（后台目录的上一级）。
- **为什么能写 PHP 代码**：站点名称等配置值原样进入模板渲染结果，攻击者在后台“网站设置”把网站名称改成 PHP 代码，生成的静态文件里就带有该代码。文件扩展名/路径由攻击者指定（`.php`），落到 Web 根后由 PHP 解析。
- **为什么不用 system() 等函数**：`global.php` 包含安全过滤文件（`db.safety.php`），对 `Delete`、`insert` 等敏感词做替换，并把英文括号 `(` 转成中文 `（`，直接写 `system('id')` 会被破坏；使用反引号执行命令（如 `<?php echo \`ls\`;?>`）或不带英文括号的语句即可绕过。原文生成的 `robots.php` 页面直接输出了 Web 根目录文件列表，证明代码已执行。

## 触发条件

- 目标为 PHPYUN 人才招聘系统（存在 `admin/index.php` 的 m/c 路由与 `cache.class.php` 首页生成功能）。
- 攻击者持有后台管理员会话（题目/实战中通过弱口令、源码泄露或其他后台入口获得）。
- Web 根目录（或目标路径）对 Web 进程可写；`make_index_url` 未做路径白名单/目录限制。
- 后台安全过滤未拦截所用语句（无英文括号、无敏感函数名）。

## 利用步骤

1. 登录后台，进入“系统 → 网站设置”，把网站名称改为 PHP 代码（如 `<?php echo \`ls\`;?>`），保存；对应请求为 `POST /admin/index.php?m=model_config&c=save`。此时 `setConfig()` 把该配置写入 `admin_config`。
2. 进入“工具 → 生成 → 首页生成”，把“首页保存路径”填为 `../robots.php`（可写 Web 根目录），提交；对应请求为 `POST /admin/index.php?m=cache&c=index`，参数 `make_index_url=../robots.php`。
3. `cache_controller::index_action()` 调用 `webindex('../robots.php')`，渲染含恶意站点名称的首页模板并 `fwrite` 到 Web 根目录。
4. 访问 `http://target/robots.php`，PHP 解析执行代码，页面输出命令结果（原文为 `ls` 的目录列表）。
5. 若需要进一步利用，可把命令换成读取 flag/落地更完整的 Webshell（同样避开英文括号与敏感词）。

## PoC

配置保存（表单字段名以“网站名称”实际字段为准，核心是让 `setConfig` 收到恶意值）：

```http
POST /admin/index.php?m=model_config&c=save HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
Content-Type: application/x-www-form-urlencoded

<site_name_field>=<?php echo `ls`;?>&...
```

首页生成（参数名来自源码 `$_POST['make_index_url']`）：

```http
POST /admin/index.php?m=cache&c=index HTTP/1.1
Host: target
Cookie: PHPSESSID=<admin-session>
Content-Type: application/x-www-form-urlencoded

make_index_url=../robots.php
```

验证：

```text
GET http://target/robots.php
# 页面输出 Web 根目录文件列表（原文为 admin/announcement/api/.../robots.php）
```

## 变体与关联

- **路径变体**：`make_index_url` 可指向其他可写且可执行的目录/文件名（如 `../shell.php`、子目录静态文件）；若目标有 Nginx 静态目录不解析 PHP，需要选到 PHP 可执行路径。
- **配置键变体**：除网站名称外，任何会进入首页模板渲染的配置值（标题、关键词、描述、统计代码等）都可作为 PHP 代码载体；`setConfig` 的“不存在则新增”还允许写入模板会读取的新键。
- **过滤绕过**：英文括号被转中文后，反引号命令执行、`<?=` 短标签、无括号语言结构、编码/拼接等都可尝试；敏感词替换可被大小写/注释/拼接绕过（需按目标过滤实现调整）。
- **同类 CMS 后台写马**：PbootCMS 站点信息 + 动态缓存 copy 写马见 [[web-php-rce-pbootcms-backend-siteinfo-copy-webshell]]；CmsEasy 第三方 header/footer 写 PHP 见 [[web-php-rce-cmseasy-thirdparty-header-footer-write-php]]；SeaCMS admin_ping 设置项拼接写 PHP 见 [[web-php-rce-seacms-admin-ping-post-write-php-code]]；Discuz saveconfig 键注入见 [[web-php-discuz-utility-convert-saveconfig-key-injection-webshell]]。

## 检测与防御

- **检测（Web 日志）**：后台 `m=model_config&c=save` 请求中出现 `<?php`、反引号、`echo`、`eval` 等；随后 `m=cache&c=index` 的 `make_index_url` 含 `../` 或指向 `.php` 文件；短时间内“保存配置 → 生成首页 → 访问新 PHP 文件”的连续行为。
- **检测（文件）**：Web 根目录出现非预期的新 `.php`/`.html` 文件；首页生成目录之外出现静态文件；文件内容含站点配置与 PHP 代码混合；`robots.php` 等非常规文件被创建/修改。
- **防御**：`setConfig` 对键名做白名单，只允许预定义配置项；`make_index_url` 做路径规范化与目录白名单（禁止 `../`、绝对路径、`.php` 后缀）；`webindex` 写入前校验目标路径必须位于静态生成目录；对可写目录禁用 PHP 解析（Nginx `location ~ \.php$` 限制）；后台强口令与访问控制；文件完整性监控。
