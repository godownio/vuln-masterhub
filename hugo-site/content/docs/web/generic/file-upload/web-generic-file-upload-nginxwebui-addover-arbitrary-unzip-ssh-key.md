---
id: web-generic-file-upload-nginxwebui-addover-arbitrary-unzip-ssh-key
title: NginxWebUI 后台任意文件上传 + addOver 任意解压目录：把 authorized_keys 解压进 ~/.ssh 获得 SSH 登录
type: scenario
domain: web
path: web/generic/file-upload
technique: nginxwebui-addover-arbitrary-unzip-ssh-key
tags:
- java
- nginxwebui
- file-upload
- zip
- unzip
- authorized-keys
- ssh
- persistence
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: 3.9.8（原文审计版本；原文称 3.9.9 未修复这些点）
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:41:01+08:00'
  notes: 已对照原文图01-11核对；main/upload 任意文件落 tmpdir、addOver dir 可控、ZipUtil.unzip 解压 authorized_keys 到 ~/.ssh 均一致；affected_versions=3.9.8 原文明确（称 3.9.9 未修复）
url: /docs/web/generic/file-upload/web-generic-file-upload-nginxwebui-addover-arbitrary-unzip-ssh-key/
draft: false
kb_aliases:
- NginxWebUI 任意解压
- 静态网页上传写 SSH 公钥
- MainController upload
- WwwController addOver
---

## 一句话结论

NginxWebUI 后台的 `adminPage/main/upload` 只在前端限制“只能上传 zip”，后端把任意文件按原始文件名存进 `System.getProperty("java.io.tmpdir")` 并返回临时路径；随后的静态网页上传功能 `adminPage/www/addOver` 允许提交任意 `dir` 作为解压目标，内部直接 `ZipUtil.unzip(dirTemp, www.getDir())`。攻击者上传内含 `authorized_keys` 的 zip，把 `dir` 设为 `~/.ssh/`，即可把公钥解压进目标用户的 SSH 目录，之后用私钥直接登录。

## 原理

- **上传落点**：`MainController#upload` 执行 `new File(FileUtil.getTmpDir() + File.separator + file.getName().replace("..", ""))` 后 `file.transferTo(temp)`，返回 `temp.getPath()`。`FileUtil.getTmpDir()` 取 `java.io.tmpdir`（Linux 通常 `/tmp`，macOS 为 `/var/folders/.../T`）。前端只说“只能上传zip文件”，后端不校验扩展名或类型，任意内容都能落到临时目录。
- **解压落点可控**：`WwwController#addOver(Www www, String dirTemp)` 先用 `wwwService.hasDir(www.getDir(), www.getId())` 检查数据库里是否已有同 `dir` 的记录，没有则 `ZipUtil.unzip(dirTemp, www.getDir())`（异常时用 GBK 再解一次），随后 `FileUtil.del(dirTemp)` 并 `insertOrUpdate(www)` 入库。
- **为什么能写 ~/.ssh**：`www.getDir()` 完全来自请求的 `dir` 参数；设置成 `/home/user/.ssh/`（或 macOS 的 `/Users/user/.ssh/`），zip 内的条目名 `authorized_keys` 就会解压到该目录。第一次因为数据库没有该目录记录，检查通过。
- **为什么只成功一次**：同一 `dir` 第二次提交时 `hasDir` 查到记录并返回“路径重复”，解压不会执行；后续可换用未入库的目录或传已有记录的 `id` 绕过（见关联的 Zip Slip 卡）。
- **后利用**：写入 `authorized_keys` 后，用对应私钥 `ssh -i id_rsa user@target` 登录；若服务以 root 运行则可写 `/root/.ssh/`。该链把“上传 + 解压”两个普通后台功能组合成任意文件写入。

## 触发条件

- 目标为 NginxWebUI 3.9.8 左右版本，且攻击者已登录后台（默认口令/弱口令或其它后台入口）。
- `java.io.tmpdir` 可写，`~/.ssh` 目录存在且 Web 进程用户对该目录有写权限。
- 目标 sshd 允许公钥登录（默认通常允许）。
- zip 内的文件条目名能落在目标目录（`authorized_keys` 或带子路径）。

## 利用步骤

1. 登录后台，进入“静态网页上传”。
2. 用 `adminPage/main/upload` 上传内含 `authorized_keys`（内容为攻击者公钥）的 zip，记录响应里的临时路径（如 `/tmp/1.zip`）。
3. 调用 `adminPage/www/addOver`，`dir` 填目标用户 `.ssh` 目录（如 `/home/snake/.ssh/`），`dirTemp` 填上一步的临时路径；`id` 留空。
4. 确认 `.ssh/authorized_keys` 出现且权限可读。
5. 用对应私钥 SSH 登录验证。
6. 若需再次写入同目录，带上该目录在数据库中的 `id`，或换未使用的目录配合 zip 条目穿越。

## PoC

```http
POST /adminPage/main/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="1.zip"
Content-Type: application/zip

<zip 内含 authorized_keys>
------x--
```

```http
POST /adminPage/www/addOver HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=&dir=%2Fhome%2Fsnake%2F.ssh%2F&dirTemp=%2Ftmp%2F1.zip
```

## 变体与关联

- 变体：`dir` 指向 Web 根或其它可写目录，zip 内放 `.jsp`/`.php` 等脚本；或指向 `/etc/cron.d`、systemd 目录做持久化。
- 变体：macOS 的临时目录每次 shell 环境不同，需从上传响应读取实际路径；Linux 固定 `/tmp`。
- 关联：[[web-generic-file-upload-nginxwebui-addover-zipslip-hasdir-bypass]]（同一 addOver 的 Zip Slip 与重名检查绕过）。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 通用原理）。

## 检测与防御

- 检测：`adminPage/main/upload` 上传非 zip/非静态资源文件；`addOver` 的 `dir` 指向 `.ssh`、`/etc`、Web 根等敏感目录；`java.io.tmpdir` 出现攻击者文件后被解压删除。
- 检测：`.ssh/authorized_keys` 被创建/修改；sshd 日志出现新公钥登录。
- 防御：上传后端校验类型并重命名，临时文件及时清理；解压目标目录固定为服务端配置，禁止用户指定；对 `dir` 做白名单与 `realpath` 校验；限制后台访问与默认口令；Web 进程低权限运行。
