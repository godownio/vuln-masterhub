---
id: web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass
title: 禅道 api debug 接口 getMethod 文件包含：filePath 经 safe64 解码，../xxx.php/foo.txt 绕过 basename
type: scenario
domain: web
path: web/php/file-inclusion
technique: zentao-api-debug-getmethod-file-inclusion
tags:
- php
- zentao
- file-inclusion
- lfi
- api
- basename-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V635
  verified_at: '2026-11-13T01:08:38+08:00'
  notes: 已对照原文与 img/14 核对：api debug($filePath,$action) 先 helper::safe64Decode 再按 extendModel/extendControl 调 api->getMethod；原文明确给出 ../xxx.php/foo.txt 绕过 basename 的结论，但未给完整请求与 getMethod 源码，卡内对 basename/include 细节的解释属按原文结论重建，confidence=medium 合理，PoC 未执行。原文未标注受影响版本，affected_versions 留空正确。dedup：库内无其他禅道 api debug 文件包含卡，非重复。
url: /docs/web/php/file-inclusion/web-php-file-inclusion-zentao-api-debug-getmethod-basename-bypass/
draft: false
kb_aliases:
- 禅道文件包含
- zentao api debug LFI
- zen tao getMethod include
- 禅道 api-debug basename 绕过
---

## 一句话结论

禅道 `api` 控制器的 `debug($filePath,$action)` 把请求里的 `filePath` 做 safe64 解码后交给 `$this->api->getMethod()` 加载文件，`getMethod` 的 basename 校验可用 `../xxx.php/foo.txt` 这类路径绕过，从而包含任意本地 PHP 文件；配合上传/日志写入即可升级为 RCE。

## 原理

- **入口**：`module/api/control.php` 的 `debug()`：`$filePath = helper::safe64Decode($filePath);`，随后 `if($action == 'extendModel') { $method = $this->api->getMethod($filePath, 'Model'); } elseif($action == 'extendControl') { $method = $this->api->getMethod($filePath); }`。
- **包含点**：`getMethod` 按传入路径 include 目标文件（此前已被报过文件包含）。其 basename 校验只取路径最后一段：`../xxx.php/foo.txt` 的最后一段是 `foo.txt`，通过校验，而包含解析落到 `../xxx.php`——原文给出的 basename 绕过方式。
- **为什么可打**：`filePath` 由攻击者完全控制且仅做 base64 解码；该 debug 接口又可通过 17.x 鉴权异常绕过或伪造会话在未授权状态下到达，构成完整 LFI。
- **为什么是文件包含而非仅读取**：`getMethod` 的用途就是加载控制器/模型 PHP 文件，路径进入 include；包含任意 PHP 文件即执行其中代码，因此是 LFI→RCE 原语。
- **边界**：需要目标存在可被包含的 PHP 文件；直接用 `..` 若被其它过滤限制，需按版本核对 `getMethod` 的完整校验逻辑；原文只给出一句绕过结论与入口截图，未给出完整请求。

## 触发条件

- `api` 模块 `debug` 方法可路由；能到达该接口（登录、伪造会话或 17.x 鉴权绕过）。
- `filePath` 可传任意 safe64 字符串；服务器存在恶意/可写 PHP 文件（上传、日志、session 文件等）。

## 利用步骤

1. 准备可包含的 PHP 文件（上传图片马、写访问日志、构造 session 文件）。
2. 计算 `filePath = helper::safe64Encode("../xxx.php/foo.txt")`；safe64 即标准 base64 的 `+`→`-`、`/`→`_` 并去掉 `=`。
3. 请求 `index.php?m=api&f=debug&action=extendModel&filePath=<filePath>`（或 `action=extendControl`）。
4. 观察被包含文件的执行效果；失败时按版本调整 `../` 层数与后缀。

## PoC

```text
GET /zentao/index.php?m=api&f=debug&action=extendModel&filePath=<helper::safe64Encode("../xxx.php/foo.txt")>
```

```text
预期：getMethod 包含 ../xxx.php 并执行其中代码。
原文只给出“../xxx.php/foo.txt 绕过 basename”这一句与入口代码截图，未给完整请求；
本 PoC 按代码与原文描述重建，未在真实目标执行。
```

## 变体与关联

- 15.x 的 RCE 直接复用本文件包含（原文：“rce 可以用上面的文件包含”）。
- 到达本接口的两条路：17.x 异常鉴权绕过 [[web-generic-auth-zentao-endresponse-exception-deny-continue]]、会话伪造 [[web-php-rce-zentao-captcha-session-repo-checkconnection-exec]]。
- 同产品另有后台路径穿越删除（入口与根因不同）：[[web-php-zentao-backup-editor-arbitrary-file-delete]]。
- 变体：`action=extendControl` 走不带 `Model` 参数的 `getMethod`；不同版本 include 前的过滤/拼接不同；若可写文件路径固定，可改为日志包含或 `/proc/self/environ` 等。

## 检测与防御

- 检测：`m=api&f=debug` 请求；`filePath` 为 base64url 且解码后含 `../`、`.php/` 片段；随后出现 include 报错、异常页面或新进程。
- 修复：debug 接口仅管理员可用；`getMethod` 用 `realpath()` 约束在模块根目录内并拒绝 `..`；不要 include 用户输入。
- 加固：禁用/限制 api debug；上传目录不可执行且不在 include 路径；开启 open_basedir 收窄可包含范围。
