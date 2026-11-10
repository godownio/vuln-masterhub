---
id: web-generic-file-upload-graphql-uploadpaste-filename-traversal-write
title: GraphQL uploadPaste 任意文件写入：filename 直接拼 WEB_UPLOADDIR，../../../tmp/pwn 写出上传目录
type: scenario
domain: web
path: web/generic/file-upload
technique: graphql-upload-mutation-filename-traversal-write
tags:
- graphql
- file-upload
- path-traversal
- arbitrary-file-write
- mutation
- dvga
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V304
  verified_at: '2026-11-08T11:53:02+08:00'
  notes: 已对照 content.md 与 img29-32 核对：uploadPaste(filename,content)、正常写入 /opt/dvga/pastes/MyFile、filename=../../../tmp/pwn 写出上传目录、save_file 源码 f=open(WEB_UPLOADDIR+filename,'w') 无校验，均与原文一致。未验证点：原文只验证到 /tmp 写入，未继续升级 RCE；卡片中覆盖 authorized_keys/cron 为延伸推演。
url: /docs/web/generic/file-upload/web-generic-file-upload-graphql-uploadpaste-filename-traversal-write/
draft: false
kb_aliases:
- GraphQL 任意文件上传
- uploadPaste 路径遍历
- 文件名未校验
- WEB_UPLOADDIR 拼接
- DVGA uploadPaste
- 任意文件写入
---

## 一句话结论

GraphQL 的 `uploadPaste(filename, content)` mutation 在服务端执行 `open(WEB_UPLOADDIR + filename, 'w')` 写文件，`filename` 未做 `basename`/路径校验；把文件名改成 `../../../tmp/pwn`，文件就被写到 `/tmp/pwn`（文章 DVGA 复现），属于可写任意路径的任意文件写入，进一步可覆盖配置/计划任务/公钥等造成 RCE。

## 原理

- **mutation 暴露文件写能力**：schema 中 `uploadPaste` 接收 `filename: String!` 与 `content: String!`，resolver 调用 `save_file(filename, text)`；文章源码为 `f = open(WEB_UPLOADDIR + filename, 'w')`，直接把用户提供的文件名拼到上传目录后。
- **没有路径规范化/边界检查**：未调用 `os.path.basename`、未拒绝 `../`、未用 `os.path.realpath` 校验最终路径仍在上传目录内；`../../../tmp/pwn` 中的 `..` 逐级跳出 `WEB_UPLOADDIR`，`open` 会解析相对路径并写入目标位置（Linux 下可写任意当前用户有权限的路径）。
- **为什么危险**：任意文件写入可覆盖 Web 根目录下的脚本/模板（若进程有权限）、写入 `authorized_keys`/cron/`~/.bashrc`、覆盖应用配置或库文件，进而代码执行/持久化；即使只能写临时目录，也可作为后续利用的落地载体。
- **与普通上传的区别**：不需要 multipart 上传，GraphQL mutation 直接传字符串文件名/内容；很多 GraphQL 网关只关注 query 复杂度/鉴权，不会对 mutation 参数做文件名安全校验。
- **文章验证**：先传 `filename:"MyFile"`、`content:"BlahBlahBlah"`，在 `/opt/dvga/pastes/MyFile` 看到内容；再把 filename 改为 `../../../tmp/pwn`，文件出现在 `/tmp`，确认穿越成功。

## 触发条件

- GraphQL schema 暴露文件写入类 mutation（upload/import/export/backup 等），且接收用户可控文件名/路径。
- resolver 直接拼接文件名到固定目录，未做 `basename`、`../` 过滤、realpath 边界校验；运行账户对目标路径有写权限。
- 攻击者可通过 introspection/字段建议发现该 mutation，并可发送自定义 GraphQL 请求。
- 目标为 Linux/Unix 路径（Windows 下也可用 `..\..\` 穿越，但路径语法不同）。

## 利用步骤

1. introspection/schema 中找到文件写入 mutation（如 `uploadPaste(filename, content)`），确认参数与返回。
2. 先用正常文件名上传，确认文件落点（文章为 `/opt/dvga/pastes/MyFile`），并读取/观察返回内容。
3. 构造穿越文件名：`../../../tmp/pwn`（按目标上传目录深度调整 `../` 数量），content 写入测试字符串。
4. 发送 mutation，检查返回是否成功；通过其他手段（文件读取/命令执行/日志）确认 `/tmp/pwn` 存在。
5. 升级利用：尝试写入 Web 可访问目录的脚本/模板、`authorized_keys`、cron、systemd 单元、应用配置等；若权限不足，寻找进程可写目录/临时目录。
6. 清理测试文件，记录路径与权限，评估是否可进一步 RCE。

## PoC

```graphql
# 正常上传
mutation {
  uploadPaste(filename: "MyFile", content: "BlahBlahBlah") {
    result
  }
}

# 路径穿越：写到 /tmp/pwn
mutation {
  uploadPaste(filename: "../../../tmp/pwn", content: "pwned") {
    result
  }
}
```

```bash
# 服务端确认（文章环境）
ls -l /opt/dvga/pastes/MyFile /tmp/pwn
```

## 变体与关联

- 变体：绝对路径 `filename:"/tmp/pwn"`（若拼接后 `open` 接受绝对路径，会直接覆盖）；Windows 用 `..\\..\\..\\Windows\\Temp\\pwn`；URL 编码/双重编码绕过简单的 `../` 过滤。
- 变体：文件名使用空字节（旧语言/库）、超长名、符号链接/硬链接、`/proc/self/fd` 等技巧；或先上传到可预测路径再通过 LFI 包含。
- 变体：其他 mutation（import/export/backup/restore）也可能把路径参数拼进文件操作，测试思路相同。
- 关联：[[web-python-comfyui-impact-pack-upload-filename-traversal-startup-rce]]（上传文件名穿越到启动目录 RCE）、[[web-generic-file-upload-unauth-file-management-upload-read-delete]]（未授权文件管理接口）、[[web-generic-graphql-endpoint-discovery-schema-enumeration]]（发现 uploadPaste）、[[web-generic-graphql-importpaste-command-injection]]（同 schema 的另一危险 mutation）。

## 检测与防御

- 检测：审计所有文件写入 mutation 的 filename/path 参数，检查是否 `basename`/realpath 前缀校验；监控包含 `../`、绝对路径、编码穿越的文件名；对上传目录做文件完整性/异常文件监控。
- 防御：只接受随机生成的文件名/服务端 ID，不使用用户文件名；用 `os.path.basename` + `os.path.realpath` 校验最终路径位于上传目录内；限制可写目录权限与文件类型；禁止执行上传目录中的文件；对 mutation 做鉴权与输入校验。
- 说明：本文是 GraphQL mutation 任意文件写入（路径遍历）场景，severity 记为 high；仅用于授权测试。
