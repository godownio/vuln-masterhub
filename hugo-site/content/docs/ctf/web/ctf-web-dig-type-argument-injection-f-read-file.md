---
id: ctf-web-dig-type-argument-injection-f-read-file
title: dig 命令参数注入：type 字段传入 -f/flag 把目标文件当作查询批处理读取
type: scenario
domain: ctf
path: ctf/web
technique: dig-option-injection-f-file-read
tags:
- ctf
- command-injection
- argument-injection
- dig
- cli
- file-read
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:32+08:00'
  notes: 已对照原文核对：web 签到 dig 参数注入，type 传 -f/flag 与原文 curl 请求一致，dig -f 批处理读文件机制相符；PoC 未在本机复跑；单动作无拆分问题
url: /docs/ctf/web/ctf-web-dig-type-argument-injection-f-read-file/
draft: false
kb_aliases:
- dig -f 读文件
- dig 参数注入
- 命令参数注入
- type 字段注入选项
---

## 一句话结论

Web 后端若把用户可控字段（如 DNS 查询类型 `type`）原样拼进 `dig` 命令行，攻击者传入 `-f/flag` 即可把目标文件当成 dig 的批处理查询文件读取，文件内容会随查询解析/报错输出泄露；本题据此直接读出 flag。

## 原理

- `dig` 支持 `-f filename` 选项，表示从文件读取一批查询语句（batch mode），而不是从命令行取查询名。
- 参数解析遵循 getopt 风格，`-f/flag` 会被拆成选项 `-f` 与值 `/flag`，因此只要用户可控值出现在选项位置，就可以注入任意 dig 选项。
- 后端常见写法是把 `type` 与 `domain` 拼成 `dig <type> <domain>`；正常业务只期望 `A`、`AAAA`、`MX` 等类型，但没有校验值不能以 `-` 开头。
- 文件被当作查询文件后，其内容会进入 dig 的解析流程，解析错误、查询回显等输出会带回文件片段，形成文件读取；若后端用 shell 字符串拼接，同一入口还可能升级为命令注入。

## 触发条件

- 存在接收 DNS 查询参数并由服务端调用 `dig` 的功能（如 DNS 查询工具、拨测接口）。
- 用户可控值被放在命令行选项位置，且未校验 `-` 前缀或未使用 `--` 终止选项解析。
- dig 可读取目标文件（进程权限足够，flag/配置可读）。

## 利用步骤

1. 抓取 DNS 查询接口请求，确认 JSON 字段名与后端调用方式（本题为 `type`、`domain`）。
2. 把 `type` 改为 `-f/flag`（或 `-f/etc/passwd` 验证），`domain` 保持合法域名以通过前置校验。
3. 观察响应：dig 把 `/flag` 当批处理文件读取，文件内容出现在输出/错误信息中。
4. 若一次只回显部分，可用其他 dig 选项或分次读取拼接。

## PoC

```bash
curl -H "Content-Type: application/json" -X POST \
  --data '{"type":"-f/flag", "domain":"www.aliyunctf.com"}' \
  http://target/digHandler
```

## 变体与关联

- 变体：其他支持文件/配置选项的 CLI 同样可参数注入，如 `curl -K <file>`、`wget -i <file>`、`tar -T <file>`、`ssh -F <file>`、`openssl -config <file>`。
- 变体：若后端使用 shell 拼接而非 execve 数组，参数注入可进一步用 `;`、`$()`、反引号升级为命令执行；CLI 选项注入的同类案例见 [[pentest-privilege-escalation-cp-option-injection-symlink-read]]。
- 边界：后端若只允许枚举值（A/AAAA/MX/TXT）或使用 `--` 终止选项，则注入不成立。

## 检测与防御

- 修复：不要拼接用户输入到命令行；使用参数数组执行并校验参数不以 `-` 开头，或在命令行中加入 `--` 终止选项解析。
- 加固：对 `type` 使用枚举白名单（A、AAAA、CNAME、MX、TXT 等），禁止任意字符串。
- 检测：服务端日志中出现 `dig` 参数以 `-f`、`-k`、`-y` 等选项开头；异常的文件读取路径。
