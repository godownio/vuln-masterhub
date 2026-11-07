---
id: web-php-rce-php2shell-oom-multipart
title: PHP OOM 清理路径堆破坏：恶意 multipart 请求触发未认证 RCE
type: scenario
domain: web
path: web/php/rce
technique: php-oom-multipart-heap-rce
tags:
- php
- rce
- oom
- heap-spray
- aslr
- multipart
- cve-2026-109618
cve:
- CVE-2026-109618
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: 5.4 ~ 8.5.11（修复：8.4.27、8.3.36、8.2.51 及以上）
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:50+08:00'
  notes: 已对照原文与5张图核对：CVE-2026-109618、php:8.4.26-apache、memory_limit=8M、zif=0x465370/dtor=0x65eb60/htdata=0x690d8、/out/p1 实执行验证、8.4.27 复测 HEAP_LEAK_FAILED 均一致；exploit.py 未公开，偏移量未独立复核；属完整 RCE 链，不因触发用 OOM 删除
url: /docs/web/php/rce/web-php-rce-php2shell-oom-multipart/
draft: false
kb_aliases:
- PHP2Shell
- CVE-2026-109618
- PHP OOM 堆破坏
- multipart 触发 RCE
---

## 一句话结论

PHP 内核在内存耗尽（OOM）的清理路径上，把未完全初始化的请求数据当成有效数据使用，恶意 `multipart/form-data` 请求可触发堆内存破坏；攻击者再通过堆喷与地址泄露绕过 ASLR，最终以 Web 进程权限执行任意命令，无需认证。

## 原理

- **触发点**：请求解析/上传进度处理阶段消耗内存，达到 `memory_limit` 触发 OOM；清理逻辑对尚未初始化完成的内部请求结构缺少合法性校验。
- **破坏方式**：清理阶段把攻击者可控的请求数据误当作有效结构，造成 PHP 进程堆上的对象/指针被破坏，形成可控的堆布局。
- **利用方式**：攻击者先进行堆喷（heap spray）布置可控数据，再利用信息泄露拿到堆 chunk 基址与 `libphp.so` 模块基址，计算 `zif_system` 等函数指针，伪造内核结构体完成调用，绕过 ASLR。
- **攻击面**：漏洞位于 PHP 请求处理链，攻击者只需向任意使用受影响 PHP 版本的 Web 入口发送 HTTP 请求，不需要账号、文件上传或额外端口。
- **不确定性**：公开分析只描述了高层链路与利用脚本输出，未给出补丁 diff 和伪造结构体细节；受影响版本范围、修复版本与具体偏移量应以官方公告和本地验证为准，不要仅凭单一文章下结论。

## 触发条件

- 运行受影响的 PHP 版本（按披露：5.4 至 8.5.11；修复版本包括 8.4.27、8.3.36、8.2.51 及以上）；
- `memory_limit` 较低或请求可造成内存快速耗尽（实验环境设为 8M）；
- 上传进度监控等请求处理路径可用（临时缓解项指向 `session.upload_progress.enabled`）；
- Web 服务使用受影响的 SAPI（实验为 Apache + mod_php 的 `php:8.4.26-apache` 镜像）；
- 攻击者能向应用发送任意 multipart 请求，且网络延迟/时序足够稳定。

## 利用步骤

1. 指纹识别目标 PHP 版本与 SAPI，确认落在受影响区间；
2. 使用公开利用脚本向目标 URL 发送构造好的 multipart 请求，触发 OOM 与堆破坏；
3. Stage 1：泄露堆 chunk 基址（案例示例 `0x7f5111a00000`）；
4. Stage 2：读取 `libphp.so` 模块基址，计算 ASLR 偏移；
5. Stage 3：定位 `zif_system` 与析构函数指针（案例中 8.4.26 构建的 `zif=0x465370`，偏移强绑定版本）；
6. Stage 4：伪造结构体并触发调用，执行命令（如 `id`）并将结果写入文件或回显；
7. 进入容器/主机验证命令确实由 Web 用户执行，排除脚本虚假回显。

## PoC

原文使用公开脚本，未给出脚本内容；可复现的调用形态如下：

```text
python exploit.py -u http://127.0.0.1:8088/index.php
```

脚本输出关键阶段：

```text
stage 1: heap leak -> chunk base = 0x7f5111a00000
stage 2: libphp leak -> libphp base = 0x7f51136d3000
stage 3: HTDATA/ZIF -> ZIF=0x7f5113b38370
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

请求本质是纯 HTTP 的 multipart 流量，不依赖上传恶意文件；具体 boundary、字段与堆喷布局需按目标版本调整，不能跨版本复用偏移。

## 变体与关联

- 变体：不同 SAPI（PHP-FPM、Apache mod_php）与不同小版本的偏移量不同，利用脚本需重新适配；同类“异常清理路径使用未初始化数据”的缺陷也可能出现在其他请求解析场景。
- 关联：[[web-php-file-inclusion-thinkphp-view-template]]（PHP 应用层 RCE 的另一种入口）；[[defense-forensics-multisource-timeline-log-clear]]（入侵后的日志与进程取证）。
- 注意：案例中的 `zif=0x465370` 只对应其构建的 PHP 8.4.26，不能作为通用地址。

## 检测与防御

- **优先修复**：升级到官方修复版本（8.4.27、8.3.36、8.2.51 及以上）；无法确认版本时按官方公告核对。
- **临时缓解**：`session.upload_progress.enabled = Off` 并重启 PHP-FPM/Apache，可阻断该触发入口；这只是缓解，不能替代升级。
- **配置**：不要把 `memory_limit` 设得过小；关闭不需要的上传进度功能；限制请求体大小与并发。
- **运行时检测**：监控 PHP/Apache 进程 SIGSEGV、异常 core dump、worker 反复崩溃；审计 `www-data`/`apache` 用户派生的 `sh`、`bash`、`id` 等非预期子进程；关注短时间大量 multipart 请求与异常内存增长。
- **隔离**：容器化运行、非 root、只读文件系统、seccomp/AppArmor 限制，降低 RCE 后的影响；但 ASLR 与容器不能阻止该漏洞本身。
- **WAF 局限**：攻击是合法 multipart 结构下的内存破坏，基于签名的 WAF 难以稳定拦截，不能作为主要防御。
