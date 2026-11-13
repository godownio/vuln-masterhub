---
id: binary-pwn-sandbox-escape-ghostscript-bcpe-filter-offbyone-arbitrary-write-pipe-rce
title: Ghostscript CVE-2023-28879：BCPEncode/TBCPEncode 转义双写越界过滤器缓冲区，链式过滤器绕过 ioerror 后堆泄漏 + 任意写清零 path_control_active 禁用沙箱，%pipe% 执行命令
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: ghostscript-bcpe-filter-offbyone-arbitrary-write-sandbox-disable
aliases:
- CVE-2023-28879
- Ghostscript RCE
- BCPEncode 越界写
- TBCPEncode 过滤器
- path_control_active
- Ghostscript SAFER 沙箱逃逸
- '%pipe% 命令执行'
tags:
- ghostscript
- postscript
- sandbox-escape
- off-by-one
- heap-overflow
- arbitrary-write
- imagemagick
- rce
- cve-2023-28879
cve:
- CVE-2023-28879
severity: high
confidence: high
affected_versions: Ghostscript@(-∞, 10.01.1)；ghostscript@(-∞, 10.0.0~dfsg-11)（原文影响范围）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V573
  verified_at: '2026-11-12T10:43:57+08:00'
  notes: 已对照原文(544行)与10图逐张核对：图01/02 gdb 崩溃于 stream.c:931 s_process_write_buf 与 s_CFE_process memcpy；图03/04 pwndbg 显示 stream 字段被 0x4343/0x4444/0x4545/0x4646 覆盖、procs.process 指向 __libc_system 且以 'id' 为参数调用；图05 GS REPL leakMemory/leakAsString 测试；图06/07 sputs 以伪造 cursor 写 0xdeadbeefdeadbeef；图08 checksec(PIE/Canary/NX/FORTIFY) 与 offset.py 输出 .init=0x18d000、system@PLT-.init=0x1814(6164)、s_std_noseek-.init=0x119c80(1154176)；图09 完整利用输出 Base r-x/system@plt/process 并执行命令得 uid=0(root)；图10 -dSAFER 下 (%pipe%id)(w)file 回显 uid=1000(debian)。原文影响范围明确给出 Ghostscript@(-∞, 10.01.1) 与 ghostscript@(-∞, 10.0.0~dfsg-11)，已按原文 set-versions；正文 10.01.0及之前与之一致。dedup 报告 0 duplicate/0 likely_duplicate，候选均 new。核对修正：原文正文称从堆泄漏 libc 地址，但 offset.py/截图显示 final-poc 实以泄漏的 s_std_noseek 代码指针减 0x119c80 得 gs 基址再加 0x1814 得 system@plt，已在卡内改为准确表述并保留原文说法。未验证点：未复跑 final-poc.ps；frontmatter 无 sources/source_url。
---

## 一句话结论

Ghostscript ≤10.01.0 的 BCPEncode/TBCPEncode 过滤器在“写缓冲区只剩 1 字节且当前字节需要转义”时，会先写 `CtrlA` 再把字符 XOR 0x40 写入，造成写指针双递增并越过 `pw->limit`；由于 `nw = pw->limit - pw->ptr` 是无符号减法，剩余空间变成 `0xffffffff`，后续写不再受长度检查约束。用链式过滤器（BCPEncode + NullEncode）让大输入绕开 ioerror 后，越界写会覆盖相邻的 stream 结构：先泄漏堆地址与 `procs` 中的代码指针算出 gs 基址与 `system@plt`，再用同一原语任意写清空 `gs_lib_ctx->core->path_control_active` 禁用 SAFER 路径沙箱，最后通过 `(%pipe%cmd)(w)file` 执行任意命令。

## 原理

- **过滤器链模型**：PostScript 的 `filter` 是特殊文件对象，链式过滤器把数据从上游读到下游。每个中间流缓冲区最大 0x800；`swritebuf` 逐级调用 `(*curr->procs.process)(curr->state, pr, pw, end)`，并把读/写游标的 `limit - ptr` 作为剩余量传给下一级。
- **漏洞函数**：`base/sbcp.c` 的 `s_xBCPE_process`（BCPEncode/TBCPEncode 共用）对需要转义的字节写 `*++q = CtrlA; ch ^= 0x40;` 再写 `*++q = ch`。若 `p == rlimit`（读缓冲区最后一个字节）则回退并退出，但判断只针对读端；当写缓冲区剩余空间不足时，靠 `if (--wcount < rcount) end--;` 修正循环边界，存在差一错误。
- **为什么越界**：构造“写目标 4 字节字符串 + 读入 6 字节、最后一个是转义字符 0x13”即可让写端在缓冲区满 1 字节时触发双写：`q` 增加两次而 `wcount` 只减一次，`pw->ptr` 最终比 `pw->limit` 大 1。`nw = (uint)(pw->limit - pw->ptr)` 发生无符号下溢（调试输出为 `nw=4294967295`），下一次写被当成“有巨大空间”。
- **绕过 ioerror**：单流越界后下一写会因“文件已满”报 `/ioerror`；把 BCPEncode 串在 NullEncode（只搬数据不变换）之后，并一次写入超过 2048 字节，数据会先填满第一级、推进到第二级，第二级大缓冲区未满即可吞下全部数据；返回第一级时不再触发空间检查，越界写直接落入紧邻的 `stream` 结构。
- **堆布局与泄漏/任意写**：中间流结构在堆上连续分配，越界可覆盖当前 stream 的 `templat/memory/report_error/min_left/error_string/cursor/procs` 等字段。覆盖 `cursor->r->ptr`/`limit` 可让下一级把堆内存当数据复制到输出（如 ASCIIHexEncode 转十六进制打印），泄漏堆地址与 `procs` 中的代码指针（原文称 libc 地址；final-poc 实际以泄漏的 `s_std_noseek` 指针减偏移得 gs 基址，再加 `system@plt` 偏移）；覆盖 `procs.process` 为 `system` 并在数据流中放入命令字符串即可直接调用；或通过 `sputs` 把数据写到伪造的 `cursor->w` 地址，实现任意地址写。
- **关闭沙箱**：`base/gpmisc.c` 的 `gp_validate_path_len` 开头检查 `mem->gs_lib_ctx->core->path_control_active == 0` 就直接放行。`gs_lib_ctx` 在堆上，泄漏堆地址后按固定偏移即可定位 `path_control_active`；用任意写清零后，`%pipe%` 设备不再被 SAFER 拦截，PostScript 可直接创建子进程执行命令。
- **攻击面**：ImageMagick 等程序把用户可控文件交给 Ghostscript 解析（PS/EPS/PDF 等委托）时，该链可由恶意文档触发远程命令执行。

## 触发条件

- Ghostscript 版本 ≤10.01.0（原文影响范围 `Ghostscript@(-∞, 10.01.1)`、Debian `ghostscript@(-∞, 10.0.0~dfsg-11)`），未打 CVE-2023-28879 补丁。
- 攻击者能提交 PostScript/被委托给 Ghostscript 解析的文件（如 ImageMagick 的 PS/EPS/PDF 处理链）。
- 目标进程可访问堆布局稳定的运行环境（PIE/ASLR 存在，但堆地址与代码指针（`s_std_noseek`）可通过本漏洞泄漏；偏移随启动参数固定）。
- 需要多次尝试的场景：转义字符表限制导致某些字节不能出现在写入数据中，堆地址含被禁字节时需重启利用几次。

## 利用步骤

1. 复现环境：编译 Ghostscript 10.01.0（`./configure && make && make install`），用 `./bin/gs -Zs` 观察 `swritebuf` 调试输出确认 `nw` 下溢。
2. 用最小 PoC 验证越界：4 字节写目标字符串 + `/BCPEncode filter`，写入 6 字节且末字节为转义字符（如 `<414141134141>`），`flushfile` 后看到 `after write ... nw=4294967295`。
3. 确认可利用性：把 BCPEncode 与 NullEncode 串联，输入构造为“2045 个 `A` + 转义字符 `0x13` + 若干填充字符”，使越界写落在相邻 stream 结构；随后按 `revision` 选择填充数量（原理与 final-poc 中的 15/23 分支一致）。
4. 泄漏：覆盖 `cursor->r->ptr` 等字段，让下一级把堆内容输出，经 ASCIIHexEncode 转成十六进制字符串读回，得到 BCPE stream 地址与 `procs` 中的代码指针（`s_std_noseek`）。
5. 计算目标地址：用 ELF 工具得到 `.init`、`system@PLT`、`s_std_noseek` 的偏移（原文 10.01.0 为 `system@plt - .init = 0x1814 (6164)`、`s_std_noseek - .init = 0x119c80 (1154176)`），由泄漏出的基址算出 `system@plt`、目标 stream 与 `path_control_active` 地址（原文按 `-375/+383`、`+111`、`+81`、`+64`、`231` 等固定偏移）。
6. 任意写：再次触发越界，伪造 `cursor->w->ptr/limit` 与 `procs`，用 `sputs` 把 0 字节写到 `path_control_active`，或直接把 `procs.process` 改成 `system` 并让数据流携带命令。
7. 执行命令：`(%pipe%id)(w)file` 或 `(%pipe%id)(w)file` 写入即可在沙箱被关闭后执行；原文验证 `system("id")` 回显与 `-dSAFER` 下 `%pipe%` 命令执行。
8. 失败排查：`-Zs` 看 `nw` 是否下溢、过滤器深度是否按预期推进、堆地址是否含被转义表禁止的字节（需重启重试）。

## PoC

```postscript
% 最小越界触发器：写目标 4 字节，读入 6 字节，末字节 0x13 为转义字符
/writtenTo {4 string} def
/theFilter writtenTo /BCPEncode filter def
/readsFrom <414141134141> def
theFilter readsFrom writestring
theFilter flushfile
```

```text
# 调试输出应出现（越界证据）
[s]write process ...(stream_state), nr=6, nw=4, end=0
[s]after write ..., nr=2, nw=4294967295, end=0, status=1
```

```text
# 完整利用（原文 final-poc.ps 思路，核心原语）
# 1) createOverflow: 2045*<41> + <1313> + 填充 B
# 2) leakMemory/leakAsString: 覆盖 cursor 读出堆地址与 gs 代码指针
# 3) writewhatwhere: 用 sputs 写任意地址
# 4) 清零 path_control_active 后：
(%pipe%id)(w)file
```

完整 `final-poc.ps` 需要按目标二进制用 ELF 偏移脚本生成（原文 `offset.py` 读取 `.init`/`system@PLT`/`s_std_noseek` 并替换模板占位符），并可在 `s->templat` 位置替换为要执行的命令 ASCII（原文为 `id`）。文章 PoC 在 Ghostscript 10.01.0 上实测 `system("id")` 与 `%pipe%id` 回显成功；本次未复跑。

## 变体与关联

- 变体：BCPEncode 与 TBCPEncode 共用 `s_xBCPE_process`、转义字符表不同，均受影响；CVE 描述同时点名 BCPDecode/TBCPDecode 组件，分析时可换用不同过滤器组合触发。
- 变体：不覆盖 `procs.process` 时，也可通过伪造读写游标实现任意读/任意写，先泄漏 gs 基址再覆盖 `path_control_active`；`-dSAFER` 是默认开启的，但漏洞路径直接改内存状态，不依赖配置。
- 关联：ImageMagick 等以委托方式调用 Ghostscript 处理用户文件是常见触发面（参见 [[web-generic-file-upload-svg-imagemagick-text-protocol-file-read]] 对 ImageMagick 委托与文件读取的讨论）；同类“语言解释器沙箱靠内存破坏关闭”可对照 [[binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure]]。
- 边界：打好补丁、禁用 PS/EPS/PDF 委托、以低权限/强沙箱运行 Ghostscript 时风险显著降低；如果输入不能到达 Ghostscript（例如 policy.xml 已禁用对应格式），本链不成立。

## 检测与防御

- 检测：PostScript 输入中出现大量 `filter` 链（同一条表达式里反复 `/BCPEncode filter`、`/TBCPEncode filter`、`/NullEncode filter`）与 `closefile`；`-Zs`/调试日志出现 `nw=4294967295` 或 `nw` 异常巨大；进程对 `%pipe%` 的创建/子进程行为；Ghostscript 版本低于 10.01.1。
- 防御：升级到 10.01.1 及以上；在 ImageMagick `policy.xml` 禁用 PS/EPS/PDF 等委托格式；不要以 root 运行 Ghostscript；对不可信文档使用容器/低权限用户处理；开启 seccomp/AppArmor 限制子进程创建。
- 响应：排查 Ghostscript 处理过的上传文件与 `%pipe%` 子进程；检查进程是否加载了用户上传的 PS/EPS 文件；记录版本与补丁状态。
