---
id: defense-hardening-elf-symbol-interposition-mitigation
title: ELF 同名符号替换的分层加固：hidden、RTLD_LOCAL、-Bsymbolic 与 AT_SECURE 的边界
type: scenario
domain: defense
path: defense/hardening
technique: elf-symbol-interposition-hardening
tags:
- linux
- hardening
- elf
- dynamic-linking
- visibility
- rpath
- suid
- symbol-resolution
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:30:04+08:00'
  notes: 已对照原文与19张图核对：hidden 不导出、RTLD_LOCAL、-Bsymbolic-functions、AT_SECURE 忽略 LD_PRELOAD、suid+可写绝对 RUNPATH 加载恶意库 constructor euid=0 且 verify_security=0xdead、RUNPATH=$ORIGIN 在 secure 下加载失败均出自原文第六章；四路证据与受限边界一致。未验证点：未实际构建 suid 环境复现；frontmatter 无 sources/source_url。
url: /docs/defense/hardening/defense-hardening-elf-symbol-interposition-mitigation/
draft: false
kb_aliases:
- 防 LD_PRELOAD 符号顶替
- hidden 可见性加固
- RTLD_LOCAL 加固
- -Bsymbolic-functions 防穿透
- AT_SECURE 与 RUNPATH
- 符号裁决加固
---

## 一句话结论

防同名符号被顶替必须分层：`hidden` 可见性管住本库导出、`RTLD_LOCAL` 管住 `dlopen` 全局作用域、`-Bsymbolic-functions` 管住库内部调用、`AT_SECURE` 管住环境变量；任何一层单独使用都只堵一条路径，尤其 setuid 程序配合可写的绝对 `RUNPATH` 仍会在 root 权限下加载恶意库。

## 原理

glibc 的符号裁决有四个可被外部影响的输入：主程序导出、`LD_PRELOAD`、`DT_NEEDED` 顺序、`dlopen` 时机。对应的加固点各管一段：

- **`visibility("hidden")`**：符号不进入 `.dynsym`，预加载库即使提供同名定义也没有裁决对象。实测：对旧库同名函数加 hidden 后预加载，程序仍调用新实现（输出 1）。它只保护“本库不希望被外部替换的符号”，不改变其它库或主程序的符号。
- **`RTLD_LOCAL`**：`dlopen` 加载的库只服务自身依赖，不加入全局搜索列表，因此不能参与全局同名裁决。实测：启动期依赖新库、运行期 `dlopen` 旧库并指定 `RTLD_LOCAL`，输出仍为 1。它只管 `dlopen` 这一条道，管不了 `LD_PRELOAD` 与 `DT_NEEDED`。
- **`-Wl,-Bsymbolic-functions`**：库内部对全局函数的引用从 `call foo@plt` 改为直连本模块地址，外部预加载无法穿透库内部调用。实测：普通库的 `verify_wrapped` 调 `verify_security` 被预加载打穿（输出 0），Bsymbolic 版守住（输出 1）。它只管库内部，程序入口与跨库调用仍按全局顺序。
- **`AT_SECURE`**：setuid/setgid 程序启动时内核设置 secure 标志，加载器忽略 `LD_PRELOAD`、`LD_LIBRARY_PATH`、`LD_DEBUG` 等环境变量。实测：普通用户跑 suid 程序，带不带注入都输出 1；同一用户跑非 suid 副本，注入照常生效输出 0。
- **`AT_SECURE` 的残余**：secure 模式不会改写 ELF 内写死的 `DT_RPATH/DT_RUNPATH`。若 suid 程序的绝对 `RUNPATH` 指向普通用户可写目录，攻击者放入同名恶意库，程序启动即加载，构造函数在 `euid=0` 下执行（实测 `verify_security=0xdead`、`euid=0`）。反过来，`RUNPATH=$ORIGIN` 在 secure 模式下不会被展开，加载失败——不能把它当成“安全的绝对路径”。
- 这说明加固必须按“所有可影响裁决顺序的输入”收敛，而不是只修其中一层。

## 触发条件

- 防守方拥有二进制/库的构建控制权，或要对现成 suid 程序做加固审计；
- 目标是动态链接的 ELF，且存在需要保护的关键符号（校验、鉴权、加密、日志等）；
- 需要同时考虑 setuid/setgid、dlopen、库内部调用与 `RPATH/RUNPATH` 四类场景。

## 利用步骤

1. **标注关键符号**：对不希望被外部替换的函数加 `__attribute__((visibility("hidden")))`，并确认它不再出现在 `readelf --dyn-syms` 中；若必须导出，改用来源校验/签名。
2. **限制 dlopen 作用域**：运行期加载插件/扩展库时使用 `RTLD_NOW | RTLD_LOCAL`，避免其符号进入全局作用域。
3. **本地绑定内部调用**：编译库时加 `-Wl,-Bsymbolic-functions`，使库内部引用不经过 PLT；用 `objdump -d` 确认调用从 `@plt` 变为本地地址。
4. **保持 secure 执行环境**：setuid/setgid 程序不要通过 wrapper 先降权再 exec，也不要清理/伪造 secure 标志；确保关键服务不以 root 权限接受用户可控环境变量。
5. **审计 ELF 内路径**：`readelf -d <suid-bin> | grep -E "RPATH|RUNPATH"`，任何指向普通用户可写目录的绝对路径都要修复；`$ORIGIN` 在 secure 模式下不可依赖，但也不能作为唯一防线。
6. **回归验证**：按下列组合逐一测试并记录输出，确认每条路径都被堵住。

## PoC

```bash
# 1) hidden：旧库同名符号不导出，预加载无效
__attribute__((visibility("hidden")))
int verify_security(void) { return 0; }
# 预加载 libB_hidden.so 后程序仍输出 1

# 2) RTLD_LOCAL：运行期 dlopen 旧库不参与全局裁决
# prog_dl_local.c: dlopen("./libB_old.so", RTLD_NOW | RTLD_LOCAL)
./prog_dl_local          # verify_security = 1（from libA_new.so）

# 3) -Bsymbolic-functions：库内部调用不走 PLT
gcc -shared -fPIC -O0 -Wl,-Bsymbolic-functions -o libA_new_bs.so libA_new.c
./prog_wrap              # 普通库：verify_wrapped = 0（被 preload 打穿）
./prog_wrap_bs           # Bsymbolic：verify_wrapped = 1（守住）

# 4) AT_SECURE：suid 程序忽略 LD_PRELOAD
su testuser -c 'LD_PRELOAD=./libB_old.so ./prog_single_abs_suid'   # 输出 1
su testuser -c 'LD_PRELOAD=./libB_old.so ./prog_single'            # 非 suid：输出 0

# 5) 残余：suid + 可写绝对 RUNPATH
readelf -d ./prog_suid_world | grep RUNPATH    # RUNPATH 指向 0777 的 world/
cp /tmp/libA_evil_ready.so ./world/libA_new.so
./prog_suid_world        # 构造函数以 euid=0 执行，verify_security = 0xdead
```

## 变体与关联

- `LD_PRELOAD` 之外还有 `DT_NEEDED` 顺序与 `RPATH/RUNPATH` 两条路径；`hidden`/`Bsymbolic` 不解决依赖图被替换的问题，需要依赖锁定与源校验。
- 静态链接或 `-Wl,-z,now` 只改变绑定时机/方式，不改变“先到先得”的裁决顺序；`-z now` 不能防同名符号顶替。
- 关联卡片：[[pentest-privilege-escalation-suid-shared-library-path-hijack]]、[[pentest-privilege-escalation-ld-preload-symbol-interposition-downgrade]]、[[pentest-privilege-escalation-dt-needed-symbol-order-hijack]]、[[defense-forensics-elf-symbol-interposition-triage]]。

## 检测与防御

- 检测：对 suid 程序做 `readelf -d` 基线，标记可写 `RPATH/RUNPATH` 或缺失 `RUNPATH` 的二进制；监控 suid 进程从非系统路径加载 `.so`（`/proc/<pid>/maps`、auditd `mmap`）；监控可写目录中新出现的 `.so`。
- 防御：库目录 root 独占、0755；`/tmp`、用户可写分区用 `nosuid` 挂载；关键服务不使用用户可控环境变量；启用 `no_new_privs`、SELinux/AppArmor 限制 SUID 程序的库加载；对 ELF 做签名/哈希校验。
- 注意：不要只做 `LD_PRELOAD` 防护就认为安全；本卡实测显示 suid + 可写绝对 `RUNPATH` 可以在完全不使用环境变量的情况下加载恶意库。
