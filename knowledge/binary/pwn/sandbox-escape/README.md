# 沙箱逃逸

## 这层是什么

容器/浏览器/语言沙箱逃逸。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [10 字节 shellcode 限制：read 覆盖自身 + jmp 回跳的分段加载](binary-pwn-sandbox-escape-tiny-shellcode-read-self-loop-staging.md) | verified | medium | 2026-11-06 |
| [ALPHA3 可见字符 Shellcode：绕过 <=0x1f/0x7f 字节过滤执行 seccomp ORW](binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw.md) | verified | high | 2026-11-05 |
| [Apache HugeGraph Gremlin 沙箱逃逸：改线程名绕过 SecurityManager 检查后反射执行 Runtime.exec（CVE-2024-27348）](binary-pwn-sandbox-escape-hugegraph-gremlin-threadname-securitymanager-bypass.md) | verified | medium | 2026-11-06 |
| [AST 变量名回查 + 禁括号 pyjail：NFKC 全角标识符、装饰器链与 \r 换行绕过](binary-pwn-sandbox-escape-nfkc-ast-name-decorator-cr-bypass.md) | verified | high | 2026-11-06 |
| [Aviator 表达式引擎沙箱逃逸：InternalVars + seq 改写 features 与 functionMissing](binary-pwn-sandbox-escape-aviator-internalvars-seq-reflection.md) | verified | medium | 2026-11-05 |
| [Bash 算术扩展中的命令替换：a[$(cmd)] 在求值报错前执行命令并回显](binary-pwn-sandbox-escape-bash-arithmetic-expansion-command-substitution.md) | verified | high | 2026-11-06 |
| [builtins 被清空后用 set_builtin 伪造 __import__，from-import 取函数 __globals__ 逃逸](binary-pwn-sandbox-escape-python-set-builtin-fake-import-globals.md) | verified | high | 2026-11-06 |
| [chroot 不是安全边界：未 chdir、双重 chroot 与已打开文件描述符三种逃逸](binary-pwn-sandbox-escape-chroot-cwd-double-chroot-fd-escape.md) | verified | high | 2026-11-06 |
| [chroot 逃逸 + exit 状态侧信道：用预打开的根目录 fd 调 openat 并逐字节回显 flag](binary-pwn-sandbox-escape-chroot-openat-fd-exit-status-sidechannel.md) | verified | high | 2026-11-06 |
| [Crawl4AI < 0.8.0 hooks.code 沙箱逃逸：builtins 白名单保留 __import__ 导致未授权 root RCE（CVE-2026-26216）](binary-pwn-sandbox-escape-crawl4ai-hooks-import-whitelist-rce.md) | verified | high | 2026-11-06 |
| [DeepSeek Harness 动态插件沙箱逃逸：未投影 exec.agent.ctx 直达 subprocess.spawn 宿主 RCE（QVD-2026-52646）](binary-pwn-sandbox-escape-dsh-exec-agent-ctx-subprocess-rce.md) | verified | high | 2026-11-05 |
| [Dify dify-sandbox < 0.2.11 JS 代码节点逃逸：用户 function parseInt 提升覆盖全局函数，在 difySeccomp 生效前以 root 执行命令](binary-pwn-sandbox-escape-dify-sandbox-parseint-hoisting-seccomp.md) | verified | high | 2026-11-06 |
| [enclave-vm < 2.7.0 工具调用错误暴露宿主 Error：cause.constructor.constructor 原型链逃逸（CVE-2026-22686）](binary-pwn-sandbox-escape-enclave-vm-host-error-prototype-chain.md) | verified | high | 2026-11-06 |
| [eval 沙箱的源码黑名单与单表达式限制绕过](binary-pwn-sandbox-escape-python-eval-filter-bypass.md) | verified | medium | 2026-11-04 |
| [FastGPT v4.14.8 沙箱逃逸：inspect 帧回溯窃取 worker 原始 open/import 引用](binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs.md) | verified | high | 2026-11-05 |
| [fork 继承 root 已打开的 fd：低权限子进程经 /proc/<pid>/fd 读取已删除脚本](binary-pwn-sandbox-escape-inherited-fd-read-deleted-file.md) | verified | high | 2026-11-07 |
| [GNU IFUNC resolver 先于 constructor 执行：绕过插件 constructor 安装的 seccomp](binary-pwn-sandbox-escape-ifunc-resolver-before-constructor-seccomp.md) | verified | high | 2026-11-04 |
| [GoogleCTF 2025 Internship pyjail：CodeType 常量/名字白名单 + 小整数打乱下用 dir(None) 迭代拼出 flag](binary-pwn-sandbox-escape-python-codetype-none-dir-iterator-flag.md) | verified | high | 2026-11-07 |
| [GraalVM HostAccess.ALL 下 getClass 反射逃逸到宿主 Runtime.exec](binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce.md) | verified | high | 2026-11-05 |
| [GraalVM HostAccess.EXPLICIT 下 toString 与异常堆栈泄露宿主类名和源路径](binary-pwn-sandbox-escape-graalvm-explicit-info-leak.md) | verified | high | 2026-11-05 |
| [Groovy 沙箱 InvokerHelper 间接调用逃逸：签名与目标分离](binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch.md) | verified | high | 2026-11-04 |
| [Groovy 沙箱反射与黑名单盲区：MethodHandles、java.beans 与 NIO](binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps.md) | verified | medium | 2026-11-04 |
| [Groovy 黑名单沙箱解释器逃逸：在脚本内新建解释器](binary-pwn-sandbox-escape-groovy-interpreter-reinstantiation.md) | verified | high | 2026-11-04 |
| [KVM 虚拟机内 root + 宿主机块设备透传：挂载 /dev/sdb 读写宿主机文件逃逸](binary-pwn-sandbox-escape-kvm-block-device-mount-host-escape.md) | verified | medium | 2026-11-05 |
| [Lua 5.1 字节码沙箱逃逸：OP_FORLOOP 类型混淆泄露对象地址，伪造 LClosure/TValue 实现任意读](binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure.md) | verified | high | 2026-11-06 |
| [MiniVN check_in：__builtins__=None 下用 list/dict 别名恢复 builtins](binary-pwn-sandbox-escape-python-builtins-none-list-dict-alias.md) | verified | high | 2026-11-04 |
| [Node.js eval 沙箱字符+AST 双层过滤绕过：with 取属性、&& 串联、console.log 换成 eval](binary-pwn-sandbox-escape-nodejs-eval-char-ast-filter-with-consolelog-eval.md) | verified | high | 2026-11-06 |
| [Node.js 原生 vm 沙箱逃逸：this.constructor.constructor 取宿主 process 执行命令](binary-pwn-sandbox-escape-nodejs-vm-constructor-constructor.md) | verified | high | 2026-11-05 |
| [Pickle 单字节翻转 LONG4→SHORT_BINUNICODE：把后续字符串字节并入整数回显泄露](binary-pwn-sandbox-escape-pickle-byte-flip-long4-short-binunicode-leak.md) | verified | high | 2026-11-06 |
| [pyjail 位置/ASCII 奇偶校验绕过：按字符奇偶选引号拼接任意字符串](binary-pwn-sandbox-escape-pyjail-position-parity-quote-bypass.md) | verified | high | 2026-11-06 |
| [Python AST 白名单 + 审计钩子沙箱逃逸：JoinedStr 未递归与 ctypes 原生 open](binary-pwn-sandbox-escape-python-ast-joinedstr-ctypes-open.md) | verified | high | 2026-11-06 |
| [Python dis 字节码检查器的 break 逻辑绕过：前置白名单指令跳过后续检查](binary-pwn-sandbox-escape-python-dis-checker-break-bypass.md) | verified | medium | 2026-11-05 |
| [Python exec 沙箱禁 e/o：八进制转义拼 __import__ 并拉起无限制子 Python](binary-pwn-sandbox-escape-python-eo-blacklist-octal-subprocess.md) | verified | high | 2026-11-06 |
| [Python exec 沙箱：unicode_escape 绕过字符 WAF + 覆盖 filter/len + 异常回溯取 environ](binary-pwn-sandbox-escape-python-unicode-audit-traceback.md) | verified | high | 2026-11-06 |
| [Python 代码长度上限绕过：分阶段递归 input 把下一段代码带进 exec](binary-pwn-sandbox-escape-python-recursive-input-length-limit-bypass.md) | verified | high | 2026-11-06 |
| [Python 受限执行环境通过子类遍历逃逸到 os/subprocess](binary-pwn-sandbox-escape-python-jail-subclass-traversal.md) | verified | high | 2026-11-04 |
| [Python 审计钩子沙箱绕过：遮蔽钩子依赖的内建并恢复被污染的 os](binary-pwn-sandbox-escape-python-audit-hook-bypass.md) | verified | medium | 2026-11-04 |
| [Python 审计钩子绕过：污染 builtins.print 并篡改 audit 局部 os._exit](binary-pwn-sandbox-escape-python-audit-hook-print-poisoning.md) | verified | high | 2026-11-05 |
| [Python 格式字符串 AttributeError.obj 构造 getattr：绕过属性名黑名单，经 traceback→frame→f_builtins 取 __import__ 逃逸](binary-pwn-sandbox-escape-python-format-string-attributeerror-getattr.md) | verified | high | 2026-11-06 |
| [Python 沙箱：异常回溯 tb_frame 与 tb_next 链取帧逃逸](binary-pwn-sandbox-escape-python-traceback-frame-escape.md) | verified | high | 2026-11-05 |
| [Python 沙箱：未 await 协程的 cr_frame 直接取 f_globals 逃逸](binary-pwn-sandbox-escape-python-coroutine-cr-frame.md) | verified | medium | 2026-11-05 |
| [Python 沙箱：生成器 gi_code 常量池与 gi_yieldfrom 嵌套帧信息泄露](binary-pwn-sandbox-escape-python-generator-code-consts-leak.md) | verified | high | 2026-11-05 |
| [Python 沙箱：生成器 gi_frame 栈帧回溯恢复真实 __builtins__](binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery.md) | verified | high | 2026-11-05 |
| [QEMU 自定义 PCI 设备 MMIO 越界读写逃逸：改 log_handler 为 system](binary-pwn-sandbox-escape-qemu-pci-mmio-oob-function-pointer-escape.md) | verified | high | 2026-11-05 |
| [Redis Lua 沙箱逃逸：Debian 打包残留 package.loadlib 加载 liblua 取 io.popen（CVE-2022-0543）](binary-pwn-sandbox-escape-redis-lua-package-loadlib-cve-2022-0543.md) | verified | high | 2026-11-06 |
| [RestrictedPython posonlyargs 漏检导致 guard 遮蔽沙箱策略绕过（CVE-2026-55830）](binary-pwn-sandbox-escape-restrictedpython-posonly-guard-shadow.md) | verified | high | 2026-11-05 |
| [Roblox Lua 沙箱类型标记绕过：write 可改私有对象 TypeTag，read 的访问拒绝被翻转](binary-pwn-sandbox-escape-roblox-lua-writable-typetag-private-address.md) | verified | high | 2026-11-06 |
| [Ruby 计算器沙箱：用户可控操作符经 send 动态派发到 Kernel#system](binary-pwn-sandbox-escape-ruby-send-calculator-method-dispatch-rce.md) | verified | high | 2026-11-06 |
| [Rust 表达式沙箱字符串黑名单绕过：include! 内用 core::arch::asm! 裸 syscall 读文件](binary-pwn-sandbox-escape-rust-include-asm-syscall.md) | verified | high | 2026-11-06 |
| [RWX shellcode 自修改绕过 syscall 字节扫描 + seccomp 白名单 openat ORW](binary-pwn-sandbox-escape-self-modifying-shellcode-seccomp-orw.md) | verified | high | 2026-11-05 |
| [Safe Rust 生命周期 soundness hole](binary-pwn-sandbox-escape-rust-nested-reference-soundness-25860.md) | verified | high | 2026-11-06 |
| [SandboxJS <0.8.26 沙箱逃逸：异步函数 .constructor 取宿主 AsyncFunction 执行任意代码（CVE-2026-23830）](binary-pwn-sandbox-escape-sandboxjs-asyncfunction-constructor-cve-2026-23830.md) | verified | high | 2026-11-06 |
| [SandboxJS 浅层污点检查失效：Object.values 带出宿主 Function 数组，经 Object.fromEntries 换形后由 Promise.finally 触发逃逸（CVE-2026-26954）](binary-pwn-sandbox-escape-sandboxjs-object-values-function-array-fromentries.md) | verified | high | 2026-11-06 |
| [seccomp write(fd==1/2) 写入限制绕过：fcntl dup2 重映射 stdout 写任意文件](binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2.md) | verified | high | 2026-11-05 |
| [seccomp 只杀 open/openat/execve：openat2 + pipe/splice 读 flag](binary-pwn-sandbox-escape-seccomp-openat2-pipe-splice.md) | verified | high | 2026-11-06 |
| [seccomp 黑名单未校验 arch：retf 切 32 位兼容模式用 int 0x80 execve 绕过，再用 shell 内建读 flag](binary-pwn-sandbox-escape-seccomp-no-arch-check-i386-compat-execve.md) | verified | high | 2026-11-06 |
| [seccomp 黑名单漏掉 execveat：execveat(AT_FDCWD, /bin/sh) 绕过 execve 禁用，再用 shell 内建读未知文件名 flag](binary-pwn-sandbox-escape-seccomp-execveat-shell-builtin-read.md) | verified | high | 2026-11-07 |
| [shutil.copytree 目录权限后置导致的跨 challenge 读取竞态](binary-pwn-sandbox-escape-shutil-copytree-permission-race.md) | verified | high | 2026-11-06 |
| [vm2 globalPromise.then/catch 回调未清洗逃逸（CVE-2026-22709）](binary-pwn-sandbox-escape-vm2-global-promise-callback-cve-2026-22709.md) | verified | high | 2026-11-06 |
| [vm2 跨 Realm 隐式调用逃逸：Error.stack、Proxy、util.inspect 与 Promise 链](binary-pwn-sandbox-escape-vm2-cross-realm-implicit-call.md) | verified | medium | 2026-11-05 |
| [xmm7 残留 libc 指针的 24 字节受限 shellcode：绕 0x0f/0xcd/0x2f/0x50-0x57 过滤执行 execve](binary-pwn-sandbox-escape-xmm7-residual-libc-24byte-shellcode.md) | verified | high | 2026-11-05 |
| [无输出 shellcode 逐字符侧信道：cmp 猜测字节 + je 自循环制造超时](binary-pwn-sandbox-escape-shellcode-cmp-timeout-oracle.md) | verified | medium | 2026-11-06 |
| [正则+AST 双层黑名单沙箱绕过：别名调用、字符串拼接与动态属性访问](binary-pwn-sandbox-escape-python-regex-ast-alias-concat.md) | verified | high | 2026-11-05 |
| [汇编即服务：GNU as 的 .incbin 指令把任意文件嵌入机器码回显](binary-pwn-sandbox-escape-gnu-as-incbin-arbitrary-file-read.md) | verified | high | 2026-11-06 |
| [沙箱共享 mailbox TOCTOU：command 二次读取跳转表越界 → 无 seccomp 父进程 ROP](binary-pwn-sandbox-mailbox-toctou-jump-table-parent-rop.md) | verified | high | 2026-11-06 |
| [禁括号 + 空 builtins 的 Python 沙箱逃逸：劫持 __build_class__，用装饰器链与 NFKC 全角标识符执行 os.system](binary-pwn-sandbox-escape-buildclass-hijack-decorator-nfkc.md) | verified | high | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
