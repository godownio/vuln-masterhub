# 混淆

## 这层是什么

控制流平坦化、字符串加密、指令替换与还原。

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
| [AES-CBC 固定 key/iv 的 encryptCode 请求体还原与伪造](code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge.md) | verified | high | 2026-11-05 |
| [AI + Chrome DevTools MCP 辅助前端加密 JS 逆向：自然语言定位加密参数并生成验证脚本](code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse.md) | verified | medium | 2026-11-06 |
| [AI IDE 辅助高度混淆 JS 解混淆：先脚本批量还原字符串表，再由 IDE 语义重构并交叉验证](code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation.md) | verified | high | 2026-11-06 |
| [ARM64 花指令批量修复：JNI_OnLoad 的 ADR/STR/LDP/BR 跳板用 keystone 模拟求目标后改 B](code-analysis-reverse-obfuscation-arm64-jni-onload-junk-jump-br-patch.md) | verified | high | 2026-11-08 |
| [Base64 多层打包 + XOR 字符码/整数混淆的 JS 工具包静态去混淆（正则常量折叠 + AI 语义重构）](code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation.md) | verified | high | 2026-11-06 |
| [C++ constexpr 编译期字符串加密：消除 .rdata 明文特征](code-analysis-reverse-obfuscation-constexpr-compile-time-string-encryption.md) | verified | high | 2026-11-05 |
| [call $+5 改写返回地址型 jmp 花指令：按 imm 宽度计算目标并用 E9/EB 重建跳转](code-analysis-reverse-obfuscation-call5-retaddr-jump-eb-e9-rebuild.md) | verified | high | 2026-11-09 |
| [CryptoAPI SHA1 派生 40 位 RC4 密钥解密恶意样本配置：CryptDeriveKey 0x280011 参数与离线复现](code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt.md) | verified | high | 2026-11-06 |
| [DevTools 断点作用域改明文变量：在签名与加密执行前改 Scope 中的请求对象，绕过前端校验并让密文/签名基于篡改值重算](code-analysis-reverse-obfuscation-devtools-scope-edit-plaintext-before-encrypt.md) | verified | high | 2026-11-09 |
| [Dridex API Hash 还原：crc32(name) ^ 0x7AF3DA47 与 HashDB XOR Key](code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key.md) | verified | high | 2026-11-05 |
| [Electron 游戏辅助 JS 混淆还原：执行字符串数组 + Babel AST 替换、别名消除与花指令清理](code-analysis-reverse-obfuscation-javascript-obfuscator-babel-ast-string-array-cleanup.md) | verified | medium | 2026-11-07 |
| [Frida 辅助 OLLVM 字符串解密：.datadiv_decode/.init_array + RegisterNatives 枚举](code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida.md) | verified | high | 2026-11-06 |
| [Frida 辅助 OLLVM 指令替换分析：Hook memcpy/寄存器提取运算结果](code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register.md) | verified | high | 2026-11-06 |
| [Frida 辅助 OLLVM 控制流平坦化分析：NewStringUTF/LR 追踪 + base64/MD5 识别](code-analysis-reverse-obfuscation-ollvm-cff-frida-trace.md) | verified | high | 2026-11-06 |
| [garble 编译 Go loader：哈希标识符/包路径、-literals 混淆字面量、-ldflags "-w -s" 去符号表](code-analysis-reverse-obfuscation-garble-go-binary-symbol-static-evasion.md) | verified | high | 2026-11-08 |
| [Go AST 跨文件代码混淆：私有符号/字符串/文件名与链接器包路径多层替换，消除静态特征](code-analysis-reverse-obfuscation-go-ast-cross-file-obfuscation.md) | verified | medium | 2026-11-07 |
| [Grandoreiro 字符串解密：三次 Base64 密钥 + 自定义 hex/差分异或 + AES-256-CBC（密钥与 IV 同样加密）](code-analysis-reverse-obfuscation-grandoreiro-string-decryption-triple-base64-diff-xor-aes.md) | verified | high | 2026-11-08 |
| [HTA VBScript 连字符填充字符串还原：Replace 去填充隐藏 Shell.Application/powershell 与整条命令](code-analysis-reverse-obfuscation-hta-vbscript-hyphen-fill-string.md) | verified | high | 2026-11-09 |
| [Huffman 式字符串混淆：frequency/left/right 树 + 0/1 位串 + Crypto++ Base64 的识别与还原](code-analysis-reverse-obfuscation-huffman-tree-bitstring-string-decode.md) | verified | medium | 2026-11-09 |
| [IDAPython 通配符掩码 bin_search 批量定位花指令并 NOP/重建跳转](code-analysis-reverse-obfuscation-idapython-wildcard-binsearch-patch.md) | verified | high | 2026-11-09 |
| [Java 客户端可查密钥 + 硬编码 IV：AES/CBC 保护的 API 敏感字段可被任意客户端解密](code-analysis-reverse-java-client-secret-key-command-hardcoded-iv-api-decrypt.md) | verified | high | 2026-11-09 |
| [JavaScript Obfuscator Debug Protection：递归 debugger + setInterval 的识别与绕过](code-analysis-reverse-obfuscation-javascript-obfuscator-debug-protection-recursive-debugger.md) | verified | medium | 2026-11-06 |
| [JavaScript Obfuscator Self Defending 的格式化陷阱：compact 绑定 + ReDoS 正则与安全分析方式](code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap.md) | verified | medium | 2026-11-06 |
| [JavaScript Obfuscator v5.3.0 字符串数组提取：底部数组定义、取值函数偏移与洗牌后数组还原](code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction.md) | verified | high | 2026-11-06 |
| [JavaScript 混淆下定位 AES-CBC 参数加密并还原 key/iv 与 iv||密文格式](code-analysis-reverse-obfuscation-js-aes-parameter-restore.md) | verified | high | 2026-11-05 |
| [JS-Forward 明文点插桩改包：DevTools 本地替换注入同步 XHR，把加密前变量经本地桥转给 Burp 修改后回写](code-analysis-reverse-obfuscation-js-forward-plaintext-override-burp-bridge.md) | verified | high | 2026-11-09 |
| [jz 跳过 E8 的线性扫描花指令：xor/jz/E8 垃圾字节与 IDA 修复](code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair.md) | verified | high | 2026-11-06 |
| [LATRODECTUS 字符串解密：前 4 字节 u32 x 与 2 字节 u16 y 派生长度，明文 = ((x+i+1) XOR 密文字节) & 0xFF](code-analysis-reverse-obfuscation-latrodectus-string-decrypt.md) | verified | high | 2026-11-09 |
| [Linux 恶意样本 API 调用混淆：dlopen/dlsym、导出表哈希匹配与运行时 syscall stub](code-analysis-reverse-obfuscation-linux-dynamic-api-hash-syscall-stub.md) | verified | medium | 2026-11-06 |
| [LLVM 18 新版 PassManager 最小闭环：PassInfoMixin 写 run()、PassRegistry.def 注册 encode、ninja opt 后以 -O3 生成的 .ll 验证](code-analysis-reverse-obfuscation-llvm18-new-pass-manager-minimal-loop.md) | verified | medium | 2026-11-09 |
| [LLVM 混淆 Pass 实现：基本块分割、控制流平坦化、虚假/随机控制流与指令/常量替代](code-analysis-reverse-obfuscation-llvm-pass-implementation.md) | verified | high | 2026-11-06 |
| [LuaJIT 字节码字符串表去混淆：自定义 Base64 字母表 + 密钥 XOR 循环，断点 dump 明文](code-analysis-reverse-obfuscation-luajit-bytecode-string-table-xor.md) | verified | medium | 2026-11-10 |
| [MCP + Skill 模板驱动 JS 逆向自动化：AI 定位加密入口并生成 JSRPC/Flask/autoDecoder 工件](code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation.md) | verified | medium | 2026-11-06 |
| [movfuscator 全 mov 混淆逆向：UPX 脱壳 + IDA F5 失效 + 按 C7 05 固定前缀扫描提取 flag](code-analysis-reverse-obfuscation-movfuscator-all-mov-flag-immediate-scan.md) | verified | high | 2026-11-08 |
| [Mystic Stealer 类样本 C2 自动化提取：TEA 变种常量识别 + 指令特征码内联密钥 + .rdata 扫描解密](code-analysis-reverse-obfuscation-mystic-stealer-tea-variant-c2-auto-extract.md) | verified | high | 2026-11-06 |
| [Obfuscar 字符串隐藏自动还原：dnlib 定位 InitializeArray 字节数组 + offset/size 切片 + byte^i^key 解密](code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt.md) | verified | high | 2026-11-06 |
| [OEP 识别与 call/add/retn 花指令：按编译器特征找入口并 NOP 掉跳转](ctf-reverse-oep-junk-code-call-add-retn.md) | verified | high | 2026-11-06 |
| [OLLVM 编译期混淆：控制流平坦化、虚假控制流与指令替换](code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution.md) | verified | medium | 2026-11-05 |
| [PE .data 节整体 XOR 加密：高熵 RW 节区 + 运行时逐字节解码还原字符串表与内嵌 PE](code-analysis-reverse-obfuscation-pe-data-section-xor-decode-embedded-pe.md) | verified | medium | 2026-11-08 |
| [PHP eval 变种壳还原：自定义解码函数内 gzinflate+base64 后再逐字节 ASCII 偏移](code-analysis-reverse-obfuscation-php-eval-chr-shift-custom-decoder.md) | verified | high | 2026-11-08 |
| [PHP eval(gzinflate(base64_decode())) 外壳动态还原：eval 改 echo + ob_start 递归剥壳](code-analysis-reverse-obfuscation-php-eval-gzinflate-echo-unwrap.md) | verified | high | 2026-11-08 |
| [PHP gzinflate+strtr+base64 多层混淆静态还原：从 eval 壳取出 backdoor 源码](code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap.md) | verified | high | 2026-11-07 |
| [PowerShell 从多个单行 txt 分片读取注入关键词并拼回反射调用：load/GetType/getMethod/Invoke/NewPE2.PE/Execute，二进制串隐藏 aspnet_compiler 路径](code-analysis-reverse-obfuscation-txt-fragment-keyword-reflection-assembly.md) | verified | medium | 2026-11-09 |
| [PowerShell 花括号变量名伪装 + -f 占位重排 + 字符码替换的三层混淆与去混淆](code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder.md) | verified | high | 2026-11-06 |
| [ptrace 父进程改写子进程门函数控制流：int3 gate + 加密节点表调度](code-analysis-reverse-obfuscation-ptrace-parent-child-gate-flow.md) | verified | high | 2026-11-06 |
| [Pyarmor 静态脱壳：Pyarmor-Static-Unpack-1shot 解析 runtime AES-CTR 密钥批量还原源码](code-analysis-reverse-obfuscation-pyarmor-static-unpack-aes-ctr.md) | verified | high | 2026-11-07 |
| [Python AST 控制流平坦化：py2cfg + 状态机 switchVar 重写函数体](code-analysis-reverse-obfuscation-python-ast-control-flow-flattening.md) | verified | medium | 2026-11-07 |
| [Python AST 混淆：变量/属性名重写与 getattr/__dict__/gc.get_referents 别名](code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename.md) | verified | medium | 2026-11-07 |
| [Rust 恶意样本 ChaCha20-Poly1305 字符串解密：硬编码 32 字节 key + IDAPython 批量还原](code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython.md) | verified | high | 2026-11-06 |
| [SMC 函数级单字节 XOR 加密的密钥恢复（反汇编合法性筛选爆破）](smc-xor-function-decrypt-disasm-filter.md) | verified | high | 2026-11-08 |
| [Triton 符号执行 + AI/Z3 化简 OLLVM MBA 混淆：从基本块 AST 还原 hash 算法](code-analysis-reverse-obfuscation-ollvm-triton-ast-ai-z3-mba.md) | verified | high | 2026-11-06 |
| [v_jstools 挂钩定位前端加密明文点：从 JSON.stringify/atob 钩子回溯请求拦截器并锁定加密与签名函数](code-analysis-reverse-obfuscation-vjstools-plaintext-hook-encryption-locate.md) | verified | high | 2026-11-09 |
| [VBE→PowerShell→.NET 三层嵌套样本分析：MSXML2 Base64 解码、AES-256-CBC 载荷还原与 procdump 抓进程镂空](code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample.md) | verified | high | 2026-11-06 |
| [WARMCOOKIE 原生 PE 字符串加密：.rdata 中 [4 字节长度][4 字节 RC4 key][密文] 记录 + 用后清零](code-analysis-reverse-obfuscation-warmcookie-rc4-string-record.md) | verified | high | 2026-11-08 |
| [x86-64 指令重叠：入口处无害指令流掩盖偏移执行的隐藏流](code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream.md) | verified | high | 2026-11-05 |
| [XORStringsNet 字符串自动解密：ClassLayout 最大 Size + FieldRVA 相邻差定位加密表，逆序+单字节 XOR 还原](code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt.md) | verified | high | 2026-11-06 |
| [Zig comptime 编译期字符串异或加密：build.zig 每次编译生成随机 key，运行时在栈上解密](code-analysis-reverse-obfuscation-zig-comptime-string-xor-encryption.md) | verified | high | 2026-11-08 |
| [不存 DLL 名字的动态解析：枚举 System32\*.dll 对每个文件名算 CRC32 匹配常量后 LoadLibraryW](code-analysis-reverse-obfuscation-wildcard-dll-crc32-resolution.md) | verified | high | 2026-11-09 |
| [假验证码投递 HTA 伪装 mp3 的多层脚本脱混淆：JS fromCharCode 数组 → 十六进制 XOR → PowerShell 字符码](code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell.md) | verified | high | 2026-11-07 |
| [兄弟文件当密钥的重复异或：同目录 .dll 作 key 解其余三份落地文件，解出配置与二级载荷地址](code-analysis-reverse-obfuscation-sibling-file-as-xor-key-multi-drop-decrypt.md) | verified | high | 2026-11-08 |
| [前端 AES 参数复现：key/iv 取 Authorization 后 16 位与 ZeroPadding/PKCS#7 填充对齐](code-analysis-reverse-obfuscation-js-aes-zeropadding-authorization-key.md) | verified | high | 2026-11-08 |
| [前端 AES-CBC 密钥与 IV 存放在 JWT/localStorage（SecretKey/SecretIV）：解 token 还原 requestData 解密-篡改-重加密](code-analysis-reverse-obfuscation-jwt-secretkey-secretiv-aes-cbc-traffic.md) | verified | high | 2026-11-09 |
| [前端 JS 硬编码 AES/ECB 密钥导致应用层加密流量可解密](front-end-hardcoded-aes-ecb-traffic-decrypt.md) | verified | high | 2026-11-08 |
| [前端 RSA-OAEP 参数加密逆向：隐藏 DOM 公钥还原与任意 id 密文伪造](code-analysis-reverse-obfuscation-rsa-oaep-dom-public-key-parameter-forge.md) | verified | high | 2026-11-06 |
| [加盐 FNV-1a API 哈希解析：字符串哈希后再哈希 4 字节盐，遍历导出表缓存函数指针](code-analysis-reverse-obfuscation-salted-fnv1a-api-hash-resolve.md) | verified | high | 2026-11-08 |
| [加载器硬编码口令 + CryptoAPI AES-256-CBC 加密下载 URL：.rdata 无明文 C2，分析时用同一 password 派生密钥即可还原](code-analysis-reverse-obfuscation-cryptapi-hardcoded-password-aes-url-decrypt.md) | verified | medium | 2026-11-09 |
| [动态密钥前端加密接口的越权测试：断点固定 generateKey 并复用页面加解密函数](code-analysis-reverse-dynamic-key-encrypted-api-idor.md) | verified | medium | 2026-11-05 |
| [扣 JS 复现前端签名：execjs 报 ReferenceError 时逐个补齐 IQ（CryptoJS MD5 工厂）与 TQ（crypto polyfill），并按页面逻辑两次调用签名函数](code-analysis-reverse-obfuscation-js-sign-execjs-dependency-patch.md) | verified | high | 2026-11-10 |
| [整数数组编码的 PowerShell 混淆与 ScriptBlock 内存执行](code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock.md) | verified | high | 2026-11-04 |
| [混淆 JS 中 CryptoJS WordArray 数值数组还原 key/iv 与 AES-CFB 参数还原](code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore.md) | verified | high | 2026-11-05 |
| [混淆 JS 加密配置数组控制台求值：提取 AES-CBC key/IV 解密双向业务流量并定位外传 URL](code-analysis-reverse-obfuscation-js-config-array-console-aes-key-iv.md) | verified | high | 2026-11-07 |
| [瑞数 6 代 cookie_t 扣代码补环境：抽取 page_url 动态 JS 与 VM 生成逻辑，在浏览器化环境执行后带 cookie_s/cookie_t 直连](code-analysis-reverse-obfuscation-rs-cookie-t-environment-emulation.md) | verified | medium | 2026-11-09 |
| [网易云 weapi 参数逆向：动态栈回溯锁定 t6n.be6Y → asrsea，还原 AES-CBC 二次加密 + 自制 RSA（encText/encSecKey）并用 Python 复刻](code-analysis-reverse-obfuscation-weapi-asrsea-aes-rsa-hop-param-forge.md) | verified | high | 2026-11-09 |
| [花指令识别：按等价指令替换、运算抵消与栈平衡判定垃圾代码](code-analysis-reverse-obfuscation-junk-instruction-equivalence-cancellation.md) | verified | high | 2026-11-09 |
| [裸 Shellcode 的 API 哈希解析：Ghidra 定位 PUSH hash + CALL reg，ROR13 类散列还原并 blobrunner 动态验证](code-analysis-reverse-obfuscation-shellcode-api-hash-ror13-blobrunner.md) | verified | medium | 2026-11-08 |
| [请求与响应双层加密 API 的 JS 逆向与 PyExecJS 自动化](code-analysis-reverse-frontend-request-response-encryption-automation.md) | verified | high | 2026-11-05 |
| [银狐 BCF 不透明谓词静态还原：常量函数内联 + 只读全局常量化触发 IDA DCE](code-analysis-reverse-obfuscation-silverfox-const-func-global-dce-bcf.md) | verified | high | 2026-11-06 |
| [银狐强混淆 VM 调用还原：IDAPython 识别 call r11 模式并常量折叠 patch](code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore.md) | verified | high | 2026-11-05 |
| [银狐样本轻量字符串混淆：@ 隔字符插入、栈上字符串与 API 包装还原](code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation.md) | verified | high | 2026-11-05 |
| [魔改 Tiny C 编译器代码混淆还原：call $+5/pop eax/jmp 调用替换、leave→pop ebx;jmp ebx 返回替换、无效 jnz 与 junk 常数的 IDC 批量 patch](code-analysis-reverse-obfuscation-tcc-junk-controlflow-idc-deobfuscation.md) | verified | medium | 2026-11-07 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
