---
title: 混淆
weight: 1
---

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
| [AES-CBC 固定 key/iv 的 encryptCode 请求体还原与伪造](code-analysis-reverse-obfuscation-aes-cbc-encryptcode-request-forge/) | verified | high | 2026-11-05 |
| [AI + Chrome DevTools MCP 辅助前端加密 JS 逆向：自然语言定位加密参数并生成验证脚本](code-analysis-reverse-obfuscation-ai-mcp-chrome-devtools-js-encryption-reverse/) | verified | medium | 2026-11-06 |
| [AI IDE 辅助高度混淆 JS 解混淆：先脚本批量还原字符串表，再由 IDE 语义重构并交叉验证](code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation/) | verified | high | 2026-11-06 |
| [Base64 多层打包 + XOR 字符码/整数混淆的 JS 工具包静态去混淆（正则常量折叠 + AI 语义重构）](code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation/) | verified | high | 2026-11-06 |
| [C++ constexpr 编译期字符串加密：消除 .rdata 明文特征](code-analysis-reverse-obfuscation-constexpr-compile-time-string-encryption/) | verified | high | 2026-11-05 |
| [CryptoAPI SHA1 派生 40 位 RC4 密钥解密恶意样本配置：CryptDeriveKey 0x280011 参数与离线复现](code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt/) | verified | high | 2026-11-06 |
| [Dridex API Hash 还原：crc32(name) ^ 0x7AF3DA47 与 HashDB XOR Key](code-analysis-reverse-obfuscation-dridex-api-hash-crc32-xor-key/) | verified | high | 2026-11-05 |
| [Electron 游戏辅助 JS 混淆还原：执行字符串数组 + Babel AST 替换、别名消除与花指令清理](code-analysis-reverse-obfuscation-javascript-obfuscator-babel-ast-string-array-cleanup/) | verified | medium | 2026-11-07 |
| [Frida 辅助 OLLVM 字符串解密：.datadiv_decode/.init_array + RegisterNatives 枚举](code-analysis-reverse-obfuscation-ollvm-string-decrypt-frida/) | verified | high | 2026-11-06 |
| [Frida 辅助 OLLVM 指令替换分析：Hook memcpy/寄存器提取运算结果](code-analysis-reverse-obfuscation-ollvm-instruction-substitution-frida-register/) | verified | high | 2026-11-06 |
| [Frida 辅助 OLLVM 控制流平坦化分析：NewStringUTF/LR 追踪 + base64/MD5 识别](code-analysis-reverse-obfuscation-ollvm-cff-frida-trace/) | verified | high | 2026-11-06 |
| [Go AST 跨文件代码混淆：私有符号/字符串/文件名与链接器包路径多层替换，消除静态特征](code-analysis-reverse-obfuscation-go-ast-cross-file-obfuscation/) | verified | medium | 2026-11-07 |
| [JavaScript Obfuscator Debug Protection：递归 debugger + setInterval 的识别与绕过](code-analysis-reverse-obfuscation-javascript-obfuscator-debug-protection-recursive-debugger/) | verified | medium | 2026-11-06 |
| [JavaScript Obfuscator Self Defending 的格式化陷阱：compact 绑定 + ReDoS 正则与安全分析方式](code-analysis-reverse-obfuscation-javascript-obfuscator-self-defending-format-trap/) | verified | medium | 2026-11-06 |
| [JavaScript Obfuscator v5.3.0 字符串数组提取：底部数组定义、取值函数偏移与洗牌后数组还原](code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction/) | verified | high | 2026-11-06 |
| [JavaScript 混淆下定位 AES-CBC 参数加密并还原 key/iv 与 iv||密文格式](code-analysis-reverse-obfuscation-js-aes-parameter-restore/) | verified | high | 2026-11-05 |
| [jz 跳过 E8 的线性扫描花指令：xor/jz/E8 垃圾字节与 IDA 修复](code-analysis-reverse-obfuscation-jz-skip-e8-junk-ida-repair/) | verified | high | 2026-11-06 |
| [Linux 恶意样本 API 调用混淆：dlopen/dlsym、导出表哈希匹配与运行时 syscall stub](code-analysis-reverse-obfuscation-linux-dynamic-api-hash-syscall-stub/) | verified | medium | 2026-11-06 |
| [LLVM 混淆 Pass 实现：基本块分割、控制流平坦化、虚假/随机控制流与指令/常量替代](code-analysis-reverse-obfuscation-llvm-pass-implementation/) | verified | high | 2026-11-06 |
| [MCP + Skill 模板驱动 JS 逆向自动化：AI 定位加密入口并生成 JSRPC/Flask/autoDecoder 工件](code-analysis-reverse-obfuscation-mcp-skill-jsrpc-autodecoder-automation/) | verified | medium | 2026-11-06 |
| [Mystic Stealer 类样本 C2 自动化提取：TEA 变种常量识别 + 指令特征码内联密钥 + .rdata 扫描解密](code-analysis-reverse-obfuscation-mystic-stealer-tea-variant-c2-auto-extract/) | verified | high | 2026-11-06 |
| [Obfuscar 字符串隐藏自动还原：dnlib 定位 InitializeArray 字节数组 + offset/size 切片 + byte^i^key 解密](code-analysis-reverse-obfuscation-obfuscar-dnlib-string-auto-decrypt/) | verified | high | 2026-11-06 |
| [OEP 识别与 call/add/retn 花指令：按编译器特征找入口并 NOP 掉跳转](ctf-reverse-oep-junk-code-call-add-retn/) | verified | high | 2026-11-06 |
| [OLLVM 编译期混淆：控制流平坦化、虚假控制流与指令替换](code-analysis-reverse-obfuscation-ollvm-cff-bcf-substitution/) | verified | medium | 2026-11-05 |
| [PHP gzinflate+strtr+base64 多层混淆静态还原：从 eval 壳取出 backdoor 源码](code-analysis-reverse-obfuscation-php-gzinflate-strtr-base64-unwrap/) | verified | high | 2026-11-07 |
| [PowerShell 花括号变量名伪装 + -f 占位重排 + 字符码替换的三层混淆与去混淆](code-analysis-reverse-obfuscation-powershell-braced-variable-format-reorder/) | verified | high | 2026-11-06 |
| [ptrace 父进程改写子进程门函数控制流：int3 gate + 加密节点表调度](code-analysis-reverse-obfuscation-ptrace-parent-child-gate-flow/) | verified | high | 2026-11-06 |
| [Pyarmor 静态脱壳：Pyarmor-Static-Unpack-1shot 解析 runtime AES-CTR 密钥批量还原源码](code-analysis-reverse-obfuscation-pyarmor-static-unpack-aes-ctr/) | verified | high | 2026-11-07 |
| [Python AST 控制流平坦化：py2cfg + 状态机 switchVar 重写函数体](code-analysis-reverse-obfuscation-python-ast-control-flow-flattening/) | verified | medium | 2026-11-07 |
| [Python AST 混淆：变量/属性名重写与 getattr/__dict__/gc.get_referents 别名](code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename/) | verified | medium | 2026-11-07 |
| [Rust 恶意样本 ChaCha20-Poly1305 字符串解密：硬编码 32 字节 key + IDAPython 批量还原](code-analysis-reverse-obfuscation-rust-chacha20poly1305-string-decrypt-idapython/) | verified | high | 2026-11-06 |
| [Triton 符号执行 + AI/Z3 化简 OLLVM MBA 混淆：从基本块 AST 还原 hash 算法](code-analysis-reverse-obfuscation-ollvm-triton-ast-ai-z3-mba/) | verified | high | 2026-11-06 |
| [VBE→PowerShell→.NET 三层嵌套样本分析：MSXML2 Base64 解码、AES-256-CBC 载荷还原与 procdump 抓进程镂空](code-analysis-reverse-obfuscation-vbe-powershell-dotnet-layered-sample/) | verified | high | 2026-11-06 |
| [x86-64 指令重叠：入口处无害指令流掩盖偏移执行的隐藏流](code-analysis-reverse-obfuscation-x86-64-instruction-overlap-dual-stream/) | verified | high | 2026-11-05 |
| [XORStringsNet 字符串自动解密：ClassLayout 最大 Size + FieldRVA 相邻差定位加密表，逆序+单字节 XOR 还原](code-analysis-reverse-obfuscation-xorstringsnet-automated-decrypt/) | verified | high | 2026-11-06 |
| [假验证码投递 HTA 伪装 mp3 的多层脚本脱混淆：JS fromCharCode 数组 → 十六进制 XOR → PowerShell 字符码](code-analysis-reverse-obfuscation-fake-captcha-hta-js-charcode-powershell/) | verified | high | 2026-11-07 |
| [前端 RSA-OAEP 参数加密逆向：隐藏 DOM 公钥还原与任意 id 密文伪造](code-analysis-reverse-obfuscation-rsa-oaep-dom-public-key-parameter-forge/) | verified | high | 2026-11-06 |
| [动态密钥前端加密接口的越权测试：断点固定 generateKey 并复用页面加解密函数](code-analysis-reverse-dynamic-key-encrypted-api-idor/) | verified | medium | 2026-11-05 |
| [整数数组编码的 PowerShell 混淆与 ScriptBlock 内存执行](code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock/) | verified | high | 2026-11-04 |
| [混淆 JS 中 CryptoJS WordArray 数值数组还原 key/iv 与 AES-CFB 参数还原](code-analysis-reverse-obfuscation-cryptojs-wordarray-key-restore/) | verified | high | 2026-11-05 |
| [混淆 JS 加密配置数组控制台求值：提取 AES-CBC key/IV 解密双向业务流量并定位外传 URL](code-analysis-reverse-obfuscation-js-config-array-console-aes-key-iv/) | verified | high | 2026-11-07 |
| [请求与响应双层加密 API 的 JS 逆向与 PyExecJS 自动化](code-analysis-reverse-frontend-request-response-encryption-automation/) | verified | high | 2026-11-05 |
| [银狐 BCF 不透明谓词静态还原：常量函数内联 + 只读全局常量化触发 IDA DCE](code-analysis-reverse-obfuscation-silverfox-const-func-global-dce-bcf/) | verified | high | 2026-11-06 |
| [银狐强混淆 VM 调用还原：IDAPython 识别 call r11 模式并常量折叠 patch](code-analysis-reverse-obfuscation-silverfox-vm-call-idapython-restore/) | verified | high | 2026-11-05 |
| [银狐样本轻量字符串混淆：@ 隔字符插入、栈上字符串与 API 包装还原](code-analysis-reverse-obfuscation-silverfox-light-string-api-obfuscation/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
