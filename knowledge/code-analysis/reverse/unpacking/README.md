# 脱壳

## 这层是什么

壳识别、手动/自动脱壳、内存 dump 与重建。

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
| [32 位 DLL 样本手动脱壳：rundll32 导出加载 + VirtualAlloc/VirtualProtect 断点定位 aPLib 载荷并修复 PE](code-analysis-reverse-unpacking-dll-aplib-virtualalloc-protect-dump.md) | verified | high | 2026-11-06 |
| [AgentTesla 阶段 DLL 还原两法：SimpleLogin.dll 用 22 字节滚动 key 异或后减后一字节（原地反馈），Gamma.dll 实为压缩包用归档工具解出 [Content]](code-analysis-reverse-unpacking-agenttesla-stage-dll-xor-subtract-archive.md) | verified | medium | 2026-11-08 |
| [ClassFinal 加密 JAR 逆向：javaagent 运行时解密 + Arthas 枚举、反编译并修改已加载类](code-analysis-reverse-unpacking-classfinal-javaagent-runtime-class-dump.md) | verified | high | 2026-11-06 |
| [ESP 定律失效时的回退：PUSHAD 后栈断点被 SEH 注册干扰，改用栈顶访问断点 + 代码段内存断点定位 OEP](code-analysis-reverse-unpacking-esp-law-seh-fallback-oep.md) | verified | high | 2026-11-08 |
| [fwrite 静态缓冲区释放内嵌 PE：按固定长度从 .data 提取二阶段驱动](code-analysis-reverse-unpacking-fwrite-static-buffer-embedded-pe.md) | verified | high | 2026-11-06 |
| [IAT 全部重定向（API Redirect）的识别与修复：NOP 关键跳转保留 API 地址，或从另一 OEP 实例二进制复制 IAT](code-analysis-reverse-unpacking-iat-redirect-key-jump-nop-two-instance-copy.md) | verified | high | 2026-11-08 |
| [JVMTI Agent（-agentpath:*.so）加密 class 脱壳：Frida 远程 hook libjvm 的 JvmtiExport::post_class_file_load_hook 取解密后字节码](code-analysis-reverse-unpacking-jvmti-classfileloadhook-frida-dump.md) | verified | high | 2026-11-08 |
| [NSIXloader（NSIS 恶意封包器）静态解包：7-Zip 提取 + DLL 密钥正则 + shellcode 逐字节运算模拟还原载荷](code-analysis-reverse-unpacking-nsis-nsixloader-static-unpack.md) | verified | medium | 2026-11-08 |
| [NSpark/ASPack 压缩壳用 x32dbg 单步手脱：F8 掠过解压循环、在壳尾 jne/ret 处 F4 跳入，到 OEP 直接 dump 且不修 IAT 可直接用](code-analysis-reverse-unpacking-nspark-aspack-x32dbg-single-step-oep-dump.md) | verified | medium | 2026-11-09 |
| [OD 脱壳：VirtualAlloc 断点按分配大小筛出载荷，首字节硬件访问断点跟到 MZ 后 dump 解密 PE](code-analysis-reverse-unpacking-virtualalloc-size-hwbp-pe-dump.md) | verified | high | 2026-11-10 |
| [OllyDbg RUN 跟踪停止条件 + ImportREC 插件/Tracer 分级修复 IAT（复杂壳/IAT 重定向）](code-analysis-reverse-unpacking-ollydbg-run-trace-condition-importrec-tracer.md) | verified | high | 2026-11-08 |
| [OllyDbg 二次断点法/内存镜像法定位 OEP：先断 .rsrc 再断 .text/.code，命中后单步收尾](code-analysis-reverse-unpacking-two-stage-section-breakpoint-oep.md) | verified | high | 2026-11-08 |
| [PE 加载器：LCG 派生 ChaCha20 key/nonce 解密二阶段 PE](code-analysis-reverse-unpacking-pe-loader-lcg-chacha20.md) | verified | high | 2026-11-06 |
| [pyc 字节码去花：删除 co_code 中的 JUMP/垃圾指令并修正 co_code 长度，恢复反编译与运行](code-analysis-reverse-unpacking-pyc-bytecode-junk-remove-co-code-length.md) | verified | high | 2026-11-13 |
| [PyInstaller --key 加密 PYZ：pyimod00_crypto_key 取密钥 + 按版本分流 PyCrypto-CFB/tinyaes-CTR 解密 pyc.encrypted](code-analysis-reverse-unpacking-pyinstaller-key-encrypted-pyz-pyc-decrypt.md) | verified | high | 2026-11-07 |
| [PyInstaller EXE 二次打包：spec TOC 注入与 CArchive 手工重写](code-analysis-reverse-unpacking-pyinstaller-repack-spec-carchive-toc.md) | verified | high | 2026-11-05 |
| [PyInstaller EXE 识别与解包：CArchive/PYZ/pyc 提取还原源码](code-analysis-reverse-unpacking-pyinstaller-carchive-pyz-extract.md) | verified | high | 2026-11-05 |
| [PyInstaller pyc 反编译不全时用 pycdas 反汇编：从 Names/Constants 表直取硬编码 AES 密钥，按 LOAD_NAME/LOAD_METHOD/CALL_METHOD 还原解密调用链](code-analysis-reverse-unpacking-pycdas-constants-key-disassembly.md) | verified | high | 2026-11-10 |
| [PyInstaller pyd 内嵌 XOR 加密 marshal code object：IDA dump + 循环异或还原 pyc](code-analysis-reverse-unpacking-pyinstaller-pyd-xor-marshal-code-object.md) | verified | high | 2026-11-07 |
| [PyInstaller 加载器：EXE 尾部追加 ZIP + 16 字节 footer（ZIP 大小/magic），解压到临时目录并启动诱饵与木马](code-analysis-reverse-unpacking-pyinstaller-appended-zip-footer-dropper.md) | verified | high | 2026-11-06 |
| [Python 恶意样本多层套娃：base64+gzip/bz2/lzma/zlib → compile/exec → reverse+marshal co_consts 链还原](code-analysis-reverse-unpacking-python-nested-marshal-consts-chain.md) | verified | high | 2026-11-07 |
| [Speakeasy 仿真运行 UPX 样本并 dump 内存：定位 Base64 内嵌 PE 二阶段](code-analysis-reverse-unpacking-speakeasy-memory-dump-base64-pe.md) | verified | high | 2026-11-06 |
| [Themida 3.x 用 unlicense 跟踪 OEP dump 脱壳 + 花指令 NOP：魔改 RC4 与 TEA 逆运算还原 flag](code-analysis-reverse-themida-unlicense-oep-rc4-tea.md) | verified | high | 2026-11-07 |
| [UPX 壳的手动脱壳流程](upx-manual.md) | draft | high | 2026-11-04 |
| [UPX 手动脱壳实战：x64dbg 栈硬件断点定位 POPAD/OEP 并用 Scylla 转储修复 IAT](code-analysis-reverse-unpacking-upx-manual-esp-breakpoint-scylla.md) | verified | high | 2026-11-07 |
| [VB 程序特征脱壳：断 MSVBVM60/50 .text 的 ThunRTMain，从栈返回地址定位 OEP](code-analysis-reverse-unpacking-vb-thunrtmain-breakpoint-oep.md) | verified | high | 2026-11-08 |
| [VMProtect 压缩壳手动脱壳：Sleep 断点 + MSVC security cookie 定位 OEP + VMPImportFixer 修复导入](code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix.md) | verified | medium | 2026-11-07 |
| [WriteProcessMemory 断点抓进程替换最终载荷 + 内存块 PE 雕刻：DOS Stub 串回退 0x4E 定位 PE 头、末节算大小、SHA256 去重与尾部 16 字节零校验](code-analysis-reverse-unpacking-writeprocessmemory-memory-block-pe-carve.md) | verified | high | 2026-11-08 |
| [XJar 加密 JAR 逆向：从启动器参数与 VisualVM 堆转储提取 AES key/iv 解密 class](code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key.md) | verified | high | 2026-11-06 |
| [Zend Guard 编码 PHP 文件识别与 SeayDZend 批量还原（通达OA webroot 实例）](code-analysis-reverse-unpacking-zend-guard-seaydzend-restore.md) | verified | medium | 2026-11-08 |
| [一步直达法：搜索 POPAD(0x61)/JMP(E9/EB/FF25)/CALL(E8/FF96) 机器码快速逼近 OEP](code-analysis-reverse-unpacking-opcode-search-popad-jmp-call-oep.md) | verified | high | 2026-11-08 |
| [从 V8 code cache 头部版本哈希反推引擎版本：base::hash_combine(major,minor,build,patch) 小空间爆破](code-analysis-reverse-unpacking-v8-bytecode-version-hash-recover.md) | verified | medium | 2026-11-08 |
| [改版 UPX x64 无执行脱壳：节表异常识别 + Unicorn 仿真 stub dump](code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation.md) | verified | high | 2026-11-06 |
| [改版 UPX 区段名还原：SAUY/YSYY/C4RP 改回 UPX0/UPX1/UPX2 后用 upx -d 脱壳](code-analysis-reverse-unpacking-upx-section-name-restore.md) | verified | high | 2026-11-06 |
| [无 asar 的 Electron 客户端：按 ByteCodeInfo 结构数组与「?? ?? DE C0」魔数从 .node 加壳模块批量导出内嵌 V8 字节码](code-analysis-reverse-unpacking-v8-bytecodeinfo-embedded-code-cache-extract.md) | verified | high | 2026-11-08 |
| [无 PUSHAD 的 FSG 壳脱壳：条件记录断点收集 GetProcAddress 地址，循环末尾条件断点跟到 OEP](code-analysis-reverse-unpacking-fsg-conditional-log-breakpoint-oep.md) | verified | high | 2026-11-08 |
| [末次异常法：统计异常次数 m，重载后按 m-1 次 Shift+F9，再于 code 段断点定位 OEP](code-analysis-reverse-unpacking-last-exception-count-oep.md) | verified | high | 2026-11-08 |
| [读懂 V8 字节码反汇编的伪 JS：参数/寄存器/累加器模型与 LdaNamedProperty、Star/Mov、CallWithSpread 的还原规则](code-analysis-reverse-unpacking-v8-bytecode-register-semantics-to-js.md) | verified | high | 2026-11-08 |
| [魔改 V8 源码造字节码反汇编器：注释 PrintSourceCode、插入 Start/End BytecodeArray 标记、关掉 SanityCheck 与魔数校验后喂 .jsc](code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch.md) | verified | high | 2026-11-08 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
