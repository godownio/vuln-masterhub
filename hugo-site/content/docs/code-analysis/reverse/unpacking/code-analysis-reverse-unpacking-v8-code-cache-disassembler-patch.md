---
id: code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch
title: 魔改 V8 源码造字节码反汇编器：注释 PrintSourceCode、插入 Start/End BytecodeArray 标记、关掉 SanityCheck 与魔数校验后喂 .jsc
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: v8-code-cache-disassembler-patch
tags:
- v8
- bytenode
- code-cache
- disassembler
- source-patch
- electron
- node
- unpacking
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:52:50+08:00'
  notes: 已对照原文核对：SanityCheck 恒返回 kSuccess、SharedFunctionInfoPrint 注释 PrintSourceCode 并插入 Disassemble、objects.cc 各分支插入 Start/End 标记、string.cc 去截断、deserializer.cc 注释 CHECK_EQ 魔数、v8gen/args.gn/ninja v8_monolith、v8dasm 驱动与 clang++ 编译参数、Start BytecodeArray/常量池输出样例均与原文及图 20 一致。未验证点：未实际编译 V8；V12 沙箱初始化差异原文仅提示未展开。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-unpacking-v8-code-cache-disassembler-patch/
draft: false
kb_aliases:
- v8dasm
- View8
- V8 字节码反汇编
- SerializedCodeData SanityCheck 绕过
- SharedFunctionInfoPrint
- Start BytecodeArray
- bytenode 反编译
---

## 一句话结论

V8 本身只会对「从源码编译」的函数打印字节码，要对一份脱离源码的 `.jsc` 打印，需要把同版本 V8 源码改三处：在 `SerializedCodeData::SanityCheck` 直接返回 `kSuccess`（绕过 source hash 校验）、在 `SharedFunctionInfo::SharedFunctionInfoPrint` 里注释掉 `PrintSourceCode(os)` 并插入 `Disassemble(os)` 调用、在 `objects.cc`/`string.cc` 的打印分支插入 `Start/End` 标记（并去掉字符串截断、放开 `ArrayBoilerplateDescription` 常量池打印）；编译出 `v8_monolith` 后写一个十几行的驱动只做 `ScriptCompiler::CompileUnboundScript(..., kConsumeCodeCache)`，反序列化过程就会把每条指令与常量池打印出来。

## 原理

- 反序列化 code cache 的入口是 `CodeSerializer::Deserialize` → `SerializedCodeData::SanityCheck(expected_source_hash)`：后者对比头部 `kSourceHashOffset` 与实际源码哈希，不匹配即失败。`.jsc` 只有字节码没有源码，所以必须让它恒返回 `kSuccess`（原文做法），否则根本走不到打印逻辑。
- 打印点必须挂在反序列化完成之后：`Deserialize` 里拿到 `result`（`SharedFunctionInfo`）后调 `result->SharedFunctionInfoPrint(std::cout)`，这一步会遍历 `SharedFunctionInfo` 的元信息、`BytecodeArray`、常量池与 scope 信息。
- `SharedFunctionInfoPrint` 自带 `PrintSourceCode(os)`，对没有源码的 code cache 会输出乱码/崩溃，必须注释；替换为 `this->GetActiveBytecodeArray().Disassemble(os)` —— `BytecodeArray::Disassemble` 才是真正逐条打印 `opcode + operands` 的函数，正常只在 `--print-bytecode` 编译时被调用。
- 常量池要能读：`BytecodeArray` 的常量池是 `FixedArray`，元素可能是 `ObjectBoilerplateDescription`（对象字面量）、`ArrayBoilerplateDescription`（数组字面量）、字符串等。`HeapObjectShortPrint` 默认对 `ASM_WASM_DATA_TYPE`/`FIXED_ARRAY_TYPE`/`OBJECT_BOILERPLATE_DESCRIPTION_TYPE`/`FIXED_DOUBLE_ARRAY_TYPE` 只打印类型与长度，所以要在这些分支里插入对应的 `*Print(os)`，常量（例如 `#send`、`#ipcRenderer` 这类私有字段名）才会显示出来。
- `String::StringShortPrint` 里有 `len > kMaxShortPrintLength` 就输出 `...<truncated>>` 的截断逻辑，注释掉才能看到完整字符串常量（很多 payload 是长 base64/URL）。
- 标记 `Start BytecodeArray`/`End BytecodeArray`/`Start SharedFunctionInfo`/`Start FixedArray` 等是给下游解析器（View8）切分用的分节符，不要改名。
- 魔数校验要单独处理：若字节码魔数与当前编译的 V8 不一致（`Deserializer<IsolateT>::Deserializer` 里的 `CHECK_EQ(magic_number_, SerializedData::kMagicNumber)`），程序直接 abort；注释该 CHECK 可强行继续（不保证语义正确）。
- 沙箱/压缩指针：V8 11+ 的 pointer compression / sandbox 需要一致编译开关，否则反序列化布局对不上；Electron 目标编译时要带 `V8_COMPRESS_POINTERS`，V12 还要额外初始化沙箱上下文代码，否则 `wee8` 初始化的 Isolate 在沙箱模式下不可用。
- 为什么要自己编译而不是用现成 `d8`：官方 `d8 --print-bytecode` 只接受源码；接受 `.jsc` 需要改 `SanityCheck` 并挂打印点，属源码级改动。

## 触发条件

- 已有一份与目标匹配的 V8 源码 tag（版本由魔数后 4 字节的版本哈希逆推，或用二进制内版本串确认）。
- 目标字节码来自 V8 11 之前或能对上编译开关（压缩指针/沙箱）的构建；原文明确指出 V8 12.* 反编译未成功。
- 具备编译环境（depot_tools + ninja + clang，30 分钟到 1 小时，建议 SSD/16G/16 核）。
- 不需要目标机器，纯离线；但绝不能把改过的 V8 拿去跑不可信字节码以外的用途（本卡只用于读字节码）。

## 利用步骤

1. 装依赖 `ninja-build clang pkg-config`，clone `depot_tools` 并加入 PATH，`fetch v8` 后 `git checkout refs/tags/<版本哈希逆推出的 tag>`，再 `gclient sync -D`。
2. 改 `src/snapshot/code-serializer.cc`：`SerializedCodeData::SanityCheck` 直接 `return SerializedCodeSanityCheckResult::kSuccess;`；在 `CodeSerializer::Deserialize` 反序列化成功后的位置（`if (FLAG_profile_deserialization) PrintF("[Deserializing failed]")` 之后）插入 `result->SharedFunctionInfoPrint(std::cout);` 与 `Start/End SharedFunctionInfo` 标记。
3. 改 `src/diagnostics/objects-printer.cc`：在 `SharedFunctionInfo::SharedFunctionInfoPrint` 里注释 `PrintSourceCode(os);`，插入 `os << "\nStart BytecodeArray\n"; this->GetActiveBytecodeArray().Disassemble(os); os << "\nEnd BytecodeArray\n";`。
4. 改 `src/objects/objects.cc`：在 `HeapObject::HeapObjectShortPrint` 的 `ASM_WASM_DATA_TYPE`、`FIXED_ARRAY_TYPE`、`OBJECT_BOILERPLATE_DESCRIPTION_TYPE`、`FIXED_DOUBLE_ARRAY_TYPE`、`SHARED_FUNCTION_INFO_TYPE` 各分支插入对应 `*Print(os)`；`src/objects/string.cc` 里注释 `kMaxShortPrintLength` 的截断 return。
5. 如魔数不匹配，注释 `src/snapshot/deserializer.cc` 里的 `CHECK_EQ(magic_number_, SerializedData::kMagicNumber);`。
6. `./tools/dev/v8gen.py x64.release` 生成 `out.gn/x64.release/args.gn`，写入 `v8_monolithic = true`、`v8_static_library = true`、`v8_enable_disassembler = true`、`v8_enable_object_print = true`、`v8_use_external_startup_data = false`、`is_debug = false`（Node 目标另加 `v8_enable_pointer_compression = false`），然后 `ninja -C out.gn/x64.release v8_monolith`。
7. 写驱动（v8dasm 思路）：`V8::SetFlagsFromString("--no-lazy --no-flush-bytecode")` → 初始化平台/Isolate → 把 `.jsc` 全量读入 `ScriptCompiler::CachedData` → `ScriptCompiler::Source`（源文本随便给一个占位字符串）→ `ScriptCompiler::CompileUnboundScript(isolate,&source,kConsumeCodeCache)`；反序列化过程中即打印指令与常量池。
8. 编译驱动：Electron 目标 `clang++ v8dasm.cpp -std=c++17 -Iinclude -Lout.gn/x64.release/obj -lv8_libbase -lv8_libplatform -lv8_monolith -DV8_COMPRESS_POINTERS -ldl -pthread -o v8dasm`；Node 目标去掉 `-DV8_COMPRESS_POINTERS`。
9. 运行 `./v8dasm test.jsc > test.asm`，再用下游解析器把伪汇编还原成可读 JS。

## PoC

```cpp
// 最小驱动：把 .jsc 当 code cache 消费，靠改过的 V8 打印反汇编（原文 v8dasm 思路精简）
#include <fstream>
#include <iostream>
#include "libplatform/libplatform.h"
#include "v8.h"
using namespace v8;

static void loadBytecode(uint8_t* buf, int len) {
  Isolate* iso = Isolate::GetCurrent();
  auto* cached = new ScriptCompiler::CachedData(buf, len);
  ScriptOrigin origin(iso, String::NewFromUtf8Literal(iso, "code.jsc"));
  ScriptCompiler::Source source(String::NewFromUtf8Literal(iso, "\"x\""), origin, cached);
  // 反序列化发生在这里；改过的 V8 会打印 Start SharedFunctionInfo / BytecodeArray / 常量池
  MaybeLocal<UnboundScript> s =
      ScriptCompiler::CompileUnboundScript(iso, &source, ScriptCompiler::kConsumeCodeCache);
  (void)s;
}

int main(int argc, char** argv) {
  V8::SetFlagsFromString("--no-lazy --no-flush-bytecode");
  V8::InitializeICU();
  std::unique_ptr<Platform> p = platform::NewDefaultPlatform();
  V8::InitializePlatform(p.get());
  V8::Initialize();
  Isolate::CreateParams cp;
  cp.array_buffer_allocator = ArrayBuffer::Allocator::NewDefaultAllocator();
  Isolate* iso = Isolate::New(cp);
  Isolate::Scope is(iso);
  HandleScope hs(iso);
  std::ifstream in(argv[1], std::ios::binary);
  std::vector<char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  loadBytecode(reinterpret_cast<uint8_t*>(data.data()), (int)data.size());
}
```

```text
# 期望输出（节选）：指令 + 常量池
Start BytecodeArray
Parameter count 2
Register count 7
  0 : 8d            CreateRestParameter
  1 : c8            Star2
  8 : 17 02         LdaImmutableCurrentContextSlot [2]
 13 : 2f f5 01 00   GetNamedProperty r4, [1], [0]
 29 : 67 f6 f5 03 04 CallWithSpread r3, r4-r6, [4]
 35 : af            Return
Constant pool (size = 3)
 1: <String[11]: #ipcRenderer>
 2: <String[4]: #send>
End BytecodeArray
```

## 变体与关联

- 变体：不改源码，改用官方 `d8` 的 `--print-bytecode-filter` 不可行（无源码）；只能 patch 或自己实现 `BytecodeArray` 遍历。
- 变体：只需常量池/字符串时，可以在 `SanityCheck` 返回成功后只保留 `HeapObjectShortPrint` 的 `FixedArray` 分支，输出更小更好读。
- 变体：把打印点改成写文件（`std::ofstream`）避免 stdout 缓冲丢失；原文用 `std::flush`。
- 关联：[[code-analysis-reverse-unpacking-v8-bytecodeinfo-embedded-code-cache-extract]]（字节码来源）、[[code-analysis-reverse-unpacking-v8-bytecode-version-hash-recover]]（决定 checkout 哪个 tag）、[[code-analysis-reverse-unpacking-v8-bytecode-register-semantics-to-js]]（反汇编文本转伪 JS）。
- 边界：V8 12.* 引入沙箱/更严格校验，原文实测未反编译成功；启用 `is_debug` 会导致反汇编报错；指针压缩开关与目标不一致时反序列化失败或常量错乱。

## 检测与防御

- 检测（分析方）：`SanityCheck`/`CHECK_EQ(magic_number_)` 被注释、`SharedFunctionInfoPrint` 中 `PrintSourceCode` 被注释并混入 `Disassemble`——这是自定义反汇编器的典型指纹。
- 防御（开发方）：不要把 code cache 当成保护手段；任何拿到 `.jsc` 的人都能用这套流程还原出指令与常量池（含私有字段名、URL、JSON 结构）。
- 加固：客户端只保留协议与展示逻辑，敏感常量/密钥服务端下发；对 addon 做签名与完整性校验，对 `.jsc` 二次加密只能提高成本。
