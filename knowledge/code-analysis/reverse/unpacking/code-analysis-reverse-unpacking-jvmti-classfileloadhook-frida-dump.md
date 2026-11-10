---
id: code-analysis-reverse-unpacking-jvmti-classfileloadhook-frida-dump
title: JVMTI Agent（-agentpath:*.so）加密 class 脱壳：Frida 远程 hook libjvm 的 JvmtiExport::post_class_file_load_hook 取解密后字节码
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: jvmti-classfileloadhook-frida-post-hook-dump
aliases:
- JVMTI Agent 脱壳
- ClassFileLoadHook dump
- -agentpath so 加密
- post_class_file_load_hook
- Frida 远程 hook JVM
- libjvm.so 基址
- Symbol _length 偏移
tags:
- code-analysis
- reverse
- unpacking
- java
- jar
- jvmti
- javaagent
- frida
- classfileloadhook
cve: []
severity: medium
confidence: high
status: verified
created: '2026-02-26'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:55:04+08:00'
  notes: 已对照原文核对：-agentpath:*.so 型壳判定、Agent_OnLoad/JVMTI ClassFileLoadHook 回调机制、jvmtiExport.cpp 的 post_to_env 与 post_class_file_load_hook 源码片段、Symbol 布局与 +2/+8 偏移、args[3]/args[4] 为 unsigned char** 的解引用时序、dlopen 捕获基址、偏移 0x7A5C60、frida-server 与 frida -H -f 用法、dump 出的 class 可反编译均与原文及图 06/08/09/10 一致。原文正文一处写 libjava.so，卡片统一写 libjvm.so（与原文脚本 Module.findBaseAddress(libjvm.so) 一致），属对原文笔误的修正。未验证点：Frida 脚本未执行；0x7A5C60 为原文特定 JDK 版本偏移，卡片已注明必须完全一致。
---

## 一句话结论

目标 JAR 的 class 被本地 JVMTI Agent（`-agentpath:./xxxagent.so`，不是常见的 `-javaagent:*.jar`）在类加载时解密，静态反编译全是空壳；但 JVM 自身在把 class 字节交给解析器前必须经过 `JvmtiExport::post_class_file_load_hook()` 并把 `data_ptr`/`end_ptr` 更新为解密后的明文，所以用 Frida 远程 attach、在 `libjvm.so` 里 hook 这个函数，在 `onLeave` 读 `*data_ptr` 到 `*end_ptr` 的区间直接写盘，即可在无需逆清 so 解密算法的前提下还原出明文 class。

## 原理

- **下壳类型判定**：JVM 启动参数形如 `java -Dsun.misc.URLClassPath.disableJarChecking=true -agentpath:./xxxagent.so -jar app.jar`。`-agentpath` 加载的是本地动态库（ELF64，Detect It Easy 显示 AMD64/DYN），入口是 `Agent_OnLoad(JavaVM*, char*, void*)`，与 `-javaagent:*.jar` 的 `premain` 完全不同。IDA 打开后常见 `SHT table size or offset is invalid` 告警、函数体残缺，静态逆成本高，所以要走运行时路线。
- **JVMTI 的解密时机**：Agent 在 `Agent_OnLoad` 中 `vm->GetEnv(..., JVMTI_VERSION)` 拿 `jvmtiEnv`，`SetEventCallbacks` 注册 `ClassFileLoadHook` 回调，再 `SetEventNotificationMode(JVMTI_EVENT_CLASS_FILE_LOAD, JVMTI_ENABLE, nullptr)` 打开事件。此后每次类加载/redefine/retransform，JVM 都会回调这个函数，Agent 在回调里把密文解密写进 `new_class_data`/`new_class_data_len` 交还给 JVM。
- **为什么 hook JVM 比 hook Agent 稳**：Agent 的 so 一般被加固（符号剥离、函数体混淆、加密常量），`ClassFileLoadHook` 函数地址难以定位；而 JVM 侧的分发入口是公开源码里固定的符号：`hotspot/src/share/vm/prims/jvmtiExport.cpp` 中 `JvmtiExport::post_class_file_load_hook(Symbol* h_name, Handle class_loader, Handle h_protection_domain, unsigned char** data_ptr, unsigned char** end_ptr, JvmtiCachedClassFileData** cache_ptr)`，内部构造 `JvmtiClassFileLoadHookPoster` 并 `poster.post()`，最终在 `post_to_env()` 里取出 `env->callbacks()->ClassFileLoadHook` 调用。只要 hook 这一处，就等于在所有 Agent 之上拿到"已解密"的那一份。
- **参数语义**：`data_ptr` 是「指向当前 class 字节首地址的指针的指针」，`end_ptr` 是「指向末尾地址的指针的指针」。函数执行前 `*data_ptr` 是密文（或上一个 agent 处理过的数据），执行后若 Agent 修改了数据，JVM 会把 `*data_ptr`/`*end_ptr` 更新为解密结果（`_curr_data`/`_curr_len`）。因此在 `onEnter` 保存 `args[3]`、`args[4]` 这两个**指针的地址**，在 `onLeave` 再 `readPointer()` 解引用，就能读到明文区间；长度用 `endPtr - ptr` 计算。
- **类名从 Symbol 读**：第一个参数 `h_name` 是 HotSpot 内部 `Symbol*`，不是 C 字符串。其布局为 `_refcount(2) | _length(2) | _identity_hash(4) | _body[]`，所以 `length = *(uint16*)(sym+2)`，`body` 从 `sym+8` 开始，读 `length` 字节再按 UTF-8 解码即得内部类名（如 `com/xxx/ParamCheck`），替换 `/` 为 `.` 后作为文件名。
- **为什么这样能"全量"脱壳**：拦截点在 `ClassFileParser::parseClassFile` 之前，JVM 还没解析字节码；即使该类依赖缺失、字节码校验失败、加载最终失败，`post_class_file_load_hook` 也已经把明文放在内存里，dump 依然成功。再写一个 classloader 主动触发加载全部 class，就能从"只能 dump 已加载类"升级为整包还原。
- **跨平台可行性**：Frida 不止安卓，Linux/Windows 都可远程使用：目标机只跑 `frida-server -l 0.0.0.0:27042`（无需 python 环境），本机 `pip install frida-tools` 后用 `frida-ps -H <ip>` 验证连通，再 `frida -H <ip> -f /bin/java -l hook.js -- -agentpath:./xxx.so -jar app.jar` 以 spawn 方式接管启动（此时进程暂停，可先注入脚本再 `%resume`）。

## 触发条件

- 目标 JAR 的 class 由 JVMTI Agent（`-agentpath:*.so`）在加载时解密，静态反编译为空/失败。
- 攻击者能在目标机启动或 attach 进程（本地调试、测试环境、或在授权范围内对运行中服务注入），并能上传/运行 `frida-server`。
- 目标 JVM 是 OpenJDK 系（源码可对照）且 `JvmtiExport::post_class_file_load_hook` 未被裁剪；模块（`libjvm.so`）可由 `dlopen` 事件捕获其基址。
- 目标 JDK 版本与本地用于 IDA 定位偏移的 `libjvm.so` **完全一致**（否则偏移对不上）。
- 进程未做反注入/反调试（无 Frida 检测、无 ptrace 保护、允许 dlopen 任意库）。

## 利用步骤

1. 确认保护类型：`ps`/启动脚本里看 `-agentpath:*.so`；解压 JAR 用反编译器看 class，若只得到 `// IntelliJ API Decompiler stub ... Implementation of methods is not available`，说明是加载时解密型壳。
2. 从目标机取同版本 JDK 的 `libjvm.so`，IDA 打开（有 `SHT table ... invalid` 告警也可用），在 Functions 窗口搜 `JvmtiExport::post_class_file_load_hook`，记录其偏移（本例 `0x7A5C60`）。
3. 目标机启动 `frida-server -l 0.0.0.0:27042`；本机 `pip install frida-tools`，`frida-ps -H <ip>` 确认能列出进程。
4. 以 spawn 模式启动目标：`frida -H <ip> -l hook.js -f /bin/java -- -agentpath:./xxx.so -jar app.jar`，进程暂停后可在 REPL 里加载脚本、输入 `%resume` 继续。
5. 由于 `libjvm.so` 可能尚未加载，先用 `Interceptor.attach(Module.findExportByName(null,"dlopen"), {...})` 在 `onEnter` 读 `args[0].readCString()`，发现 `libjvm.so` 后在 `onLeave` 执行 hook 逻辑（拿 `Module.findBaseAddress("libjvm.so")` + 偏移）。
6. 在该地址 `Interceptor.attach`：`onEnter` 保存 `args[3]`（data_ptr）、`args[4]`（end_ptr），并用 `Symbol` 布局读 `args[0]` 得到类名；`onLeave` 解引用两端指针、算长度、`readByteArray`，写到 `/<dumpdir>/<name>.class`。
7. 跑完后用反编译器打开 dump 目录确认明文；再写一个 classloader 触发全量加载，重复上述流程补齐未加载的类。

## PoC

关键 Frida 脚本（片段，未在本机执行）：

```javascript
const moduleName = "libjvm.so";
const functionOffset = 0x7A5C60;           // 必须与目标 JDK 完全一致

function getSymbolString(symbolAddr) {
  const length = ptr(symbolAddr).add(2).readU16();   // _length 偏移 2
  const body = ptr(symbolAddr).add(8);               // _body 偏移 8
  return Memory.readUtf8String(body.readByteArray(length), length);
}

function hookFunction() {
  const base = Module.findBaseAddress(moduleName);
  if (base === null) return;
  Interceptor.attach(base.add(functionOffset), {
    onEnter: function (args) {
      this.ptrAddress = args[3];      // unsigned char **data_ptr
      this.endPtrAddress = args[4];   // unsigned char **end_ptr
      this.name = getSymbolString(args[0]);   // Symbol* h_name
    },
    onLeave: function (retval) {
      const p = this.ptrAddress.readPointer();
      const e = this.endPtrAddress.readPointer();
      const len = e.sub(p).toInt32();
      if (len > 0) {
        const data = p.readByteArray(len);
        const path = "/tmp/" + this.name.replaceAll("/", ".") + ".class";
        const f = new File(path, "wb");
        f.write(data); f.flush(); f.close();
        console.log("dump -> " + path);
      }
    }
  });
}

const dlopen = Module.findExportByName(null, "dlopen");
if (dlopen) {
  Interceptor.attach(dlopen, {
    onEnter: function (args) {
      const so = args[0].readCString();
      if (so && so.indexOf(moduleName) !== -1) this.hit = true;
    },
    onLeave: function () { if (this.hit) hookFunction(); }
  });
}
```

运行：

```bash
# 目标机（只需二进制，无需 python）
frida-server -l 0.0.0.0:27042

# 本机
frida-ps -H 192.168.12.1
frida -H 192.168.12.1 -l hook.js -f /bin/java -- -agentpath:./xxx.so -jar ./app.jar
```

## 变体与关联

- 变体：若只想 dump 已加载类而不 hook JVM，可 attach Arthas 用 `sc` + `dump`（同类思路见 ClassFinal 卡），但只能覆盖已加载类。
- 变体：也可 hook JVM 的 `ClassFileParser::parseClassFile` 之后（拿到已定义类），但那时失败加载的类已丢失；`post_class_file_load_hook` 的优势正是"解析前"。
- 变体：`Symbol` 布局随 JDK 大版本可能变化（字段顺序/填充），若读出的类名乱码，改用运行时枚举已加载类名或从 `Klass` 侧取名字做对齐。
- 变体：Windows 平台把 `libjvm.so` 换成 `jvm.dll`、`frida-server` 换成 `frida-server.exe`，其余逻辑一致。
- 关联：[[code-analysis-reverse-unpacking-classfinal-javaagent-runtime-class-dump]]（同为 class 加密壳运行时脱壳；该卡是 javaagent+`ClassFileTransformer`+Arthas，本卡是本地 JVMTI agent+Frida hook JVM 侧 hook 点，载体、hook 点与工具链均不同）。
- 关联：[[code-analysis-reverse-unpacking-xjar-encrypted-class-heap-key]]（同为加密 JAR 脱壳；该卡走 key/iv 堆转储+AES 解密，本卡不需要密钥，直接截获明文）。
- 关联：[[tools-frida-native-hook-export-unexport-retval-constructor]]（Frida 原生 hook 的基础用法）。

## 检测与防御

- 检测（被保护方）：进程列表出现 `frida-server`；`27042` 端口对外监听；JVM 进程内存里出现 `frida-agent`/`frida-gadget` 字符串与注入线程；`libjvm.so` 代码段被修改（inline hook 特征：函数首字节跳转）；异常的 `dlopen` 调用序列。
- 检测（分析方）：`Interceptor.attach` 后 Java 侧行为（如反调试检查）可能变化；若 dump 出的 class 时间戳/哈希与运行时类不符，说明 hook 点选错（应选 `post_class_file_load_hook` 而非 `post_to_env` 内部实现）。
- 防御（厂商侧）：class 加密壳只能提高静态分析成本，不能阻止运行时 dump；真正有效的加固是 JVMTI 层完整性自检（检测本进程被 hook/agent 列表异常）、关键逻辑下沉到 native 并做反调试、服务端校验关键授权而非纯客户端 class 校验。
- 防御：不要以"class 被加密"作为知识产权/授权的唯一防线；核心算法与判定放服务端或做硬件绑定。
