---
id: mobile-android-frida-antidebug-dlsym-fake-pthread-create-offset-patch
title: 加固 App 的 Frida 检测绕过的两条互补手法：Hook dlsym 把 pthread_create 换成空壳函数（让反调试线程根本不启动），或按 so 基址+固定偏移直接替换检测子函数
type: scenario
domain: mobile
path: mobile/android
technique: frida-antidebug-dlsym-fake-pthread-create-offset-replace
aliases:
- dlsym 替换 pthread_create
- 伪造 pthread_create 绕过检测
- Frida 反调试 偏移替换
- 加固 App Frida 检测绕过
- libnllvm so 反调试
- Sub_64D10 替换
- 空壳函数 ret  gadget
- 多 so 反调试链绕过
tags:
- android
- frida
- anti-debug
- native
- hook
- dlsym
- pthread-create
- hardening
- reverse
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:06:14+08:00'
  notes: 已对照原文核对：android_dlopen_ext 定位 libnllvm<后缀>.so、Hook dlsym 见连续两次解析 pthread_create、伪造 Memory.alloc+RWX+Arm64Writer.putRet 空壳函数在 onLeave retval.replace 并 detach、两个 so（libnllvm 与 libface_nllvm）分别替换、以及路径二用 so.base 与 args[2] 相减得 0x64D10（0x7c5c465d10-0x7c5c401000）再 Interceptor.replace 均与原文一致（已读图 06 核对基址/入口地址）。核对中修正 PoC：路径二原写 this.interceptor.detach()，按原文改为闭包变量 interceptor.detach()。未混入 sources/source_url/文章ID/URL；原文未给产品版本区间，不设 affected_versions 正确。未验证点：未在真机上执行脚本。
---

## 一句话结论

当加固 App 在 native 层用 `pthread_create` 起反调试线程、并且为了隐藏调用而通过 `dlsym` 动态取符号时，有两条互补的绕过路径：一是 Hook `dlsym`，在它返回 `pthread_create` 地址时把返回值替换成一个只有 `ret` 指令的空壳函数（反调试线程的入口压根不是真正的 pthread 入口，检测逻辑永远不执行）；二是先用 `pthread_create` 的 `onEnter` 打印“so 基址 + 线程入口地址”算出偏移，再对该 so 内 `基址+偏移` 处的检测子函数做 `Interceptor.replace`。前者对“检测函数本身”动刀、通用于一串 so；后者对“具体检测点”动刀、适合定位到某个子函数后精确清除。

## 原理

- **加固 App 的检测模型**：客户端要检测 Frida，最可靠的位置在 native 层——读 `/proc/self/maps` 找 `frida`/`gadget`、检查 27042 端口、枚举线程名、检查 `TracerPid`。这些动作通常由一个专门线程周期执行，线程入口往往不在对外导出的函数里，而是 so 内部某个子函数。
- **为什么要通过 `dlsym` 拿 `pthread_create`**：加固/混淆常把关键 API 改成运行时解析（`dlsym(RTLD_DEFAULT, "pthread_create")`），而不是直接 PLT 调用；这样静态交叉引用看不到线索，也方便做完整性校验。原文正是 Hook `dlsym` 后才看到 `libnllvm<随机后缀>.so` 加载后连续两次 `dlsym("pthread_create")`。
- **路径一：伪造 `pthread_create` 返回值**。`dlsym` 的语义是“返回符号地址”，只要在 `onLeave` 里把返回值替换成自己分配的可执行内存，目标 so 后续对“假 pthread_create”的调用就落到空壳函数上：`Memory.alloc(4096)` + `Memory.protect(..., "rwx")` + `Memory.patchCode(..., code => new Arm64Writer(code, {pc}).putRet())` 生成一个“立刻 ret”的函数（ARM64 的 `ret` 指令），返回值为 0（成功）。反调试线程的启动请求被吞掉，检测逻辑从未运行；而 `interceptor.detach()` 保证只替换第一次、避免影响后续正常线程创建。
- **为什么对两个 so 各替换一次**：加固常把同一套检测复制到多个 so（原文先是 `libnllvm1717052779924.so`，绕过它之后又卡在 `libface_nllvm.so`）。`dlsym` 的 hook 需要在每次目标 so 加载时重新挂上，因此把“加载时挂 dlsym hook”放在 `android_dlopen_ext` 的 `onEnter` 里，用文件名匹配两个 so。
- **路径二：按偏移精确替换子函数**。直接 Hook 全局 `pthread_create` 会导致 App 白屏/强制退出（因为真正的 `pthread_create` 调用被全局拦截，线程创建语义被破坏）。可行做法是只在 `pthread_create` 的 `onEnter` 里读信息、不做替换：`Process.findModuleByName("<so>").base` 给出基址，`args[2]` 给出线程入口地址，两者相减得到偏移（原文算出 `0x64D10`）；随后对 `so.base.add(0x64D10)` 用 `Interceptor.replace` 换成空 `NativeCallback`，精确清掉这个检测子函数，同时 `interceptor.detach()` 归还真正的 `pthread_create`。
- **两条路径的取舍**：dlsym 伪造法不需要知道检测函数在 so 里的位置、可以批量套用到多个 so，但依赖目标确实通过 `dlsym` 取符号（直接 PLT 调用就失效）；偏移替换法依赖“基址+偏移”稳定（so 未重打包、未随机化到不同版本），但能精确到子函数、不影响线程创建语义。原文对两个 so 都用了 dlsym 伪造；偏移法是其补充分析。
- **前置条件**：设备已 root、可运行 frida-server 并 spawn 目标进程；App 未使用内核级/硬件级反调试（否则连 Frida 附加都失败）；反调试逻辑由可 Hook 的 libc 导出函数（`android_dlopen_ext`、`dlsym`、`pthread_create`）串起来。

## 触发条件

- 目标 App 为加固/加密企业版产物，native 层存在 Frida 检测线程，且检测线程通过 `pthread_create` 创建。
- 加固实现通过 `dlsym`（而非直接调用）获取 `pthread_create` 或其它检测 API，或在 so 内部存在可定位的检测子函数。
- 测试设备已 root 且能 attach/spawn（Magisk Delta + Shamiko/Zygisk 等可先解决 root 检测）。
- App 未启用不可绕过的 RASP/内核级反调试。
- 仅限授权逆向与安全研究。

## 利用步骤

1. **先绕 root 检测**：即使 native 检测是重点，Java 层可能仍会检查 `/system/xbin`、`/system/bin`、`/sbin`、`/vendor/bin`、`/su/bin` 等路径；用 Magisk Delta 的 App 白名单或 Shamiko 把目标 App 的 root 访问置为“拒绝”即可。
2. **Hook `android_dlopen_ext` 定位检测 so**：打印每次 `dlopen` 的文件名；Frida 在加载某个 so 后进程被杀，即该 so 为检测载体（原文为 `libnllvm<后缀>.so`，绕过它后又出现 `libface_nllvm.so`）。
3. **Hook `dlsym` 观察符号解析**：在目标 so 加载后挂 `dlsym`，打印 `args[1]` 的符号名；看到连续两次 `pthread_create` 说明检测线程要走这条路径。
4. **生成空壳函数**：分配 RWX 内存，用 `Arm64Writer.putRet()`（32 位设备用 `ThumbWriter`/`ArmWriter`）写入一条返回指令，得到“看起来是 pthread_create、实际什么也不做”的函数。
5. **替换 `dlsym` 返回值**：在 `dlsym` 的 `onLeave` 里 `retval.replace(fake)`，并立刻 `interceptor.detach()`，保证只影响目标 so 的第一次解析。
6. **按 so 重挂 hook**：把“目标 so 加载 → 挂 dlsym”的逻辑放进 `android_dlopen_ext` 的 `onEnter`，用文件名匹配（`indexOf("<so 关键字>") >= 0`）覆盖多个检测 so。
7. **验证**：日志里目标 so 加载后不再出现“进程终止”，App 正常进入；此时可继续 Frida Hook 业务逻辑。
8. **偏移替换（可选，路径二）**：改为只 Hook `pthread_create` 的 `onEnter` 打印 `Process.findModuleByName("<so>").base` 与 `args[2]`，相减得偏移；再用 `Interceptor.replace(module.base.add(offset), new NativeCallback(() => {}, 'void', []))` 清掉检测子函数，然后 `detach()` 归还 `pthread_create`。
9. **回归**：替换后确认业务功能正常（不是被“静默杀死”），并用 `frida-ps`/自身日志确认 Frida 仍存活。

## PoC

路径一（dlsym 返回空壳 `pthread_create`，含两个 so 的匹配）：

```javascript
var fake_pthread_create = create_fake_pthread_create();
var dlopen_interceptor = hook_dlopen();

function create_fake_pthread_create() {
  const p = Memory.alloc(4096);
  Memory.protect(p, 4096, "rwx");
  Memory.patchCode(p, 4096, code => {
    const cw = new Arm64Writer(code, { pc: ptr(p) });
    cw.putRet();          // 只有一条 ret 的“函数”
  });
  return p;
}

function hook_dlsym() {
  var interceptor = Interceptor.attach(Module.findExportByName(null, "dlsym"), {
    onEnter: function (args) {
      console.log("[dlsym]", ptr(args[1]).readCString());
    },
    onLeave: function (retval) {
      retval.replace(fake_pthread_create);   // 关键：把返回的 pthread_create 地址换掉
      interceptor.detach();                  // 只替换一次，避免影响后续
    }
  });
  return interceptor;
}

function hook_dlopen() {
  Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
    onEnter: function (args) {
      this.fileName = args[0].readCString();
      console.log("dlopen onEnter:", this.fileName);
      if (this.fileName.indexOf("libnllvm1717052779924.so") >= 0 ||
          this.fileName.indexOf("libface_nllvm.so") >= 0) {
        hook_dlsym();
      }
    },
    onLeave: function (retval) {
      console.log("dlopen onLeave:", this.fileName);
    }
  });
}
```

路径二（算偏移后替换检测子函数，原文偏移 `0x64D10`）：

```javascript
function hook_pthread_and_patch() {
  // 用闭包变量保存 interceptor，onEnter 内才能 detach（原文即此写法）
  var interceptor = Interceptor.attach(Module.findExportByName(null, "pthread_create"), {
    onEnter: function (args) {
      const mod = Process.findModuleByAddress(ptr(this.returnAddress));
      if (!mod) return;
      const so = Process.findModuleByName("libnllvm1717052779924.so");
      if (!so) return;
      console.log("so base =", so.base, "thread entry =", args[2]);
      // 偏移 = args[2] - so.base（原文由 0x7c5c465d10 - 0x7c5c401000 算得 0x64D10）
      Interceptor.replace(so.base.add(0x64d10), new NativeCallback(function () {
        console.log("hook_sub_64d10 replaced");
      }, "void", []));
      interceptor.detach();
    }
  });
}
```

预期日志：目标 so 加载后出现 `[dlsym] pthread_create` / `=== EXIT ===`，随后 App 不再 `Process terminated`，业务界面可正常进入。

## 变体与关联

- **路径变体**：直接 Hook `pthread_create` 全量替换入口（`mobile-android-native-frida-antidebug-thread-bypass` 的 4.7.3 做法）会破坏线程创建语义，导致白屏/卡死；本卡强调“局部伪造 dlsym 返回值”与“只在 onEnter 读信息、按偏移替换子函数”这两种更稳的形态。
- **架构变体**：arm64 用 `Arm64Writer` + `putRet()`，arm32 用 `ThumbWriter`/`ArmWriter`，x86 用 `X86Writer`；纯数据返回可用 `NativeCallback` 返回 0。
- **检测面变体**：除 `dlsym("pthread_create")`，还可对 `dlsym` 取 `open`/`fopen`/`syscall`/`ptrace` 的返回值做伪造（例如伪造 `open` 让 `/proc/self/maps` 打开失败），思路相同：**在符号解析层动手，绕开具体检测实现**。
- **加固变体**：so 名带随机后缀（`libnllvm1717052779924.so`）说明加固会在打包时重命名 so，匹配逻辑要用前缀（`libnllvm`、`libface_nllvm`）而不是全名；同类加固还会把检测复制到多个 so（原文绕过第一个后遇到第二个）。
- 关联：[[mobile-android-native-frida-antidebug-thread-bypass]]（同族场景：dlopen 定位 so + pthread_create 线程入口替换 + 精准替换只第一条线程；本卡是该思路的两条不同落点）。
- 关联：[[mobile-android-anti-detection-root-emulator-proxy]]（root/模拟器/代理检测的 Java 层绕过，本卡前置的 root 白名单/Shamiko 也在此类）。
- 关联：[[mobile-android-encrypted-so-runtime-dlopen-extraction]]（同样 Hook `dlopen`/`android_dlopen_ext` 做 so 层分析）。
- 关联：[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 App 的查壳与 dex dump）。
- 边界：目标改为直接 PLT 调用 `pthread_create` 时 dlsym 伪造失效；so 校验自身代码完整性（inline hook 检测、CRC）时 `Interceptor.replace` 可能触发二次崩溃；`0x64D10` 这类硬编码偏移只在同一版本 so 上稳定，换版本必须重新计算。

## 检测与防御

- 检测（App 侧）：定期校验 libc 导出函数的机器码是否被改写（inline hook 检测）；校验 `dlsym` 返回的函数地址是否落在预期模块范围内（若返回值指向匿名 RWX 内存，即为被劫持）；检测进程中存在 `rwx` 匿名映射与 Frida 特征。
- 检测：检测线程不要只依赖单一 API 解析路径，同时混用直接调用、syscall 直调、内联汇编，使 `dlsym` 伪造失效。
- 防御（App 侧）：把 Frida 检测分散到多个 so、多条线程并做相互校验；关键逻辑下沉服务端，客户端只做辅助判断；使用 RASP/Play Integrity 与服务端风险评分。
- 防御：so 完整性校验（签名/哈希）、反调试（`ptrace` 自附加、`TracerPid` 检查）、代码混淆与 so 名随机化组合使用。
- 防守方（企业侧）注意：这类绕过的意义是“取得动态分析能力”，不是直接攻破业务；真正的安全边界应在服务端授权与风控，不应把加固与反调试当作唯一防线。
