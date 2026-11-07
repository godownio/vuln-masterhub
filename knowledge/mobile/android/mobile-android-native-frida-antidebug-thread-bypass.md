---
id: mobile-android-native-frida-antidebug-thread-bypass
title: Android libnesec.so Frida 反调试定位与线程替换绕过：dlopen/路径监控 + pthread_create 精准替换第一条线程
type: scenario
domain: mobile
path: mobile/android
technique: android-native-frida-antidebug-thread-bypass
aliases:
- libnesec.so
- Frida 反调试
- pthread_create 替换
- /proc/self/maps 检测
- Interceptor.replace
- 到梦空间
- 反调试线程
- 精准绕过
tags:
- android
- frida
- anti-debug
- native
- so
- pthread
- hook
- reverse-engineering
cve: []
severity: low
confidence: high
status: verified
affected_versions: 4.7.3、4.8.3（文章实测）
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V121
  verified_at: '2026-11-06T04:13:46+08:00'
  notes: 已对照原文及9张图核对：dlopen 定位 libnesec.so、open/access/stat 路径监控 TID 22033 访问 /proc/self/maps、pthread_create 替换全部线程、4.8.3 onLeave/onEnter 线程ID区分并只替换第一条反调试线程，均与原文/截图一致；已修正原文 Frida 默认端口笔误 27047→27042；4.7.3/4.8.3 为原文实测目标 App 版本，保留 affected_versions；PoC 未本机执行
---

## 一句话结论

目标 App 在启动时由 `libnesec.so` 创建一个反调试线程，扫描 `/proc/self/maps` 等特征并杀死 Frida；用 Frida Hook `dlopen` 定位该 SO、Hook `open/access/stat` 确认线程访问 `/proc/self/maps`，再 Hook `pthread_create` 替换该线程入口即可绕过；新版本中 `libnesec.so` 还创建核心解密线程，必须通过 onLeave/onEnter 线程 ID 找出“第一条反调试线程”，只替换它而保留解密线程，否则 App 会卡住。

## 原理

- **Frida 检测面**：App 启动后先起一个线程扫描主进程环境，常见检测包括：
  - 扫描 `/proc/self/maps` 或 `/proc/<pid>/maps`，查找 `frida`、`gadget`、`libfrida-agent.so` 等库；
  - 检查 Frida Server 默认端口 27042（原文写作 27047，应为笔误；读 `/proc/net/tcp` 或 netstat）；
  - 遍历 `/proc/self/task/<tid>/comm`，查找 `gmain`、`gdbus`、`frida-*` 等线程名；
  - 检查环境变量中的 Frida 特征。
  检测到后直接杀死进程/Frida，表现为 App 闪退或卡在启动页。
- **定位 SO**：Hook `dlopen`，打印 `args[0]` 的 SO 路径；观察到先加载 `libc.so`，再加载 `libnesec.so` 后 Frida 进程被杀。`libc.so` 是系统库（提供 pthread），排除；`libnesec.so` 是反调试载体。
- **确认行为**：Hook `open/openat/access/stat/lstat`，打印路径与线程 ID；`libnesec.so` 创建的线程（如 TID 22033）访问 `/proc/self/maps`，随后 Frida 被杀，确认该线程执行反调试逻辑。
- **绕过（4.7.3）**：Hook `pthread_create`，其签名是 `int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg)`；`args[0]` 是线程 ID 指针、`args[2]` 是入口函数地址。用 `Process.findModuleByAddress(args[2]).name` 判断是否属于 `libnesec.so`，是则 `Interceptor.replace(args[2], NativeCallback(...))` 把入口替换成空函数，反调试线程不执行，Frida 存活。
- **精准绕过（4.8.3）**：直接替换 `libnesec.so` 的所有线程会把“核心逻辑解密线程”也替换掉，App 卡在启动页（不闪退、Frida 不被杀）。需要区分线程：
  - `pthread_create` 的 `onLeave` 阶段（线程已创建、尚未运行）读取 `args[0]` 的临时线程 ID；
  - `onEnter` 阶段（线程被调度、真正运行）读取真实线程 ID；
  - 观察发现只有第一条 `libnesec.so` 线程有真实 ID（非 0），后续线程未运行——说明第一条线程就是反调试线程，它检测到 Frida 后终止了后续线程创建。
  - 因此只记录并替换第一条 `libnesec.so` 线程的入口（`target_entry_addr` 只赋值一次），其余线程（解密线程）保留原逻辑。
- 根因是“客户端反调试线程必须运行才能检测，而 Frida 可以在 `pthread_create` 层拦截入口”；反调试强度取决于线程分工与检测面，精准替换比无差别替换更稳定。

## 触发条件

- 目标 Android App 使用 native `.so`（如 `libnesec.so`）创建反调试线程，检测 Frida/调试环境。
- 测试设备已 root 并能运行 Frida Server/frida CLI，可附加/ spawn 目标进程。
- App 未使用更强的 RASP/内核级反调试，或检测逻辑可被 Frida Hook 拦截。
- 能 Hook `libc.so` 的 `dlopen`/`pthread_create`/`open` 等导出函数。
- 仅限授权逆向/安全研究环境。

## 利用步骤

1. Hook `dlopen`，观察 App 启动时加载的 SO；找到加载后触发 Frida 被杀的目标 SO（本题 `libnesec.so`）。
2. Hook `open/openat/access/stat/lstat`，打印路径与线程 ID，确认目标 SO 创建的线程访问 `/proc/self/maps` 等检测路径。
3. 写 `pthread_create` Hook：在 `onEnter` 读取 `args[0]`（线程 ID 指针）与 `args[2]`（入口地址），用 `Process.findModuleByAddress(args[2]).name` 过滤 `libnesec`。
4. 4.7.3：直接 `Interceptor.replace(args[2], NativeCallback(...))` 替换所有 `libnesec` 线程入口，验证 App 正常运行、Frida 不被杀。
5. 4.8.3：在 `onLeave` 打印临时线程 ID、在替换回调/`onEnter` 打印真实线程 ID；确认只有第一条线程真正运行，记录其入口地址 `target_entry_addr`。
6. 只替换第一条线程入口，其他 `libnesec` 线程保留；验证 App 正常进入、无卡顿、Frida 存活。
7. 若仍被检测，检查是否有 ptrace/TracerPid、syscall 直调、inline hook 或其它 SO 的反调试。

## PoC

Hook `dlopen` 定位 SO：

```javascript
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter(args) {
    try { console.log("加载 SO:", args[0].readUtf8String()); } catch (e) {}
  }
});
```

Hook 路径访问确认线程：

```javascript
setImmediate(() => {
  ["open", "openat", "access", "stat", "lstat"].forEach(name => {
    const addr = Module.findExportByName(null, name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          console.log(name, args[0].readUtf8String(), "TID=", Process.getCurrentThreadId());
        } catch (e) {}
      }
    });
  });
});
```

精准替换第一条 `libnesec.so` 线程：

```javascript
function hookPthreadCreate() {
  const pt = Module.findExportByName("libc.so", "pthread_create");
  let targetEntry = null;
  Interceptor.attach(pt, {
    onEnter(args) {
      this.threadPtr = args[0];
      const entry = args[2];
      const mod = Process.findModuleByAddress(entry);
      const so = mod ? mod.name : "unknown";
      if (so.indexOf("libnesec") === -1) return;

      const tid = Process.pointerSize === 8
        ? this.threadPtr.readU64().toString(16)
        : this.threadPtr.readU32().toString(16);

      if (targetEntry === null) {
        targetEntry = entry;
        console.log("锁定第一条反调试线程:", tid, entry, so);
        Interceptor.replace(entry, new NativeCallback(() => {
          console.log("反调试线程已替换:", tid);
          return ptr(0);
        }, "pointer", ["pointer"]));
      }
    },
    onLeave(retval) {
      if (retval.toInt32() === 0 && this.threadPtr) {
        const tid = Process.pointerSize === 8
          ? this.threadPtr.readU64().toString(16)
          : this.threadPtr.readU32().toString(16);
        console.log("线程创建成功:", tid);
      }
    }
  });
}
hookPthreadCreate();
```

## 变体与关联

- **检测变体**：maps、27042 端口（原文 27047）、线程名、环境变量、`/proc/self/status` TracerPid、ptrace、syscall 直调、inline hook、时间/信号检测。
- **绕过变体**：替换 `pthread_create` 入口、Hook `open/read` 过滤路径、Hook `strstr`/`strcmp` 改返回值、Hook `ptrace`、Hook `kill`/`exit`、patch SO、Frida 隐藏（改名/端口/线程名）。
- **线程分工变体**：反调试线程 + 核心解密线程 + 网络线程；必须区分目标线程，避免无差别替换导致 App 卡死。
- **关联**：[[mobile-android-anti-detection-root-emulator-proxy]]（Root/模拟器/代理检测绕过）；[[mobile-android-packer-apkid-frida-dexdump-jadx]]（加固 APK 与 Frida dump）；[[mobile-android-ssl-pinning-bypass-cert-frida]]（Frida Hook 的另一场景）；[[code-analysis-reverse-anti-debug-sandbox-environment-checks]]（反调试/反沙箱通用思路）。
- **边界**：App 使用内核级/硬件级反调试、RASP 检测 Frida 自身、或反调试逻辑在多个 SO/线程中冗余时，单点替换可能失效；仅用于授权研究。

## 检测与防御

- **检测**：App 启动时 native 线程访问 `/proc/self/maps`、`/proc/net/tcp`、`/proc/self/task/*/comm`；检测 Frida 端口/线程名/库名；进程异常退出。
- **防御（App 侧）**：多线程/多 SO 冗余检测、检测 Frida 自身（端口/线程名/内存特征）、RASP、Play Integrity、ptrace 自保护；不要把反调试逻辑集中在单一线程。
- **研究侧**：先定位 SO 与线程，再精准替换；保留核心解密/业务线程；必要时 patch SO 或 Hook 检测函数返回值。
- **合规**：仅用于授权逆向/安全研究，遵守应用服务条款与法律。
