---
id: code-analysis-reverse-windows-frida-ida-address-hook-wechat-revoke
title: Frida 按 IDA 静态地址定位 Windows DLL 功能函数：模块基址换算 + 调用点 hook 改 RDI 使微信撤回无效
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: frida-ida-address-hook-call-site-register-patch
aliases:
- Frida Interceptor.attach
- IDA 地址转运行时地址
- Module.findBaseAddress
- WeChatWin.dll 撤回
- 修改寄存器跳过调用
- 微信撤回无效
tags:
- reverse
- windows
- frida
- ida
- hook
- pe
- dynamic-analysis
- wechat
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383-fix
  verified_at: '2026-11-09T09:01:08+08:00'
  notes: V383 核对指出两处并已修正：1) 原理段原写 if (v9 != 4) 才调用，实际是 switch(v9) case 4 才调用 sub_1823CD710（v9 != 4 跳过），与『置 rdi=0 改为非 4 即跳过』一致；已改为 case 4 门控表述，步骤4同步。2) 定位叙述原称最终定位到含 Update rv msg 日志的函数 0x1826D9B90，截图实为疑似日志函数内 call sub_1826D9B90（0x1826D9B90 为被调用者），最终 hook 地址为 0x1823E5B8A；已按截图重写并注明。PoC 与原文 exp 不变。
---

## 一句话结论

对 Windows x64 的 WeChatWin.dll 这类 PE 模块，可以先用 IDA 的字符串列表按关键词（如 `revoke`）定位功能相关函数，再用 `运行时地址 = Module.findBaseAddress(模块) + (IDA 地址 - IDA 首选基址 0x180000000)` 把静态地址换算成实际地址，用 Frida `Interceptor.attach` 逐个验证；确认撤回调用链后，不修改函数内部的大量判断，而是在“调用撤回更新函数”的那条指令处 hook，`onEnter` 中把决定分支的寄存器（原文为 `rdi`）置 0，使条件不成立、跳过调用，从而让客户端撤回无效、消息保留。

## 原理

- **静态地址与运行时地址的偏差**：PE 模块在 IDA 中按首选基址（常见 x64 DLL 为 `0x180000000`）显示地址；进程加载后受 ASLR 影响实际基址不同。Frida 的 `Module.findBaseAddress('WeChatWin.dll')` 给出运行时基址，二者差值即同一函数在运行时的位置：
  `resolveAddress(idaAddr) = baseAddr + (idaAddr - 0x180000000)`。
- **用字符串找功能点**：撤回相关逻辑必然引用 `revoke` 一类字符串。IDA 中 `Shift+F12` 打开字符串窗口搜索 `revoke`，对候选字符串取交叉引用即可落到相关函数；再把候选地址换算后用 Frida hook，在 `onEnter` 打印日志，触发一次撤回动作即可验证是否命中（原文先验证了 `0x1823CD710` 等候选；在疑似日志函数内看到 `call sub_1826D9B90`，`0x1826D9B90` 是被调用者、疑为日志函数，最终把 hook 点定在调用点 `0x1823E5B8A`）。
- **为什么改调用点而不是改函数**：撤回函数内部判断分支很多，逐条改代码成本高且易漏；往上回溯调用者可以看到 `switch(v9) case 4` 才调用 `sub_1823CD710`（`v9 != 4` 时跳过）这类单条件门控。Frida 在调用前那条指令（原文 `0x1823E5B8A`）的 `onEnter` 中把承载 `v9` 的寄存器（原文为 `rdi`）置 0，使 `v9 != 4`、调用即被跳过。hook 到指令级地址而不是函数入口，是这类“单点分支短路”能成立的关键。
- **寄存器约定提醒**：Windows x64 的整型参数在 RCX/RDX/R8/R9，但 `rdi` 是 callee-saved 寄存器，常被编译器用来保存局部变量/分支值；因此“置 rdi=0”不是通用写法，必须按目标版本反汇编确认该指令处哪个寄存器参与比较。
- **边界**：这是**客户端本地行为修改**，只影响本机显示（撤回后消息仍可见），服务端消息状态与其它端不受影响；不是服务端鉴权绕过，也不改变数据归属。

## 触发条件

- 目标为 Windows x64 应用，功能逻辑位于已加载的 PE 模块（如 `WeChatWin.dll`），且能拿到对应版本的二进制做 IDA 静态分析。
- Frida 能 attach 目标进程（无强反调试，或已绕过）；`Module.findBaseAddress` 能取到模块基址。
- 已定位到承载功能分支的调用点指令地址，且该地址与运行版本一致（版本更新会使偏移失效）。
- 仅用于本地客户端研究/授权测试，不涉及服务端数据。

## 利用步骤

1. IDA 载入目标 DLL，`Shift+F12` 打开 Strings，搜索功能关键词（如 `revoke`），记录候选字符串与其交叉引用函数。
2. Frida 附加进程，打印 `Module.findBaseAddress('WeChatWin.dll')`，实现 `resolveAddress()` 把 IDA 地址换算为运行时地址。
3. 对候选函数地址 `Interceptor.attach` 并在 `onEnter` 打印日志，执行一次目标动作（发消息/撤回），确认命中哪个候选。
4. 进入命中函数，找到关键日志（如 `"Update rv msg : %d"`）与真正执行更新的 call；向上回溯调用者，识别门控条件（如 `switch(v9) case 4` 才调用 `sub_1823CD710`）及参与比较的寄存器。
5. 把 hook 地址改到“调用前的那条指令”，`onEnter` 中修改该寄存器（如 `this.context.rdi = 0`），使条件不成立、跳过调用。
6. 验证：发送消息后从另一端撤回，本机消息仍然存在；记录脚本与版本偏移。
7. 退出 Frida、恢复正常行为；不要把偏移写成跨版本通用值。

## PoC

```python
import frida, sys

def main(pid):
    session = frida.attach(pid)
    script = session.create_script("""
    const baseAddr = Module.findBaseAddress('WeChatWin.dll');
    console.log('base: ' + baseAddr);

    function resolveAddress(addr) {
        const idaBase = ptr('0x180000000');       // IDA 首选基址
        return baseAddr.add(ptr(addr).sub(idaBase));
    }

    // 调用点指令地址（按目标版本从 IDA 反汇编获取）
    const hookAddr = resolveAddress('0x1823E5B8A');
    Interceptor.attach(hookAddr, {
        onEnter(args) {
            this.context.rdi = 0;                 // 令 v9 != 4，跳过撤回更新调用
            console.log('hit call site');
        }
    });
    """)
    script.load()
    sys.stdin.read()

if __name__ == '__main__':
    main(8112)  # 目标进程 PID
```

```javascript
// 验证候选函数是否命中（第 3 步；0x1826D9B90 为疑似日志函数/被调用者）
const cand = resolveAddress('0x1826D9B90');
Interceptor.attach(cand, { onEnter(args) { console.log('candidate hit'); } });
```

地址 `0x1823CD710`、`0x1826D9B90`、`0x1823E5B8A` 均为原文针对其测试版本的偏移；换版本需重新在 IDA 中定位，不能直接复用。

## 变体与关联

- 变体（改分支而非改寄存器）：在调用点把条件跳转 patch 成 `jmp`/NOP，或将比较指令的操作数改为恒不等；Frida 也可用 `Memory.patchCode` 做内存补丁。
- 变体（hook 函数本身）：在目标函数入口 hook 并直接 `return`，适合函数无返回值依赖的场景；若函数内部有副作用/多处调用，改调用点更精准。
- 变体（基址获取）：IDA 载入时可查看 `Edit → Segments → Rebase` 的实际 ImageBase；若模块非默认基址，换算常量随之改变；也可用 `Module.enumerateSymbols`/特征码扫描避免硬编码偏移。
- 关联：[[code-analysis-reverse-windows-detours-funcptr-offset-calling-convention]]（Windows 原生 Detours hook 的地址/调用约定）、[[code-analysis-reverse-windows-iat-hook-install-messagebox]]（IAT hook）、[[code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass]]（同属客户端校验/分支绕过）、[[code-analysis-reverse-windows-game-sun-pointer-scan-win32-write]]（运行期内存定位与修改）。

## 检测与防御

- 检测：进程出现 `frida-agent`/注入线程、模块代码段被改为可写可执行；关键函数/调用点被 hook 后行为异常（撤回后消息仍展示）；进程完整性校验、代码段哈希与内存扫描。
- 防御（应用侧）：不要把“消息是否保留、权限是否生效”只放在客户端分支里；关键状态以服务端为准并在 UI 层复核；加入反调试/Frida 检测与完整性校验（只能提高成本，不能根治客户端修改）。
- 边界：该手法属于本地客户端 mod/逆向实验，不改服务端状态；用于未授权客户端篡改时可能违反软件许可与相关法规，仅在授权/自有环境测试。
