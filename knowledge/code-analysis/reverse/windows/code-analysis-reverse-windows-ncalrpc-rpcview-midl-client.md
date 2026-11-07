---
id: code-analysis-reverse-windows-ncalrpc-rpcview-midl-client
title: Windows ncalrpc 本地 RPC 接口发现与 MIDL 客户端调用
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-ncalrpc-rpcview-midl-client
aliases:
- ncalrpc RPC
- RpcView
- MIDL 客户端
- 本地 RPC 调用
- 只本地可调 RPC 接口
tags:
- windows
- rpc
- ncalrpc
- alpc
- rpcview
- midl
- reverse-engineering
- svchost
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V96
  verified_at: '2026-11-05T19:57:34+08:00'
  notes: 已对照原文与9张图片核对；ncalrpc端点、UUID 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5、endpoint dhcpcsvc、Proc23、DhcpFindAndRefContext的LUID 0x6008001000000均有正文/截图支撑；PoC为原文客户端最小化改写，未在本机复跑；原文CVE溢出仅到memcpy越界写，卡片只记录RPC调用方法，未宣称RCE。
---

## 一句话结论

当目标 Windows 服务把敏感 RPC 方法只注册在 `ncalrpc`（本地 ALPC）端点上、远程或普通网络 RPC 无法触达时，可用 RpcView 枚举接口 UUID/版本/端点/过程号，导出 IDL 后用 `midl` 生成客户端存根，再以 `RpcStringBindingComposeW` 绑定 `ncalrpc` 端点调用指定 `ProcN`，从而在本机到达该函数（例如 dhcpcore 的 `RpcSrvGetOriginalSubnetMask`）。

## 原理

- Windows RPC 端点可绑定到不同协议序列：`ncacn_ip_tcp`（网络 TCP）、`ncacn_np`（命名管道）、`ncalrpc`（本机 ALPC/LPC）。`ncalrpc` 端点只在本机端点映射器中注册，远端无法直接连接，常用于服务内部或同机进程间调用。
- 每个 RPC 接口由 UUID + 版本号标识，接口内有一张过程表（procedure 0..N）。RpcView 通过 RPC 运行时枚举进程/端点/接口，能显示 endpoint 名称、协议、UUID、版本、过程数与 stub 信息；选择接口后可 Decompile 出 IDL。
- `midl` 根据 IDL 生成客户端/服务端存根与头文件，负责参数按 NDR 规则编组。客户端用 `RpcStringBindingComposeW(UUID, "ncalrpc", NULL, endpoint, NULL, &binding)` 组出绑定字符串，`RpcBindingFromStringBindingW` 得到句柄，调用生成的 `ProcN` 即进入服务端 stub，最终执行到目标内部函数。
- 这也解释了为什么直接对网络路径或普通 RPC 扫描打不到某些方法：方法只暴露在 ncalrpc 上，必须由本机进程主动调用。对于以 `LOCAL SERVICE`/`SYSTEM` 运行的 svchost 服务，调用会以服务进程身份执行目标逻辑，但能否调用取决于端点 ACL 与调用者会话/令牌。
- 目标函数可能还要求业务参数正确才能走到漏洞点。例如 dhcpcore 的 `RpcSrvGetOriginalSubnetMask` 先调用 `DhcpFindAndRefContext`，后者在 `cmp rax, [rdx+18h]` 处比对网卡 LUID；必须传入目标网卡真实的 NetLuid（如 `0x6008001000000`）才会继续，否则返回错误码 2。

## 触发条件

- 目标服务确实注册了 `ncalrpc` 端点（RpcView 中 Protocol 列显示 `ncalrpc`），且调用者能访问该端点（同一会话/用户或有相应 ACL）。
- 能获取接口 UUID、版本、端点名与目标过程号；有对应 IDL 或可由 RpcView 反编译生成。
- 本机可运行自编译的 RPC 客户端（需要能加载 rpcrt4、编译 MIDL 生成代码）；调试时可将服务单独挂到独立 svchost 或用 IDA remote debugger 附加。
- 目标方法要求的业务参数（会话 ID、网卡 LUID、句柄、结构体等）可获取并可正确编组。
- 目标未对 ncalrpc 端点设置额外安全回调/身份校验，或调用者身份满足其检查。

## 利用步骤

1. 在目标机上运行 RpcView，按进程展开 svchost，找到 `Protocol = ncalrpc` 的 endpoint（如 `dhcpcsvc`），记录 Interface UUID、版本与过程数。
2. 选中接口执行 Decompile，导出 IDL；用 `midl /client none`（或默认）生成 `test.h`、`test_c.c` 等客户端存根。
3. 编写客户端：`RpcStringBindingComposeW(UUID, L"ncalrpc", NULL, L"<endpoint>", NULL, &binding)` → `RpcBindingFromStringBindingW` → 调用目标 `ProcN`；用 `RpcTryExcept/RpcExcept` 捕获 RPC 异常。
4. 准备参数：对 dhcpcore 场景，先用 `Get-NetAdapter -IncludeHidden | Format-List Name,NetLuid` 取得目标网卡 LUID，填入 IDL 生成的结构体成员（示例为 `Struct_10_t.StructMember0`）。
5. 在服务端下断点（如 IDA 附加到承载 dhcpcore.dll 的 svchost），运行客户端；确认命中断点后，根据返回值/比较指令校正参数（如 LUID、会话）。
6. 到达目标函数后继续分析漏洞点；若为输入解析类漏洞，再配合对应的网络/本地输入（如恶意 DHCP 响应）完成触发。

## PoC

```c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <rpc.h>
#include "test.h"                 /* midl 由 RpcView 导出的 IDL 生成 */
#pragma comment(lib, "Rpcrt4.lib")

int main(void) {
    RPC_WSTR binding = NULL;
    handle_t h = NULL;
    RPC_STATUS st = RpcStringBindingComposeW(
        (RPC_WSTR)L"3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5",  /* RpcView 中的接口 UUID */
        (RPC_WSTR)L"ncalrpc",                              /* 仅本地 ALPC */
        NULL,
        (RPC_WSTR)L"dhcpcsvc",                             /* RpcView 中的 endpoint */
        NULL, &binding);
    if (st != RPC_S_OK) return 1;
    if (RpcBindingFromStringBindingW(binding, &h) != RPC_S_OK) return 1;
    RpcStringFreeW(&binding);

    Struct_10_t arg = { 0 };
    arg.StructMember0 = 0x6008001000000ULL;   /* 目标网卡 NetLuid，需按实际机器替换 */
    long out_mask = 0;

    RpcTryExcept {
        long rc = Proc23(h, NULL, &arg, &out_mask);   /* RpcSrvGetOriginalSubnetMask */
        printf("Proc23 rc=%ld out=%ld\n", rc, out_mask);
    }
    RpcExcept(1) {
        printf("RPC exception: 0x%lx\n", RpcExceptionCode());
    }
    RpcEndExcept

    RpcBindingFree(&h);
    return 0;
}

void __RPC_FAR *__RPC_USER midl_user_allocate(size_t len) { return malloc(len); }
void __RPC_USER midl_user_free(void __RPC_FAR *p) { free(p); }
```

## 变体与关联

- 变体：把 `ncalrpc` 换成 `ncacn_np`（命名管道）或 `ncacn_ip_tcp`，即可从其他主机/会话调用；端点名与 UUID 仍由 RpcView 获取。
- 变体：不生成 MIDL 客户端，直接按 NDR 手工构造 ALPC/RPC 消息，或用 Impacket 的 `rpcclient`/自写 DCERPC 客户端（更适用于 Linux 侧）。
- 变体：RpcView 的 Decompile 失败时，可用 IDA 分析服务端 `RPCRT4` 注册信息、接口 stub 与过程表，手工还原 IDL。
- 关联：Windows 本地服务漏洞研究中的“先让本地 RPC 可达，再触发解析/内存破坏”流程；与 DHCP/DNS 等客户端协议的服务端伪造配合（如恶意 DHCP 响应喂给客户端）。
- 边界：若服务端在 endpoint 上注册了安全回调并校验调用者 SID/会话，普通用户调用会被拒绝；`ncalrpc` 不等于无鉴权。

## 检测与防御

- 检测：监控本机进程对敏感 ncalrpc 端点的调用（RPC ETW/ALPC 审计）；发现非系统进程加载 rpcrt4 并绑定 `ncalrpc`、调用服务接口；关注 RpcView 等枚举工具的运行痕迹。
- 修复：对本地 RPC 端点设置严格的安全描述符/回调，校验调用者身份与会话；服务端对所有 RPC 参数做长度与边界校验，不信任客户端传入的指针/长度。
- 加固：最小化服务暴露的 RPC 方法；以低权限账户运行服务；启用 Windows RPC 相关审计与 ETW；对本地服务漏洞及时打补丁。
