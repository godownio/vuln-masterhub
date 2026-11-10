---
id: code-analysis-reverse-firmware-jhttpd-cgi-table-idapython-dump
title: jhttpd CGI 路由表提取：IDAPython 按 0x14 步长遍历 httpd_cgi_all_fun，解析路径字符串与 handler 函数建立路由映射
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: jhttpd-cgi-handler-table-dump
aliases:
- jhttpd 路由表 dump
- httpd_cgi_all_fun 遍历
- IDAPython CGI 接口提取
- IoT WebServer 路由审计
- jhttpd 白盒审计
tags:
- jhttpd
- iot
- firmware
- idapython
- cgi
- route-table
- reverse-engineering
- audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V294
  verified_at: '2026-11-08T07:46:46+08:00'
  notes: 已对照原文与17张图核对：main→mem_init_fun/httpd_find_type2_init→httpd_file_init/ext/cgi_init→httpd_sever_init(0x50=80端口)→http_poll/httpd_do_recv→memcmp GET/POST 分支；IDAPython 脚本从 0x6b0000 按 0x14 步长遍历 httpd_cgi_all_fun 至 0x4801000，data[3] 路径、data[4] handler，与图13/14 一致。修正：脚本对路径指针为 0 的表项是跳过而非终止，已改卡内两处表述。原文未给设备型号/固件版本，未设 affected_versions。dup-scan pair#78 与同篇命令注入卡为 related（审计方法 vs 具体漏洞），非重复。
---

## 一句话结论

jhttpd 把「URL 路径 → 处理函数」的 CGI 路由保存在全局表 `httpd_cgi_all_fun` 中，每项固定 0x14 字节（5 个 32 位字段，其中第 4 个字段指向路径字符串、第 5 个字段是 handler 函数指针）；用 IDAPython 从表起始地址（本例 0x6b0000）按 0x14 步长遍历到给定上界、跳过路径指针为空的表项，就能批量 dump 出 `http://host/<路径>` 与 handler 的对应关系，把固件审计从「满屏函数找 xref」变成「按路由逐个看处理逻辑」。

## 原理

- jhttpd 启动时在 `main` 中完成几类初始化：
  - `mem_init_fun()`：内存管理初始化；
  - `httpd_find_type2_init()`：服务类型初始化；
  - `httpd_file_init()` / `httpd_file_ext_init()` / `httpd_cgi_ext_init()`：分别初始化文件、文件扩展名、CGI 扩展名相关的哈希表（`gl_vfile_ext_hash`、`gl_file_hash`、`gl_cgi_ext_hash`），并初始化 `httpd_all_file` 结构体保存服务器可用文件列表；
  - `httpd_sever_init(addr, port, max_conn)`：创建 TCP socket、`setnonblocking`、`SO_REUSEADDR`、`bind`（失败重试最多 10 次）、`listen` 80 端口；
  - `http_poll` / `httpd_do_recv`：轮询处理连接，`memcmp` 匹配 `GET`/`POST`，GET 走 `httpd_dowith_get`，POST 走 `httpd_do_wwwparm`。
- CGI 路由表 `httpd_cgi_all_fun` 位于固件的全局数据区（本例起始 0x6b0000），每项 0x14 字节，字段布局（按 dump 脚本的解析）：
  - `data[0..2]`：其他元数据/标志；
  - `data[3]`：指向 URL 路径字符串的指针（脚本把它拼到 `http://127.0.0.2/` 后读出）；
  - `data[4]`：handler 函数指针（脚本用 `get_ea_name` 取函数名）。
  
  表项按固定步长连续排列，路径指针为 0 的项被脚本跳过、不中断遍历；脚本用 0x4801000 作为硬上界（应按实际固件的数据段范围调整）。
- 为什么用 dump 表而不是直接搜字符串/xref：IoT 固件常被裁剪符号、字符串分散在 rodata，Ghidra/IDA 的字符串 xref 未必能覆盖所有 handler；路由表是运行时真正使用的结构，按固定 stride 解析可以直接恢复完整的「路径 → 函数」映射，再逐个 handler 查 `system`/`popen`/`jhl_system`/`nvram_set` 等危险调用。
- 审计流程：
  1. 用 Ghidra 导入固件，从 `main` 找 `httpd_file_init`/`httpd_cgi_ext_init` 等初始化；
  2. 定位 `httpd_cgi_all_fun` 表（通常在初始化函数里被引用，或按已知起始地址）；
  3. 用 IDAPython 脚本按 0x14 步长遍历，输出路径字符串 + handler 名称；
  4. 对每个 handler 查参数获取（`httpd_get_parm`）、`nvram_set`、`snprintf` 拼命令、`jhl_system`/`system`/`popen` 等 sink；
  5. 找到可疑接口后用 FirmAE/QEMU 仿真复现。
- 边界：表起始地址、步长、字段偏移随 jhttpd 版本/厂商定制而变；脚本中的 0x6b0000/0x4801000 是样本特定值，换固件需重新确认；若表项经过重定位/压缩，静态 dump 可能失败，需要动态调试辅助。

## 触发条件

- 拿到 jhttpd 固件（或对设备有调试/仿真环境），具备 IDA/Ghidra 与 IDAPython。
- 固件中的 CGI 路由表未被加密/混淆，或可在运行时内存中找到；表项按固定 stride 排列。
- 已知或能定位表起始地址；数据段范围可确定，避免越界遍历。
- 需要审计 CGI 接口的命令注入/认证绕过等 Web 漏洞。

## 利用步骤

1. 用 Ghidra/IDA 打开 jhttpd，定位 `main`，跟进 `httpd_file_init`/`httpd_cgi_ext_init`，确认 CGI 表结构与起始地址。
2. 在 IDA 中运行脚本：从表起始地址按 0x14 步长读取 5 个 32 位字段，第 4 个字段作为路径字符串指针、第 5 个作为 handler 地址；路径指针为 0 时停止。
3. 输出形如 `[flags..., "http://127.0.0.2/proxy_client.asp", "0x47EAE8"]` 的列表，建立路由 → handler 映射。
4. 对每个 handler 反编译，重点搜索 `httpd_get_parm` 取值后进入 `nvram_set`、`snprintf`、`system`/`popen`/`jhl_system` 的路径。
5. 发现可疑接口后用 FirmAE/QEMU 起仿真环境，按路由构造请求验证（如命令注入的回连/文件写入）。

## PoC

IDAPython 路由表 dump 脚本（原文）：

```python
from idaapi import *

host = "http://127.0.0.2/"

def ReadStr(addr):
    res = ''
    while True:
        ch = get_byte(addr)
        if ch == 0:
            break
        res += chr(ch)
        addr += 1
    return res

class dump(object):
    def http_cgi_all_fun(self):
        print("start")
        httpd_cgi_all_fun_addr = 0x6b0000
        while httpd_cgi_all_fun_addr < 0x4801000:
            cgi_name = get_32bit(httpd_cgi_all_fun_addr + 3 * 4)
            if cgi_name != 0:
                data = get_bytes(httpd_cgi_all_fun_addr, 0x14)
                data = list(struct.unpack("<" + "I" * 5, data))
                data[3] = host + ReadStr(data[3])     # URL path
                data.append(get_ea_name(data[4]))     # handler name
                data[4] = hex(data[4])
                print(data)
            httpd_cgi_all_fun_addr += 0x14
        print("end")

dump_obj = dump()
dump_obj.http_cgi_all_fun()
```

脚本输出示例（字段为示例结构）：`[..., 'http://127.0.0.2/proxy_client.asp', '0x47EAE8']`，其中 `0x47EAE8` 即该路由的 handler，后续分析确认其调用 `jhl_system` 形成命令注入。

## 变体与关联

- 对 thttpd/Boa/httpd 等 IoT WebServer，路由/处理函数表通常也是全局数组或哈希表；可把「找表起始 + 固定 stride + 字符串/函数指针字段」的方法迁移，stride/字段需按结构体调整。
- 与 `tools/ida` 下 IDAPython 批量解密/注释卡可组合：先 dump 路由，再对 handler 中的字符串解密、危险调用定位。
- 具体漏洞利用见本文章「jhttpd proxy_client.asp proxy_srv 命令注入」卡（iot）。

## 检测与防御

- 这是审计方法，防御侧对应：固件发布时去除符号/字符串并不能阻止路由表被解析；应通过输入校验、最小权限、去掉调试 CGI、对 Web 管理接口鉴权来降低 handler 被利用的风险。
- 安全研究侧：dump 脚本应在副本上运行，避免修改固件；使用仿真环境验证，不直接连生产设备。
