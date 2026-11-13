---
id: code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation
title: Remcos v4.9.3 socket 协议逆向：24 04 FF 00 magic + 小端长度/指令号，自研 TCP 控制端复现初始化、30 秒心跳与 screen_capture/process_manager/command_line 指令
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: remcos-socket-protocol-controller-emulation
tags:
- windows
- remcos
- rat
- malware-analysis
- protocol-reversing
- c2-emulation
- socket
- heartbeat
- go
cve: []
severity: medium
confidence: high
affected_versions: Remcos v4.9.3 Light（原文分析/复现版本）
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V618
  verified_at: '2026-11-12T21:01:27+08:00'
  notes: 已对照原文 content.md 与全部 41 张图逐项核对：24 04 FF 00 magic、4 字节小端长度/指令号（Sendbuf 大端写入后整体反转）、7C 1E 1E 1F 7C 分隔符、0x4B 初始化→回 0x01(0|30)→发 0x11、30 秒心跳、0x10/0x06/0x0E 指令与 0x4F/0x62 响应、0x21/0x22 均与原文代码及图 17/32/33 抓包一致；Remcos v4.9.3 Light 见原文图 13/18/19 标题栏（正文称免费版）；dedup 20 候选全 new，最近候选 SETTINGS 配置提取卡技术不同，dup-scan 无涉及 pair。未验证点：未在本机复现控制端，未对真实样本执行 PoC。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-remcos-socket-protocol-controller-emulation/
draft: false
kb_aliases:
- Remcos socket 协议
- Remcos 通信模型
- Remcos 控制端复现
- Remcos 0x2404ff00
- Remcos 指令编号
- Remcos C2 仿真
- Remcos Agent 分析
---

## 一句话结论

Remcos v4.9.3 关闭 TLS 后走明文 socket 协议：每帧以 `24 04 FF 00` 开头，随后是 4 字节小端长度、4 字节小端指令编号和载荷，载荷字段用 `7C 1E 1E 1F 7C` 分隔；只要按这个格式写一个 TCP 监听器冒充控制端，先回应 Agent 的初始化指令（0x4B），再按 30 秒周期发心跳（指令 0x01，载荷 `0|分隔符|30`），就能向 Agent 下发 screen_capture（0x10）、process_manager（0x06）、command_line（0x0E）等指令并解析其响应（0x4F/0x62），无需完整逆向 Agent 即可复现通信模型。

## 原理

- **连接方向**：Remcos Agent 主动外连控制端（反向连接），所以分析机只需监听配置里的端口（示例 8080），接受连接后按协议读写即可；socket 模式下不启用 TLS，数据明文，便于逐帧分析。
- **帧格式**：`24 04 FF 00`（固定 magic）＋4 字节长度＋4 字节指令编号＋载荷。长度与指令号在线上是小端（原文代码用 `BigEndian` 写入后再整体反转字节实现）；解析时先反转 4 字节再按大端读回。
- **载荷分隔**：多字段载荷用 `7C 1E 1E 1F 7C`（可见字符 `|` + 0x1E 0x1E 0x1F + `|`）分隔，字符串多为 ASCII/UTF-16LE 混合的十进制 ID 与路径（如 `C:\Users\admin\Desktop\remcos_b.exe`）。
- **初始化序列**：连接建立后 Agent 先发指令编号 0x4B；控制端回 0x01，载荷 `0|分隔符|30`；收到响应后控制端再发 0x11；随后进入心跳循环——每 30 秒发一次 0x01 + `0|分隔符|30`，Agent 回包确认在线。
- **指令编号观测**：screen_capture 为 0x10（发送后 Agent 返回截图数据，文件名与 PNG 数据用分隔符分段）；process_manager 为 0x06，响应 0x4F（进程列表 + 当前 PID）；command_line 为 0x0E，先发 `135707728|分隔符|cmd.exe` 建立会话，再逐条发 `135707728|分隔符|<命令>`，输出帧编号 0x62；close 为 0x21、uninstall 为 0x22。
- **为什么自研控制端可行**：socket 模式没有 TLS 证书校验或口令鉴权，协议字段都可由监听端构造；与其静态逆向庞大的 Agent，不如实现最小控制端，通过“发指令—收响应”直接把每个编号与功能、响应格式对应起来。原文用 Go 实现了初始化、心跳与三条指令，并在 VMware 中的 Agent 上成功复现。

## 触发条件

- 目标为 Remcos v4.9.3（或协议相近版本），且通信配置为 socket 模式（未勾选 Secure Connection TLS 1.3）。
- 分析机可监听 Agent 配置的 C2 端口，Agent 能回连（隔离实验网络或已控制的目标）。
- 仅用于授权样本分析与 C2 仿真，不用于未授权控制他人主机。

## 利用步骤

1. 从样本 SETTINGS 配置中提取 C2 地址/端口与 TLS 开关（见 [[code-analysis-reverse-windows-remcos-settings-config-extraction]]）。
2. 在分析机监听该端口（示例 `0.0.0.0:8080`），接受 Agent 连接。
3. 读取首帧并解析指令编号：若为 0x4B，执行初始化——发 `01 00 00 00` + `0|分隔符|30`，读响应，再发 `11 00 00 00`，读响应。
4. 启动心跳协程：每 30 秒发 `01 00 00 00` + `0|分隔符|30`，保持会话在线。
5. 交互下发指令：screen_capture 发 0x10（示例载荷 `136391552|分隔符|50|分隔符|0|分隔符|-1|分隔符|0`）；process_manager 发 0x06 并解析 0x4F；command_line 发 0x0E 建立 cmd.exe 会话，再逐条发送命令并打印 0x62 输出。
6. 记录每个指令编号的请求/响应样本，沉淀为协议映射表，用于后续流量识别与解密验证。

## PoC

Go 帧收发核心（长度与指令号按线上小端处理）：

```go
func Sendbuf(conn net.Conn, buf []byte) {
    sendbuf := []byte{0x24, 0x04, 0xff, 0x00}
    hexLen := common.IntToBytes(len(buf)) // BigEndian
    common.Reversedata(&hexLen)           // 反转后上线为小端
    sendbuf = append(sendbuf, hexLen...)
    sendbuf = append(sendbuf, buf...)
    conn.Write(sendbuf)
}

func RecvBuf(conn net.Conn) ([]byte, error) {
    var bufRecv []byte
    for {
        buffer := make([]byte, 4096)
        n, err := conn.Read(buffer)
        if err != nil { return nil, err }
        bufRecv = append(bufRecv, buffer[:n]...)
        if len(bufRecv) >= 8 && hex.EncodeToString(bufRecv[:4]) == "2404ff00" {
            hexLen := append([]byte{}, bufRecv[4:8]...)
            common.Reversedata(&hexLen)
            buflen := common.BytesToInt(hexLen)
            if len(bufRecv)-8 >= buflen {
                return bufRecv[8:], nil
            }
        }
    }
}
```

初始化与心跳：

```go
// 收到 0x4B 后
Sendbuf(conn, []byte{0x01, 0x00, 0x00, 0x00, 0x30, 0x7c, 0x1e, 0x1e, 0x1f, 0x7c, 0x33, 0x30})
RecvBuf(conn)
Sendbuf(conn, []byte{0x11, 0x00, 0x00, 0x00})
RecvBuf(conn)

// 每 30 秒
func Heartbeat(conn net.Conn) {
    for {
        Sendbuf(conn, []byte{0x01, 0x00, 0x00, 0x00, 0x30, 0x7c, 0x1e, 0x1e, 0x1f, 0x7c, 0x33, 0x30})
        RecvBuf(conn)
        time.Sleep(30 * time.Second)
    }
}
```

说明：PoC 为协议帧构造的最小骨架，来自文章对 Agent 的实测；仅在自有隔离环境对样本使用。

## 变体与关联

- **版本差异**：v1.x 用带静态密钥的 RC4 加密 socket 通信；v3.0 起支持 TLS1.3 双向证书；v4.9.3 同时支持 TLS1.3 与明文 socket。TLS 模式下协议字段被加密，控制端仿真需要证书/口令，难度显著提高。
- **配置提取**：C2 地址、端口与 TLS 开关从 `SETTINGS` 资源 RC4 解密获得，见 [[code-analysis-reverse-windows-remcos-settings-config-extraction]]。
- **同类 RAT 协议**：Xeno-RAT 的帧结构与 AES-CBC 解密见 [[defense-forensics-xeno-rat-aes-cbc-lznt1-traffic-batch-decrypt]]；其他 RAT 也可用“自研控制端驱动 Agent”的方法梳理指令表。
- **检测**：明文 socket 流量中可见固定 magic `24 04 FF 00`、4 字节长度和 `7C 1E 1E 1F 7C` 分隔符；默认 30 秒心跳与固定载荷长度可作为行为特征（TLS 模式见 [[defense-detection-remcos-v493-tls13-cipher-heartbeat-fingerprint]]）。
- **边界**：Agent 若被定制修改（magic/心跳/指令号变化）或强制 TLS，本文帧格式与控制端需要同步调整。

## 检测与防御

- **网络检测**：TCP 载荷以 `24 04 FF 00` 开头、后续长度与分隔符符合上述格式；同一连接周期性 30 秒小包；外联目标为未知 IP/域名且进程为非浏览器程序。
- **端点检测**：EDR 关注 Agent 进程外联、`SETTINGS` 资源、持久化项与键盘记录/截屏行为；结合样本哈希与威胁情报。
- **防御**：封禁 C2、隔离主机、提取样本与内存；对出站连接做域名/IP 白名单；邮件与下载链路拦截 LNK/压缩包投递（Remcos 常见投递方式）。
- **分析侧**：在隔离网络运行 Agent，控制端仿真只监听回连，不将样本暴露到互联网。
