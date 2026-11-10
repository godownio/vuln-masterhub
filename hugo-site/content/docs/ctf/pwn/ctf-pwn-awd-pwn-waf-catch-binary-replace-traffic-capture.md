---
id: ctf-pwn-awd-pwn-waf-catch-binary-replace-traffic-capture
title: AWD 流量捕获：用 pwn_waf 的 catch 包装替换题目二进制，落盘对手全部 exp 输入
type: scenario
domain: ctf
path: ctf/pwn
technique: awd-pwn-waf-catch-traffic-capture
tags:
- ctf
- awd
- pwn
- defense
- traffic-capture
- pwn-waf
- forensics
- mitm
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:47:06+08:00'
  notes: 已对照原文核对：pwn_waf 改 makefile 的 log path 后 make、把 pwn 与 catch 放进新建目录、用 catch 替换 pwn 文件、exp 打替换后的 pwn 即在目录中收到流量，均与原文一致；已把属于推测的连接命名规则与 catch 取原二进制路径等细节标注为以工具实现为准。未验证点：未在赛事环境复跑，pwn_waf 编译参数与日志格式未验证。
url: /docs/ctf/pwn/ctf-pwn-awd-pwn-waf-catch-binary-replace-traffic-capture/
draft: false
kb_aliases:
- pwn_waf 流量捕获
- catch 替换 pwn
- AWD 抓对手 exp
- pwn 流量监控
- 落盘 exp payload
- 防守方流量取证
---

## 一句话结论

AWD 防守阶段可以把题目下发的 pwn 二进制换成一个 `catch` 包装程序：它先把自己接收到的全部 stdin/网络数据落盘，再把数据转交给原始 pwn 处理并回传输出，于是对手对同一目标的每一次 exp 输入（偏移、gadget、payload 全文）都会被完整记录，用于复盘对手利用链、反推偏移或事后取证。

## 原理

- **包装器只是 I/O 中转**：`catch` 与其替身 `pwn` 放在同一目录，`catch` 被调用时按约定读取原始二进制路径与日志目录，先 `recv/read` 客户端数据并写入日志文件（常按连接/时间命名），再把同一份数据交给原二进制执行，最后把原二进制的 stdout 回写给客户端。对客户端而言协议与响应不变，只是多了一层透明转发。
- **替换点选在题目可执行文件**：赛事通常以固定文件名启动题目（如 `./pwn`），把 `catch` 复制/改名为该文件名即替换入口；原始二进制改名保留，由 `catch` 通过参数或配置调用，`makefile` 里的 `log path` 决定落盘目录。
- **为什么有效**：AWD 中对手的 exp 是同一份脚本反复打所有队伍，payload 稳定且包含偏移/gadget 地址；拿到完整输入后可以直接抄对手的利用思路，甚至定位自己 binary 里同类漏洞的正确偏移。
- **与补丁的区别**：补丁（AWDP fix）是“让利用失效”，本手法是“观测与学习”，两者互补——先捕获看清对手打什么，再决定修哪里。
- **前提与风险**：需要目录写权限与可执行权限；包装器必须保证协议时序一致（缓冲、EOF、超时），否则对手 exp 失败反而暴露；日志可能被对手通过路径/文件名注入污染，需按连接生成固定名并做长度限制。

## 触发条件

- AWD 防守环节，题目以固定文件名/路径启动可执行文件，且该文件可被替换（有写权限、无完整性校验）。
- 有 `pwn_waf` 类包装工具（或自行写 `recv→log→exec→回写` 的中转），能编译并放到题目目录。
- 目录可写，日志目录有足够空间；赛事规则允许对自家靶机做此类监控。
- 要求对客户端协议透明（包括交互式多轮输入、超时行为）。

## 利用步骤

1. 建一个日志目录并给写权限，改 `makefile` 里的 `log path` 指向它，`make` 得到 `pwn` 与 `catch` 两个产物。
2. 把原始题目二进制改名（如 `pwn_orig`），把 `catch` 放到题目目录并改名为 `pwn`（或按工具约定以 `catch <orig>` 方式启动）。
3. 用小脚本自打一次：确认 `catch` 能转发、原程序行为不变、日志目录出现对应记录文件。
4. 观察日志：按连接/时间读取落盘内容，记录对手 payload 的偏移、gadget 地址、菜单交互序列。
5. 复盘：把对手 payload 拿到本地打自己的备份二进制，确认命中点；据此修漏洞（AWDP 补丁）或加固检查。
6. 赛后清理：恢复原始二进制、保留日志作为取证材料，注意日志中的 payload 不要外传。

## PoC

```text
# 目录布局（按工具约定）
chall/
  pwn        -> 指向 catch（或 catch 改名而来）
  pwn_orig   -> 原始二进制，catch 内部调用
  catch
  logs/      -> makefile 中 log path，落盘连接数据
```

```text
# 验证：自打一次后应能在 logs/ 看到本次输入
1) 启动题目（正常监听）
2) 用本地 exp 连一次并发 payload
3) 读取 logs/ 下新生成文件，比对与发送内容一致，且客户端收到原程序输出
```

说明：`pwn_waf` 的具体编译参数与日志格式随工具版本变化，这里只给替换思路与验证方法；未在赛事环境复跑。

## 变体与关联

- 变体：不替换二进制，而在启动脚本里用 `socat`/`ncat` 的 `-x`/tee 做“端口转发 + 双向落盘”，避免改题目文件。
- 变体：用 `LD_PRELOAD` hook `read/recv` 落盘，保留原文件与其哈希（避免被赛事完整性检测发现）。
- 变体：捕获后做自动化解析——按 recv 块切分多轮 payload、提取十六进制地址、聚类对手 payload 模板。
- 关联：[[ctf-pwn-awd-round-loop-flag-collect-submit]]（进攻侧轮次循环与提交）、[[ctf-pwn-awd-batch-scan-concurrent-exp-runner]]（批量 exp 调度）；本条是防守侧的观测手段。
- 边界：包装器引入延迟/缓冲改变时序，可能让时间类 oracle 的对手误判；题目有完整性校验或只读挂载时无法替换；日志过大会写满磁盘。

## 检测与防御

- 检测（作为对手/裁判视角）：题目目录出现新文件、进程树里出现“包装程序 → 原二进制”两层、`/proc/*/cmdline` 与文件哈希不一致。
- 检测（作为防守方自查）：确认替换未破坏协议时序，日志写入失败时要降级为直接 exec，避免服务不可用。
- 防御（赛事组织侧）：对下发的二进制做哈希/签名校验、只读挂载、限制目录写权限，可阻止此类替换。
- 合规：只在自家靶机与授权范围内使用；日志属敏感取证材料，避免包含对手凭据外泄。
