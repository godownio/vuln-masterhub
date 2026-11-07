---
id: defense-forensics-app-service-call-log-timeline
title: 无中间件访问日志时用应用服务调用日志还原 Java 入侵
type: scenario
domain: defense
path: defense/forensics
technique: app-service-call-log-timeline
tags:
- forensics
- java
- log-analysis
- timeline
- incident-response
- webshell
- ufida
- yonyou
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V3
  verified_at: '2026-11-04T22:02:19+08:00'
  notes: 已对照原文与图 01-10 核对：三条调用日志的 userid/remoteAddr/remoteCallMethod/costtime/readfromclientbytes=1780/writetoclientbytes=100、sol.jsp 修改时间 19:41:23 与 1393 字节、创建时间存疑、1102/104 日志清除、UGTfsAcga.exe 19:42:16 与 .weax 加密时间线均一致；原文无法定位具体漏洞编号，卡片明确留白；取证脚本未执行。
url: /docs/defense/forensics/defense-forensics-app-service-call-log-timeline/
draft: false
kb_aliases:
- 用友 U8C 调用日志溯源
- remoteCallMethod 日志分析
- 无 Tomcat 访问日志溯源
- 服务调用日志时间线
---

## 一句话结论

当 Tomcat 等中间件没有开启访问日志时，Java 企业应用自身在服务调用层记录的日志仍包含每次远程调用的时间、`userid`、`remoteAddr:port`、`remoteCallMethod`、耗时与读写字节数；用这些字段可以区分匿名探测、内部身份利用调用和载荷上传，再与 WebShell 文件的修改时间对齐，重建从入口到加密的完整时间线。

## 原理

- Java 企业应用（尤其用友 U8 Cloud/UAP 这类 RPC/服务化架构）通常在业务方法入口统一记录服务调用日志，记录的是“调用层”而非 HTTP 中间件层，因此即使 Tomcat access log 关闭，调用日志仍可能存在。
- 典型字段足以还原行为：
  - `ts`/`begintime`：调用时间，可与文件时间戳精确到秒对齐；
  - `userid`：调用身份，`anonymous` 表示未认证访客，`#UAP#` 等内部标识表示已取得平台内部调用身份；
  - `remoteAddr`：来源 IP 与端口，可做威胁情报与资产归属研判；
  - `remoteCallMethod`：被调用的服务接口，用于判断是否命中敏感/外部系统接口；
  - `readfromclientbytes`/`writetoclientbytes`：从客户端读入与写回的字节数，读多写少通常意味着客户端在上传数据；
  - `readrownum`/`sqlcosttime`：是否真正读写业务数据，可区分“探测”与“利用”。
- 未授权探测通常表现为：`userid=anonymous`、目标为外部系统接口、`readrownum=0`、`readfromclientbytes=0`、耗时数百毫秒。
- 利用成功往往表现为：`userid` 变为内部身份（如 `#UAP#`）、调用登录/写标志类方法、`readfromclientbytes` 明显大于 `writetoclientbytes`（例如读入约 2 KB、只回写 100 字节），说明攻击者把载荷送进了服务器。
- 调用日志只能证明“调用了什么”，不能直接看到 HTTP body；必须用主机侧 WebShell 文件的修改时间、大小与日志时间交叉验证，才能把“调用”和“文件落地”闭合。文件创建时间可被攻击者篡改，修改时间与日志同秒更具证明力。

## 触发条件

- 应用开启了服务调用日志，且保留周期覆盖事件时间窗；
- 日志包含来源地址、调用身份、方法名与读写字节数中的至少若干项；
- 中间件访问日志缺失或已被清理，但应用自身日志仍在；
- 主机侧可获取 Web 目录文件列表及时间戳（文件系统、备份、EDR 遥测均可）；
- 已知业务正常调用的方法与身份基线，才能识别异常。

## 利用步骤（取证分析）

1. 固定证据：导出应用服务调用日志、Web 目录文件列表（含大小/创建时间/修改时间/访问时间）、主机进程执行痕迹与事件日志，记录采集时间与主机时区。
2. 解析日志：按 `ts`、`userid`、`remoteAddr`、`remoteCallMethod`、`costtime`、`readfromclientbytes`、`writetoclientbytes`、`readrownum` 提取字段，统一时区。
3. 建立基线：统计正常业务时段各 `remoteCallMethod` 的调用身份、来源网段与字节数量级；把外部 IP 调用内部服务、匿名调用敏感接口标为异常。
4. 找探测：筛 `userid=anonymous` 且 `readrownum=0`、`readfromclientbytes=0` 的调用，按来源 IP 聚合，判断是否为漏洞可用性探测。
5. 找利用：筛调用身份突变为内部标识（如 `#UAP#`）、且 `readfromclientbytes` 远大于 `writetoclientbytes` 的调用；记录精确时间与方法名。
6. 交叉验证：在 Web 部署目录检索新增/改动的 JSP、脚本或可执行文件，比较修改时间与利用调用时间；文件大小应与读入字节数处于同一量级（含编码开销）。
7. 补主机侧链路：用 Amcache/AppCompatCache、Prefetch、进程创建日志确认加密器或工具的执行时间；检查事件 ID 1102/104 等日志清除记录，标注时间线不可信区间。
8. 输出结论时区分“日志能证明的调用行为”和“只能推断的漏洞编号”；无法定位具体漏洞时明确留白，不要臆断。

## PoC

```bash
# 1) 先看所有远程服务调用中的敏感方法（示例：外部系统接口、登录/写标志接口）
grep -E 'remoteCallMethod=.*(ExtSystemInvokeServer|ILogin2Service|writeFlag)' u8c_call.log

# 2) 统计每个来源 IP 的匿名调用次数
grep 'userid=anonymous' u8c_call.log \
  | grep -o 'remoteAddr=[^;]*' | sort | uniq -c | sort -nr
```

```python
# 3) 解析 key=value 字段，输出可疑调用的时间线
import re, sys

for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    if "remoteCallMethod=" not in line:
        continue
    f = dict(re.findall(r"([A-Za-z$][\w$]*)=([^;]*)", line))
    print(
        f.get("ts", "").strip(),
        f.get("userid", "").strip(),
        f.get("remoteAddr", "").strip(),
        f.get("remoteCallMethod", "").strip(),
        "read=" + f.get("readfromclientbytes", "").strip(),
        "write=" + f.get("writetoclientbytes", "").strip(),
        "rows=" + f.get("readrownum", "").strip(),
    )
```

```text
# 4) 与文件时间对齐的判读示例
调用时间 19:41:23 + 内部身份 + 读入 1780 字节 / 回写 100 字节
Web 目录 sol.jsp 修改时间 19:41:23、大小 1393 字节
  -> 同秒且数量级吻合：调用与文件落地可闭合
```

## 变体与关联

- 变体：应用只记录异常堆栈而没有成功调用日志时，改用异常类型、业务类名与 JNDI 地址做锚点（见关联卡）。
- 变体：Dubbo、HSF、gRPC 等 RPC 框架的调用日志、网关访问日志、WAF 日志、负载均衡日志都能承担“调用层”证据的角色。
- 变体：日志级别过低导致没有字节数字段时，可用请求体长度、WAF 记录、文件大小反推。
- 关联：[[defense-forensics-java-exception-timeline-reconstruction]]（以异常堆栈为锚点）；[[defense-forensics-multisource-timeline-log-clear]]（日志被清后的多源时间线）；[[defense-forensics-ransomware-entry-host-encrypted-last]]（用加密顺序反推入口）；[[web-java-classloader-unsafe-anonymous-class-jsp-shell]]（本案落地载荷的加载方式）。
- 不确定点：调用日志的字段名、保留周期与是否记录 body 字节因产品和版本而异；本卡描述方法，不声称能复现某个具体漏洞。

## 检测与防御

- 检测：同一 `remoteCallMethod` 在短时间内被多个外部 IP 以 `anonymous` 身份调用；匿名探测后数十秒内出现内部身份调用；`readfromclientbytes` 远大于 `writetoclientbytes` 的调用；调用时间与 Web 目录新增小文件同秒。
- 检测：关注 `ILogin2Service.writeFlag`、外部系统调用接口等敏感方法名，以及 `userid=#UAP#` 等内部身份从非可信网段发起的调用。
- 防御：ERP、财务、OA 等核心系统不直接暴露公网，远程访问走 VPN 或网关白名单；对外部系统接口做访问控制。
- 防御：开启并集中留存 Web 中间件访问日志与应用服务调用日志（建议异地留存 180 天以上），把来源 IP、调用身份、方法名、读写字节纳入统一日志平台。
- 检测：对事件 ID 1102（安全审核日志清除）与 104（System/Application 等日志清除）建立实时告警；攻击者清痕迹的动作本身就是告警信号。
- 响应：先保全应用日志与 Web 目录文件时间，再重装或打补丁；补丁后原环境消失会导致具体漏洞点无法复测，取证结论应保留这一限制。
