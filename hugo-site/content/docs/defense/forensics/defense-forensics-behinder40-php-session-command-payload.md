---
id: defense-forensics-behinder40-php-session-command-payload
title: 冰蝎4.0 PHP 会话与命令执行流量：连接/信息包结构、cmd/path 的 Base64 与六函数回退链
type: scenario
domain: defense
path: defense/forensics
technique: behinder40-php-session-command-payload
tags:
- defense
- forensics
- traffic-analysis
- webshell
- behinder
- php
- base64
- incident-response
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V453-fix
  verified_at: '2026-11-10T02:26:14+08:00'
  notes: V453 核对指出原文样本的 cmd/path 是两行赋值 $cmd="<base64>"; $cmd=base64_decode($cmd);（path 同形），原卡步骤4 写作 $cmd=base64_decode("...")、PoC 正则无法匹配原文样本。已改写步骤4 为两行赋值结构，PoC 的 extract_cmd 改为 grab_var() 先匹配两行赋值、再回退匹配内联 base64_decode，并注明第6分支 is_callable('exec')+popen 的插件笔误按文章总结仍记 popen。其余连接/信息包/回退链/回显核对不变。
url: /docs/defense/forensics/defense-forensics-behinder40-php-session-command-payload/
draft: false
kb_aliases:
- 冰蝎4.0连接包
- 冰蝎基础信息包
- 冰蝎命令执行payload
- 冰蝎信息收集流量
- Behinder PHP session packet
---

## 一句话结论

冰蝎 4.0 PHP 会话解密后，连接包是 `assert|eval(base64_decode('...'))` 包着 `main/Encrypt` 框架的插件代码，紧随的基础信息包会回传 phpinfo、盘符、当前路径、系统与内网 IP；命令执行包的明文里含 `$cmd`、`$path` 两个 Base64 变量和 `main($cmd,$path)`，并按 `system → proc_open → passthru → shell_exec → exec → popen` 依次判断可用函数，解出 cmd/path、对响应 `msg` 做 Base64 解码即可还原攻击者执行的命令与回显。

## 原理

- **马端执行模型**：PHP 马读取 `php://input`，用 `$key` 做 AES-128 解密（openssl 不可用时回退为 `base64_decode` + `key[(i+1)&15]` 的 XOR），再 `explode('|', $post)` 取出功能名与参数，最后 `call_user_func(new C(), $params)` 进入 `eval`。因此解密出的“请求体”就是操作插件的 PHP 源码，操作语义写在代码里，而不是 URL 或参数名里。
- **密钥来源**：`$key` 是连接密码 32 位 MD5 的前 16 个字符；默认密码 rebeyond 对应默认 key `e45e329feb5d925b`。密码已知、为默认值或被破解时，无需马文件即可推导 key；否则要从马文件或 `$_SESSION['k']` 取得。openssl 未加载时走 XOR 回退，解密顺序必须按马代码。
- **连接/信息包为什么长这样**：连接包内层 base64 是一段自包含插件，定义 `main($content)` 与 `Encrypt($data)`，把结果放进 `status/msg` 的 Base64 JSON 后加密输出；信息包在 `main` 里用输出缓冲抓取 `phpinfo()`，遍历 A–Z 盘符、`getcwd()`、`PHP_OS`、`PHP_INT_SIZE` 取系统与位数，并 `exec('arp -a')` 枚举同网段主机，最后把 `basicInfo/driveList/currentPath/osInfo/arch/localIp` 逐项 Base64 后回传。
- **为什么命令执行包可识别**：插件固定带 `$cmd`、`$path` 两个 Base64 赋值与 `main($cmd,$path)` 调用；`main` 先读 `disable_functions`，再按固定顺序做 `is_callable` 判断并执行，全部不可用才返回 fail。该回退链是冰蝎 PHP 命令执行插件的稳定结构。
- **回显编码**：执行结果经 `getSafeStr()` 做 UTF-8/GBK 往返修正后 Base64 放进 `msg`，JSON 信封再整体加密；所以解一层响应得到 JSON，再解 `msg` 得到命令输出的原始文本。

## 触发条件

- 有冰蝎 PHP 会话的 pcap/HTTP 日志，且已通过马文件、密码或内存得到 key 完成解密（算法细节见关联卡）。
- 需要判定攻击者是否只做了连接/信息收集，或进一步执行了系统命令。
- 响应体完整（命令回显在 `msg` 里）。

## 利用步骤

1. 逐条解密请求与响应；若明文不是可读 PHP/JSON，先确认 key 与算法（AES-CBC、AES-ECB、XOR 回退）是否匹配。
2. 识别连接包：明文形如 `assert|eval(base64_decode('<b64>'))`；对内层 Base64 再解码，得到含 `function main($content)`、`function Encrypt($data)`、`$_SESSION['k']` 的插件源码。
3. 识别基础信息包：插件里出现 `ob_start(); phpinfo();`、盘符遍历、`getcwd()`、`PHP_INT_SIZE`、`exec('arp -a')`；响应解密后是 JSON，`msg` 再 Base64 解码得到 JSON，字段 `basicInfo/driveList/currentPath/osInfo/arch/localIp` 再逐项 Base64 解码；`basicInfo` 就是 phpinfo 输出。
4. 识别命令执行包：明文含两行赋值 `$cmd="<base64>"; $cmd=base64_decode($cmd);`（`$path` 同形）、`main($cmd,$path)`，以及 `is_callable('system')`、`proc_open`、`passthru`、`shell_exec`、`exec`、`popen` 的回退判断；解码 cmd 与 path。原文样本第 6 分支以 `is_callable('exec')` 判断后调用 `popen`（插件自身笔误），本卡按文章总结仍记为 `popen`。
5. 还原回显：响应解密 → JSON → `msg` Base64 解码；Windows 下命令会追加 `2>&1`，输出已合并 stderr。
6. 按时间排序连接、信息收集与命令执行，标注攻击者掌握的资产信息（内网 IP、盘符、路径）与执行过的命令。

## PoC

无攻击 PoC（取证场景）。解析思路示例：

```python
import base64, json, re

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def envelope(plain_json: str) -> bytes:
    # plain_json 为已解密的 JSON 文本
    return b64d(json.loads(plain_json)["msg"])

# 命令执行请求：从解密后的 PHP 插件源码取 cmd/path
# 原文样本是两行赋值：$cmd="<base64>"; $cmd=base64_decode($cmd);（path 同形）
def grab_var(plain_php: str, var: str):
    m = re.search(rf'\${var}\s*=\s*["\']([^"\']+)["\']\s*;\s*\${var}\s*=\s*base64_decode\(\${var}\)', plain_php)
    if not m:
        m = re.search(rf'\${var}\s*=\s*base64_decode\(["\']([^"\']+)', plain_php)
    return m.group(1) if m else None

def extract_cmd(plain_php: str):
    cmd_b64 = grab_var(plain_php, "cmd")
    path_b64 = grab_var(plain_php, "path")
    return (b64d(cmd_b64).decode(errors="replace"),
            b64d(path_b64).decode(errors="replace"))

# 信息包响应：msg 再解一层成 JSON，字段再逐项 Base64
def basic_info(plain_json: str):
    obj = json.loads(envelope(plain_json))
    return {k: b64d(v).decode("utf-8", "replace") for k, v in obj.items()}
```

说明：按报文结构重写，未对实际流量复跑；字段名与回退顺序以具体马/插件版本为准，遇到运行时生成的变量名（如随机函数名变量）需按赋值结构而非字面量匹配。

## 变体与关联

- [[defense-forensics-behinder-php-webshell-traffic-decrypt]]：AES-128-CBC 零 IV 的完整解密流程与 key 提取。
- [[defense-forensics-behinder-php-default-key-aes-ecb-traffic-decode]]：默认 key、AES-ECB 与 magicNum 截断等变体。
- [[defense-forensics-behinder-php-rc4-xor-modified-traffic]]：RC4+XOR 魔改马的解密顺序。
- [[defense-forensics-behinder-jsp-md5-password-key-traffic-decrypt]]：JSP 冰蝎同样使用密码 MD5 前 16 位派生 AES key，但插件是 Java class，操作字段不同。
- [[defense-forensics-behinder40-php-file-operation-response-parse]]：同一会话的文件操作回显结构。
- [[defense-detection-behinder40-client-traffic-fingerprint]]：先用客户端头部指纹定位会话，再做本卡解析。
- 变体：马可能改写函数名变量、改用 `array_map`/动态调用、调整回退顺序；openssl 禁用时命令与回显都走 XOR；ASPX/ASP 马为 .NET 插件，字段与回显结构不同。
- 边界：只抓到单向流量、key 动态生成且未落地、流量被 TLS 保护时，需要主机取证或内存镜像配合。

## 检测与防御

- 检测：同一脚本路径高频 POST；请求体为 Base64/高熵；解密后出现 `assert`、`eval`、`call_user_func`、`phpinfo`、`arp -a`、`proc_open`、`passthru`、`shell_exec`、`popen` 等特征组合。
- 检测：响应 JSON 的 `status`/`msg` 均为 Base64、加密后整体为高熵；基础信息包会暴露大量主机指纹，可作为“侦察阶段”标记。
- 防御：上传目录禁止脚本解析、禁用 `eval`/`assert` 与危险函数、Web 服务低权限运行、限制出网；部署 WebShell 检测与 NTA 规则。
- 响应：隔离主机、保存 pcap/马文件/内存镜像，提取 key 解密全部历史会话，按本卡还原命令与信息收集结果，评估横向移动与凭据泄露。
