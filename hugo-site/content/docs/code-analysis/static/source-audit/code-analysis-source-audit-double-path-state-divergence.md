---
id: code-analysis-source-audit-double-path-state-divergence
title: 双路径分歧审计：长度计算/执行共享状态导致缓冲区长度不一致，或编译/运行时编码不一致
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: double-path-state-divergence-audit
tags:
- source-audit
- nginx
- varnish
- split-path
- state-divergence
- heap-overflow
- length-mismatch
- compile-time
- runtime
cve:
- CVE-2026-42945
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: nginx 1.30.0（原文分析版本；CVE-2026-42945）
verification:
  verified_by: verifier-V103
  verified_at: '2026-11-05T22:32:25+08:00'
  notes: 已对照原文与11张提取图片核对：ngx_http_complex_value 两阶段共用 e、copy_capture_len_code/copy_capture_code 同条件不同 is_args、Varnish EncToken/VRT_SetHdr 7次引用均与截图一致；CVE-2026-42945 与 nginx 1.30.0 为原文说法，未复跑 PoC。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-double-path-state-divergence/
draft: false
kb_aliases:
- 双路径分歧
- Split-path divergence
- nginx is_args 堆溢出
- 长度计算与执行不一致
- 编译时与运行时路径分叉
- Varnish EncToken/VRT_SetHdr
- CVE-2026-42945
---

## 一句话结论

同一份输入先后经过“长度计算/执行”或“编译/运行时”两条路径，而两条路径共享可变状态或使用不同解释器时，前一条路径算出的长度/转义结果可能与后一条路径实际写入的内容不一致，形成堆溢出或配置/头部注入；审计时应画三阶段链、标出两次调用之间被修改的 flag/状态，并验证两阶段是否共用同一变量。

## 原理

- **nginx is_args（长度计算 ↔ 执行）**：`ngx_http_script_complex_value_code` 使用两个同类型引擎实例：主引擎 `e`（执行拷贝）与子引擎 `le`（算长度，`ngx_memzero(&le)` 清零）。长度阶段用 `le.ip = code->lengths->elts` 遍历 `lcode(&le)`，按 `len` 分配 buffer；执行阶段用主引擎 `e` 遍历 `code(&e)`。
  - `copy_capture_len_code` 与 `copy_capture_code` 的条件写法一样：
    `if ((e->is_args || e->quote) && (e->request->quoted_uri || e->request->plus_in_uri))`
    但长度阶段的函数形参名虽为 `e`，实际传入的是子引擎 `le`；`ngx_memzero(&le)` 把 `le.is_args` 清零，条件不成立，返回原始 `cap[n+1]-cap[n]`。执行阶段传入主引擎 `e`，`ngx_http_script_start_args_code` 已在 rewrite 替换串带 `?` 时把 `e->is_args` 设为 1，条件成立，调用 `ngx_escape_uri(..., NGX_ESCAPE_ARGS)` 写入转义展开后的更长内容。
  - 结果：buffer 按短长度分配，执行时写入长内容 → 堆溢出（CVE-2026-42945）。
  - 一个易踩坑：nginx 1.30.0 没有独立的 `ngx_http_script_len_engine_t`；`e` 与 `le` 是同一个 `ngx_http_script_engine_t` 类型的两个实例。更隐蔽的是长度函数内部检查的是形参 `e` 的状态，而调用方传的是 `le`——变量命名掩盖了跨引擎状态读取。
- **Varnish VCL（编译时 ↔ 运行时）**：VCL 不是解释执行，而是 VCC 编译器把 token 通过 `EncToken(e1->vsb, tl->t)` 编码进生成的 C 源文件，GCC 编成 `.so`，cache 进程 `dlopen` 加载。运行时 `VRT_SetHdr` 把字符串写进 HTTP 响应头，中间没有重新转义/校验层。编译阶段检查 token 合法性，运行阶段信任已编译的 C 代码——同一个 VCL 字符串在两条路径上被不同地解释。
- **共性**：性能优化倾向于“多走一次”（先算长度避免 realloc、先编译避免运行时解析），两次走时都假设状态“和第一次一样”，但状态在两次之间被 flag 赋值、配置合并、上下文切换改变；或者第二条路径根本没有重新检查第一条路径的结论。
- 这类问题可以表现为：长度/分配不匹配（堆溢出）、转义/编码不一致（CRLF/头部注入、路径穿越）、校验/使用不一致（TOCTOU）、编译/运行时不一致（代码注入）。

## 触发条件

- 代码存在多阶段处理：长度计算→分配→执行、校验→使用、编译→运行、序列化→反序列化等。
- 两阶段之间共享可变变量/结构体/全局状态，且存在 flag、配置、上下文在阶段间被修改。
- 第二条路径假设第一条路径已经检查/计算好，不再重新验证或重新计算。
- 输入可以影响阶段间状态（如 rewrite 中的 `?`、quoted_uri/plus_in_uri、编码字符、配置片段）。

## 利用步骤

1. 画三阶段链：定位“长度计算 → buffer 分配 → 执行写入”或“编译 → 生成产物 → 运行时加载”的代码。
2. 标状态变更点：搜索两次调用之间的 `flag =`、`is_args`、`quote`、配置合并、`e->` 字段写入、全局状态修改。
3. 验证状态共享：确认两阶段用的是同一个变量/结构体实例，还是同类型的两个实例（如 `e` 与 `le`）；后者要追踪子函数实际读取的是哪个实例的状态。
4. 对比两条路径的条件分支：长度计算与执行是否使用相同条件但不同状态？编译检查与运行时写入是否使用不同转义？
5. 构造能改变阶段间状态的输入（如带 `?` 的 rewrite、需要 `NGX_ESCAPE_ARGS` 的 capture、含编码字符的 prefix），观察分配长度与实际写入长度/转义结果。
6. 用 ASan/Valgrind/差分测试验证；对配置类目标，比较编译产物与运行时输出。

## PoC

```c
/* nginx 伪代码：主引擎 e 与子引擎 le，两阶段状态不同 */
ngx_http_script_engine_t e, le;
ngx_memzero(&le, sizeof(ngx_http_script_engine_t));  /* le.is_args = 0 */
le.ip = code->lengths->elts;
le.request = e->request;
for (len = 0; *(uintptr_t *) le.ip; ) {
    lcode = *(ngx_http_script_len_code_pt *) le.ip;
    len += lcode(&le);            /* 传入 le，copy_capture_len_code 读到 le.is_args=0 */
}
e->buf.data = ngx_pnalloc(e->request->pool, len);     /* 按原始长度分配 */

e->pos = e->buf.data;
/* start_args_code 已在 rewrite 替换串带 ? 时把 e.is_args 设为 1 */
for ( ; *(uintptr_t *) e.ip; ) {
    code = *(ngx_http_script_code_pt *) e.ip;
    code(&e);                     /* 传入 e，copy_capture_code 读到 e.is_args=1，执行 escape 展开 */
}
```

```text
# Varnish：一行 VCL 被编译成多处运行时调用
vcl 4.1;
backend default { .host = "127.0.0.1"; .port = "8080"; }
sub vcl_recv { set req.http.X-Test = "hello"; }

varnishd -C -f test.vcl | grep -c "VRT_SetHdr"   # 7
# 编译阶段 EncToken 写入 C 源；运行时 VRT_SetHdr 直接写头部，无二次转义
```

## 变体与关联

- 变体：`snprintf` 返回值当长度导致截断/越界、整数溢出导致分配过小、UTF-8/UTF-16 长度与实际字节数不一致、路径规范化前后不一致。
- 变体：编译时校验、运行时不再校验（模板/JIT/DSL）；序列化时校验、反序列化时信任。
- 关联：[[binary-pwn-stack-snprintf-return-length-read-overflow]]（返回值/长度不一致）、[[code-analysis-source-audit-dsl-config-sprintf-injection]]（编译/运行时配置注入）、[[code-analysis-source-audit-additive-cve-fix-chain]]（修复链断裂）、[[cloud-k8s-ingress-nginx-spec-path-quote-config-injection]]（模板转义缺失的具体 CVE）。
- 边界：需要能影响阶段间状态或输入；单阶段实现、每次重新计算/重新校验的代码不受影响；具体 CVE 的可利用性依赖版本与缓解措施。

## 检测与防御

- 检测：审计多阶段函数，重点看两阶段共享的结构体字段与 flag；对比长度计算与执行、校验与使用、编译与运行的条件；用差分输入（会改变 flag/编码的输入）做 fuzz；ASan/Valgrind 捕捉分配/写入不一致。
- 修复：只计算一次长度/转义结果并复用；或执行阶段重新计算/重新校验；避免在阶段间修改共享状态；把状态作为不可变参数传递。
- 加固：编译期/运行期使用同一套转义与校验函数；对配置 DSL 做结构化生成而不是字符串拼接；回归测试覆盖会改变状态的边界输入。
