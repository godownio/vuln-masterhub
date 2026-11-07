---
id: code-analysis-dynamic-fuzzing-afl-post-library-havoc-virgin-map-extension
title: AFL 二次开发扩展：POST_LIBRARY 后处理钩子、自定义 havoc 算子与 virgin_bits 可视化
type: scenario
domain: code-analysis
path: code-analysis/dynamic/fuzzing
technique: afl-post-library-havoc-virgin-map-extension
tags:
- fuzzing
- afl
- post-library
- havoc
- mutation
- coverage
- visualization
- fuzzing-engineering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V268
  verified_at: '2026-11-07T18:18:39+08:00'
  notes: 已对照原文全文3597行与23张图核对：POST_LIBRARY/afl_postprocess 示例（每100次执行平均长度追加 /tmp/avg_len）、自定义 havoc 算子（switch UR(15+2+extras)，词典算子移到17/18，15/16 写 0xcafe1234/0xbabe5678，需 make clean && make）、virgin_bits 快照（has_new_bits 更新后、存 queue 前 fwrite 到 /tmp/virgin_bits/id:%06u,%s）与 matplotlib 可视化脚本均与正文/图14-22一致；图23为白皮书队列进化图。dedup 候选（libFuzzer harness/MALintent/rust 多 fuzzer/AFLGo）均非同一链，verdict=new；dup-scan 无涉及本篇 pair。工程技巧卡 severity low 合理，无 affected_versions；未在本机重编 AFL/跑 fuzz
url: /docs/code-analysis/dynamic/fuzzing/code-analysis-dynamic-fuzzing-afl-post-library-havoc-virgin-map-extension/
draft: false
kb_aliases:
- AFL POST_LIBRARY
- afl_postprocess
- AFL 自定义 havoc 算子
- virgin_bits 可视化
- AFL 二次开发
- AFL 扩展变异
---

## 一句话结论

AFL 提供三类低侵入的二次开发点：用 `AFL_POST_LIBRARY` 加载 `afl_postprocess` 共享库，在每个测试用例送入目标前做统计/改写；修改 `afl-fuzz.c` 的 havoc `switch`，把词典算子后移并插入自定义 magic-number 算子，提升对 `strcmp`/magic 检查的命中率；在 `has_new_bits` 更新 `virgin_bits` 后把该位图落盘，再用 matplotlib 堆叠可视化，直观看到 fuzz 的探索进度与瓶颈。

## 原理

- **AFL 的边覆盖率基础**：插桩在每个基本块写入 `cur_location`，执行 `shared_mem[cur_location ^ prev_location]++`，`prev_location = cur_location >> 1`；`afl-fuzz` 通过共享内存读取 64KB 的 trace bitmap，`virgin_bits` 记录尚未被任何用例命中的边，`has_new_bits()` 在出现新边或 hit count 桶变化时返回非 0，决定是否把用例加入 queue。
- **POST_LIBRARY 后处理钩子**：`common_fuzz_stuff()` 在调用目标前检查全局函数指针 `post_handler`；该指针由 `AFL_POST_LIBRARY` 环境变量指向的共享库中的 `afl_postprocess(uint8_t* buf, uint32_t* len)` 提供。钩子可以读取/修改缓冲区与长度，返回值作为新的输入。文章用它统计每 100 次执行的输入平均长度并追加到 `/tmp/avg_len`，从而观察 fuzz 在发现特定语法（如连续 `a`、栈溢出触发点）后的行为变化。
- **自定义 havoc 算子**：havoc 阶段用 `switch (UR(15 + 2 + ((extras_cnt + a_extras_cnt) ? 2 : 0)))` 选择变异算子；0–14 为常规算子，15/16 为词典覆盖/插入，仅在有词典时可选。把词典算子改到 17/18，并在 15/16 插入自定义算子（如把随机 dword 写成 `0xcafe1234` / `0xbabe5678`），就能在不改变其他阶段的前提下，针对目标程序的 magic number/固定校验值做定向爆破。重新 `make clean && make` 后生效。
- **virgin_bits 可视化**：`has_new_bits(virgin_bits)` 在发现新边时把 `virgin_bits` 对应字节清零并返回 1/2。文章在“保存 queue 用例”之前插入代码，把当前 `virgin_bits` 写入 `/tmp/virgin_bits/id:%06u,<describe_op>`，随后用 Python 读取所有快照、按字节 `!= 255` 标记已覆盖、`imshow` 绘制热图；颜色/条纹可以直观看出哪些区域长期未被探索、fuzz 是否陷入瓶颈。
- **为什么有效**：这三处都不改变 AFL 的核心调度（覆盖率反馈 + 队列进化），只在“输入生成/后处理/进度观测”三个边界上扩展；因此实现简单、风险可控，适合针对特定目标（magic 检查多、输入格式复杂、需要评估覆盖率增长）做定制。

## 触发条件

- 有 AFL 源码并能在本地编译（`make`）；目标程序已用 AFL 插桩（`afl-gcc`/`afl-clang-fast`）编译。
- 使用 `AFL_POST_LIBRARY` 时，共享库导出 `afl_postprocess` 符号，且与 fuzzer 的 ABI 一致（`uint8_t*`、`uint32_t*`）。
- 修改 havoc 算子时，需确认当前 AFL 版本的 `switch` 编号与词典算子位置；不同版本/AFL++ 的算子编号可能不同。
- 需要可写的输出目录（`/tmp/avg_len`、`/tmp/virgin_bits`）以及 Python + matplotlib（可视化）。
- 仅用于授权的漏洞挖掘/研究工作；不要在未授权目标上运行 fuzz。

## 利用步骤

1. **准备 AFL 与目标**：`make` 编译 AFL；用 `./afl-gcc target.c -o target -g`（或 `afl-clang-fast`）编译目标，准备 seeds 目录。
2. **POST_LIBRARY**：编写 `afl_postprocess`（示例统计平均长度），`gcc -fPIC -shared work.c -o mypost.so`；运行 `AFL_NO_UI=1 AFL_POST_LIBRARY=./mypost.so ./afl-fuzz -i ./corpus -o ./work -- ./target`；从 `/tmp/avg_len` 读取统计并用 matplotlib 画 `avg len` 随 `exec/100` 的变化。
3. **自定义 havoc**：在 `afl-fuzz.c` 的 havoc `switch` 中，把 `case 15/16`（词典）改为 `case 17/18`，在 `case 15/16` 插入自定义变异（如随机位置写 `0xcafe1234`/`0xbabe5678`）；`make clean && make` 重新编译，运行 fuzz，观察是否更早触发 magic 检查后的深路径/crash。
4. **virgin_bits 追踪**：在 `has_new_bits` 返回非 0、保存 queue 用例之前，把 `virgin_bits` 写入 `/tmp/virgin_bits/id:%06u,<describe_op>`（`fwrite(virgin_bits, 1, sizeof(virgin_bits), fp)`）；运行 fuzz 产生快照。
5. **可视化**：用 Python 读取快照，按 `data != 255` 标记已覆盖，`imshow` 绘制；结合 `fuzzer_stats` 的 `execs_done`、`paths_total`、`unique_crashes` 判断覆盖率增长是否停滞。
6. **迭代**：根据热图/统计调整种子、字典、自定义算子或插桩比例；保留改动前后的 fuzz 结果做对比。

## PoC

POST_LIBRARY 示例（统计每 100 次执行的平均输入长度）：

```c
#include <stdio.h>
#include <stdint.h>

uint8_t* afl_postprocess(uint8_t* buf, uint32_t* len) {
    static uint32_t len_sum, cnt;
    len_sum += *len;
    cnt++;
    if (cnt == 100) {
        FILE* fp = fopen("/tmp/avg_len", "a");
        fprintf(fp, "%lf\n", (double)len_sum / cnt);
        fclose(fp);
        len_sum = 0;
        cnt = 0;
    }
    return buf;
}
```

```bash
gcc -fPIC -shared work.c -o mypost.so
AFL_NO_UI=1 AFL_POST_LIBRARY=./mypost.so ../afl-fuzz -i ./corpus -o ./work -- ./app
```

自定义 havoc 算子（插在 `afl-fuzz.c` 的 havoc switch 中，词典算子后移）：

```c
case 15: {
    if (temp_len < 4) break;
    u32 pos = UR(temp_len - 3);
    *(u32*)(out_buf + pos) = 0xcafe1234;
    break;
}
case 16: {
    if (temp_len < 4) break;
    u32 pos = UR(temp_len - 3);
    *(u32*)(out_buf + pos) = 0xbabe5678;
    break;
}
```

virgin_bits 快照与可视化：

```c
/* 在 has_new_bits(...) 返回非 0、保存 queue 用例之前插入 */
{
    u8* virgin_filename = alloc_printf("/tmp/virgin_bits/id:%06u,%s",
                                       queued_paths, describe_op(hnb));
    FILE* virgin_fp = fopen(virgin_filename, "w");
    fwrite(virgin_bits, 1, sizeof(virgin_bits), virgin_fp);
    fclose(virgin_fp);
    ck_free(virgin_filename);
}
```

```python
import os
import numpy as np
import matplotlib.pyplot as plt

data = []
for name in sorted(os.listdir('virgin_bits')):
    with open(os.path.join('virgin_bits', name), 'rb') as f:
        data.append(list(f.read()))

data = (np.array(data) != 255)
touched = data.any(axis=0)
data = data[:, touched]
plt.imshow(data, cmap='Blues')
plt.xlabel('virgin map')
plt.show()
```

说明：PoC 按文中代码整理，未在本机重新编译 AFL/运行 fuzz；`switch` 编号、`virgin_bits` 写入位置与 `describe_op` 签名随 AFL 版本变化，需按实际源码调整。

## 变体与关联

- **AFL++ 等价扩展**：AFL++ 提供自定义 mutator API、`AFL_CUSTOM_MUTATOR_LIBRARY`、`AFL_POST_PROCESS_KW` 等更规范的扩展点；概念与本卡的 havoc/POST_LIBRARY 相同，但接口不同。
- **定向 fuzz**：若目标是特定代码位置，用 AFLGo 的距离插桩/模拟退火比盲目加 magic 算子更高效（见关联卡）。
- **字典优先**：如果 magic 值已知，优先用 `-x dict` 与自动字典；自定义 havoc 算子适合“无法枚举全部 magic/需要随机组合”的场景。
- **virgin map 替代**：AFL 自带 `fuzz_bitmap`、`plot_data`、`afl-plot`；自定义快照适合需要细粒度时间序列/热图的场景。
- 关联：[[code-analysis-dynamic-fuzzing-aflgo-directed-distance-instrumentation]]（AFLGo 距离插桩与定向 fuzz）、[[code-analysis-dynamic-fuzzing-libfuzzer-engineering-corpus-parallel-dict-coverage]]（libFuzzer 的语料/字典/并行工程）、[[code-analysis-dynamic-fuzzing-rust-cargo-fuzz-afl-honggfuzz]]（多 fuzzer 工作流）。
- 边界：AFL 版本差异导致 `switch`/`has_new_bits` 代码位置不同；POST handler 若修改输入语义可能引入误报；自定义算子可能降低通用性、增加无效执行；virgin_bits 快照频繁写盘会影响 fuzz 性能。

## 检测与防御

- **工程校验**：每次改动后对比 `fuzzer_stats`（`execs_done`、`paths_total`、`unique_crashes`、`execs_per_sec`），确认没有明显性能下降；用 `afl-showmap`/`afl-cmin` 验证覆盖率与语料精简。
- **输入一致性**：POST handler 只做可逆的统计/轻量改写；若改写输入，需保证目标仍能正常解析，避免把 fuzzer 引入无效路径。
- **版本管理**：把 AFL 源码改动、编译器版本、字典与种子一起纳入版本控制，记录改动前后的 fuzz 结果，便于复现。
- **资源与隔离**：fuzz 在隔离环境/容器中运行；限制 `/tmp` 写盘与 CPU/内存；对目标启用 ASAN/UBSAN 时降低插桩率（`AFL_INST_RATIO`）避免误报。
- **合规**：仅对授权目标/自研程序进行 fuzz；不要将自定义算子用于未授权的第三方服务。
