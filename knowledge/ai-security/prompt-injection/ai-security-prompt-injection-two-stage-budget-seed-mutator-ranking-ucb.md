---
id: ai-security-prompt-injection-two-stage-budget-seed-mutator-ranking-ucb
title: 提示注入模糊测试的两阶段调度：准备阶段轮询评估种子/变异器/验证防御并排名，专注阶段用 UCB 树选择种子 + 按权重采样变异器 + 提前终止省预算
type: scenario
domain: ai-security
path: ai-security/prompt-injection
technique: two-stage-prompt-fuzz-budget-scheduling-ucb-early-stop
aliases:
- PROMPTFUZZ 两阶段
- 准备阶段 Preparation Stage
- 专注阶段 Focus Stage
- UCB 种子选择器
- 变异器权重 mutatorASR
- 提前终止系数 epsilon
- 种子池更新
- 验证防御机制
tags:
- ai-security
- prompt-injection
- fuzzing
- red-team
- scheduling
- ucb
- budget
- llm
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:52:19+08:00'
  notes: 已对照原文核对：准备/专注两阶段的划分、攻击矩阵 A 与 seedASR/mutatorASR 排名、保留 Top-K 种子与每变异器 Top-T 变体、UCB 树选择（图08 四步）、按变异器权重采样、|Dt|*bestASR*eps 提前终止与不入池、few-shot 余弦相似度 top-R、TensorTrust 语料，均与原文一致；未验证点：PoC 为按原文 Algorithm 1 重写的最小骨架，原文未给完整可执行实现，未运行
---

## 一句话结论

把提示注入黑盒 fuzz 的有限查询预算分成两段：**准备阶段**对每个种子 × 变异器 ×（一组已知的）验证防御机制做轮询评估，得到攻击成功矩阵 A，据此给种子算 `seedASR`、给变异器算 `mutatorASR` 并保留前 K 个种子与前 T 个高质量变体；**专注阶段**只在排名靠前的种子上迭代，用 UCB 树搜索在“探索/利用”间选择种子、按 `mutatorASR` 权重采样变异器、并引入提前终止——当前变体若已在 `|Dt|·bestASR·ε` 个目标防御上失败就停止评估且不入池。这样在攻击者看不到真实目标防御 `Dt` 的前提下，既能把预算压在有效组合上，又能避免被高优先级的劣质新种子带偏。

## 原理

- **为什么必须分两阶段**：种子与变异器的组合空间非常大（S × M × D），一开始就均匀投入会浪费预算；先用小份额资源“试点”所有组合，得到统计上可比较的成功率，再决定主攻方向，是灰色/黑色盒 fuzz 通用的“先分诊后聚焦”策略。
- **为什么用攻击矩阵 A**：把每次“种子 i + 变异器 j + 防御 k 是否成功”累加到 `A[i,j,k]`，就让排名可计算：`seedASR = Σ_j,k A[i,j,k]/(M·D)`、`mutatorASR = Σ_i,k A[i,j,k]/(S·D)`。这两个量分别是“哪种起点更容易长成有效变体”和“哪种变异算子更常产出有效变体”。
- **为什么需要“验证防御”而不是真实防御**：攻击者不知道目标的真实防护机制 `Dt`，但可以用一组“构建方式与真实机制相似且自己已知”的验证防御 `Dv` 来评估变体有效性——既有区分度又不至于过拟合到某一个具体规则。
- **UCB 树为什么适合种子选择**：种子池是树状结构（新变体挂在父种子下）。UCB 分数 = 利用项（该节点已知成功率） + 探索项（访问次数少的节点加成），能在“继续深挖已成功种子”和“给新加入的高优先级但未验证种子一次机会”之间平衡，避免纯贪心陷入局部最优。
- **按权重采样变异器为什么有效**：`W[j] = mutatorASR` 越大越常被选中，等于把预算从低效算子（如“缩短”常常破坏注入）转移给高效算子（如“改写/扩展”）而不完全放弃探索。
- **提前终止为什么省预算且防陷入局部最优**：判定一个变体“无希望”不需要跑完所有防御——若它已经在 `|Dt|·bestASR·ε` 个防御上失败，它即便成功也不足以超过当前最优 `bestASR`，继续评估就是纯浪费；同时把它排除出种子池，避免 UCB 因为“新加入节点优先”而在后续轮次反复选中它。且阈值随 `bestASR` 抬升而变严，越到后期越聚焦。
- **为什么要 few-shot 相似检索**：变异器并不是凭空改写种子，而是从保留的成功变体里挑与当前种子最相似的前 R 个作为示例，把“历史上什么形态有效”注入到变异模型的上下文里，提高生成有效变体的概率。

## 触发条件

- 有明确授权，能对目标 LLM/应用做批量查询，并有查询预算上限 B（次数或时间）。
- 有种子池（人工种子或公开数据集如 TensorTrust）、变异器集合 M（见关联卡）、以及可自我构造的验证防御集合 Dv。
- 有一个能判定“是否注入成功”的 oracle O（例如目标是否输出指定字符串、是否泄露系统提示、是否执行被注入的指令）。
- 种子选择器、成功率统计与提前终止逻辑由脚本维护（原文用 gptfuzzer 库 + 自写实验脚本）。

## 利用步骤

1. 准备阶段初始化：`S=|seeds|`、`M=|mutators|`、`D=|Dv|`，把 `A = zeros(S, M, D)`、`W = zeros(M)`、保留变体字典 `P` 清零。
2. 轮询评估：对每个种子 i、每个变异器 j 生成变体，再对每个验证防御 k 执行查询并用 oracle 判定；成功则 `A[i,j,k] += 1`，并把该变体记入 `P[j]` 的成功计数。
3. 排名与保留：对每个种子算 `seedASR` 并取前 K 个；对每个变异器算 `mutatorASR` 写入 `W`；对每个变异器取成功次数前 T 个变体存入 `P̄`。
4. 专注阶段初始化：`bestASR = 0`、历史列表清空、按目标防御 `Dt` 的数量确定 D；用前 K 个种子初始化 UCB 树。
5. 每轮：用 UCB 从树里选种子 → 按 `W` 采样变异器 → 用嵌入余弦相似度从 `P̄` 里取前 R 个最相似变体作 few-shot → 生成变体。
6. 执行与判定：在 `Dt` 上查询并用 oracle 判定，算 `ASR`；若 `ASR > 0` 把变体加入种子池并更新 UCB 节点统计。
7. 提前终止：若当前变体已在 `|Dt|·bestASR·ε` 个防御上失败，跳过剩余防御、且不入池；随着 `bestASR` 抬升该阈值自动变严。
8. 直到达到停止条件（迭代数、成功次数、时间或预算 B），输出累积的成功变体与其成功率。

## PoC

调度逻辑的最小骨架（不含真实模型调用）：

```python
import math

class UCBNode:
    def __init__(self, seed):
        self.seed, self.children, self.visits, self.success = seed, [], 0, 0

def ucb(node, total, c=1.414):
    if node.visits == 0:
        return float("inf")                 # 新节点优先探索一次
    return (node.success / node.visits) + c * math.sqrt(math.log(total) / node.visits)

def ucb_select(roots):
    node, total = None, sum(r.visits for r in roots) + 1
    best = max(roots, key=lambda r: ucb(r, total))
    while best.children:                    # 沿最优点下探
        total = sum(c.visits for c in best.children) + 1
        best = max(best.children, key=lambda c: ucb(c, total))
    return best

def prepare(seeds, mutators, defenses, oracle, query):
    A = [[[0] * len(defenses) for _ in mutators] for _ in seeds]
    P = {j: [] for j in range(len(mutators))}
    for i, s in enumerate(seeds):
        for j, m in enumerate(mutators):
            mutant = m.apply(s)
            for k, d in enumerate(defenses):
                if oracle(query(mutant, d)):
                    A[i][j][k] += 1
                    P[j].append(mutant)
    return A, P

def focus(seeds_ranked, mutators, W, Pbar, defenses, oracle, query,
          budget, eps=0.8, top_t=3, top_r=3):
    roots = [UCBNode(s) for s in seeds_ranked]
    best, history = 0.0, []
    for _ in range(budget):
        node = ucb_select(roots)
        chosen = weighted_pick(mutators, W)          # W = mutatorASR
        exemplars = top_similar(node.seed, Pbar[chosen], top_r)
        mutant = chosen.apply(node.seed, exemplars)
        ok = 0
        for idx, d in enumerate(defenses):
            # 提前终止：已失败阈值即放弃，且不入池
            if idx >= len(defenses) * best * eps and best > 0:
                break
            if oracle(query(mutant, d)):
                ok += 1
        asr = ok / len(defenses)
        history.append((mutant, asr))
        if asr > 0:
            child = UCBNode(mutant)
            node.children.append(child)
            node.visits += 1
            node.success += asr
        best = max(best, asr)
    return history, best
```

说明：原文对应的是 PROMPTFUZZ 算法 1（准备阶段）与专注阶段的流程说明，并给出对应的实验脚本（`gptfuzzer` 库、`run_fuzzer`、概率选择 `AccessGrantedPredictor`/`MatchPredictor`、`--phase preparation|focus` 与 `--all_defenses` 参数）；原文未在文中给出完整可执行实现，本卡为按其描述重写的最小调度骨架，未运行。

## 变体与关联

- **阶段切分变体**：去掉准备阶段（直接在全种子上专注）以省预算但更易陷入局部最优；或做“多轮准备+专注”交替。
- **选择策略变体**：UCB 换成 Thompson 采样、ε-greedy、覆盖率引导（用 query 相似度聚类代替树）；权重采样换成 softmax 温度。
- **提前终止变体**：固定阈值（简单但阻碍早期探索）、按剩余预算动态调 ε、同时用“连续失败次数”而非比例。
- **oracle 变体**：字符串匹配（目标输出指定 token）、系统提示泄露片段匹配、行为差异（是否调用工具/是否返回特定 JSON 字段）。
- **边界**：oracle 误判会把噪声当成功、导致预算被错误分配；验证防御与真实防御差异过大时排名失效；目标有强限速时注意预算 B 的计量单位。
- 关联：[[ai-security-prompt-injection-llm-semantic-mutator-fenced-templates]]（被调度的五个语义变异器）、[[ai-security-prompt-injection-system-prompt-incremental-extraction]]（同领域的多轮提取场景）、[[ai-security-jailbreak-automated-prompt-generation-pipeline]]（另一套“生成-判定-入库”闭环）。

## 检测与防御

- 检测：同一来源在短时间对目标模型发大量结构相似但措辞不同的请求（变体族特征）；请求中出现 few-shot 式“样例 + 围栏 + 改写要求”；成功率在请求量上呈现两阶段分布（前期均匀试探、后期集中）。
- 防御：输入侧做语义级意图识别而不是只做关键词过滤；对同一会话/账号的查询速率与多样性做异常检测；输出侧做确定性检测（如是否泄露系统提示片段）以降低 oracle 的可用性。
- 加固：用这类两阶段 fuzz 定期做红队回归，量化不同防御（预防御/后防御/微调/词表过滤）下的 ASR 变化，而不是依赖单次人工测试。
