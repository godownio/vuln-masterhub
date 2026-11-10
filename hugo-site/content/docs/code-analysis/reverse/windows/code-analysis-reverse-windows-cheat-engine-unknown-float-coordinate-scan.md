---
id: code-analysis-reverse-windows-cheat-engine-unknown-float-coordinate-scan
title: Cheat Engine 未知初始值浮点扫描定位 Unity 玩家坐标：增减/不变筛选 + 冻结验证后改坐标穿墙
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: cheat-engine-unknown-float-coordinate-scan
tags:
- reverse
- windows
- game
- cheat-engine
- memory-scan
- float
- unity
- coordinate
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V382
  verified_at: '2026-11-09T09:19:13+08:00'
  notes: 已对照原文全文与 33/33 截图核对：img01 显示 pico.exe 639KB/UnityPlayer.dll 28MB(Unity Mono)、img06/07 Unknown initial value+Float 首扫 Found 215,168,000、img10-16 Increased/Decreased/Unchanged+Repeat 逐步收敛 1,361,194→905,794→6,203→463→64(卡片正文顺序与截图一致)、img17/18 候选 1B20D855BC=Float 2.301950693、img19 Change Value 11、img20/31/32 游戏显示 WELCOME_TO_UNITY!!、img22-30 dnSpy 中 APTX.OnTriggerEnter 与新建 Start 写 this.Mysterious.SetActive(true)。CE 操作序列(未知初值→方向筛选→冻结验证→改值)与原文叙述一致；冻结-不可移动-锁定坐标分量的判定方法准确。原文未给版本，affected_versions 已 clear。与既有已知整数阳光值指针链、CE Mono Dissect、IL2CPP 精确值触发等卡路线不同，非重复。dnSpy 路线跳过判断成立：与既有 code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass(方法体编辑改游戏流程)同场景，静态浏览则由 assembly-csharp-dnspy-analysis 覆盖，rejected 草稿 ingest/rejected/drafts/20261109-080949-unity-mono-assembly-csharp-dnspy-method-patch.md 存在。
  unverified:
  - CE 路线最终成功的具体改值与截图不完全对应：img19 展示改为 11，而合成截图 img20 的 Change Value 对话框显示 5.733219385(且为另一 PID/Found 57 的会话)，改 11 与看到 WELCOME_TO_UNITY 的因果关系原文未明确；卡片 PoC 按原文叙述写 11，核心方法不受影响，建议后续补充说明。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-cheat-engine-unknown-float-coordinate-scan/
draft: false
kb_aliases:
- CE 未知初始值扫描
- Unknown initial value
- 浮点坐标扫描
- 游戏坐标定位
- 冻结候选地址验证
- Unity 玩家坐标修改
- 穿墙/空气墙绕过
---

## 一句话结论

当不知道游戏坐标的初始数值时，可在 Cheat Engine 里用 `Scan Type = Unknown initial value`、`Value Type = Float` 做首次扫描，然后根据角色移动方向反复做 `Increased value` / `Decreased value` / `Unchanged value + Repeat` 的 Next Scan，把上亿个浮点数收敛到几十个候选；逐个冻结候选地址、回游戏看角色是否无法移动，即可锁定玩家坐标字段，解冻后改成一个更大的值就能越过空气墙/碰撞边界到达原本不可达的位置。

## 原理

- **未知初值扫描**：精确值扫描需要先知道目标数值；坐标这类浮点数在内存中初值未知、而且通常同时存在 X/Y/Z 多个分量。CE 的 `Unknown initial value` 先记录整个可写内存的快照（本例 2.15 亿个值），之后不再依赖“知道原值”，只依赖“值的变化方向”。
- **变化方向筛选**：角色向前走时，至少一个坐标分量增大（`Increased value`），向后走时减小（`Decreased value`）；角色静止时坐标不变（`Unchanged value` + `Repeat`）。每次 Next Scan 只保留符合方向/不变条件的地址，候选数量指数级下降（2.15 亿 → 136 万 → 90 万 → 6203 → 463 → 64）。
- **冻结验证**：剩下的候选里可能包含视角、动画时间、物理量等同样随移动变化的浮点数；CE 的“冻结”（Active 复选框）会把值持续写回原值。逐个或分批冻结候选，回游戏尝试移动：如果角色无法移动，该地址很可能就是坐标分量（或多个分量同时被冻结）。
- **改值穿墙**：坐标是普通浮点数，没有服务器校验时，直接把值改大/改小即可把角色传送到墙外；空气墙/碰撞体只限制正常移动路径，不限制坐标被直接改写后的位置。
- **为什么有效**：Unity/Mono 或 IL2CPP 游戏的玩家位置通常以 `float` 存在组件/Transform 结构里；CE 以同用户权限读写进程内存，不需要逆向全部游戏逻辑，只要能观察到“移动→数值变化”的相关性。
- **边界**：坐标可能被加密/混淆（如 `Vector3` 被拆成定点数）、由服务器权威校验、或存在反作弊/内存完整性检查；此时 Unknown 扫描可能找不到稳定候选，需要先定位读写指令或反混淆。

## 触发条件

- 目标为本地运行、无内核反作弊/服务器权威校验的 Unity/单机游戏；CE 可附加并读写进程内存。
- 玩家坐标以 `float`（或可被 Float 扫描命中的类型）存储，且移动会改变至少一个分量。
- 允许在窗口/无边框模式下切换游戏与 CE（或用 `Ctrl+Alt+Tab` 保持游戏后台运行）。
- 有可观察的“移动/静止”反馈用于判断候选是否正确（冻结后角色不能动）。

## 利用步骤

1. CE 附加游戏进程（Process List 选择 `pico.exe` 等，或按窗口标题/pid）。
2. 首次扫描：`Scan Type = Unknown initial value`、`Value Type = Float`，扫描范围默认 `All`/可写内存，点 `First Scan`（本例 Found: 215,168,000）。
3. 回游戏向前走几步，CE 选 `Scan Type = Increased value`，点 `Next Scan`；回游戏向后走，选 `Decreased value` 再扫；静止不动时选 `Unchanged value` 并勾 `Repeat` 再扫。交替重复，直到候选降到几十个。
4. 在结果列表中勾选候选的 `Active` 冻结，回游戏尝试移动；若角色无法移动，说明该地址是坐标分量（或与移动直接相关）。取消冻结后恢复。
5. 双击锁定地址的 Value，改成明显更大/更小的值（如 2.3 → 11），回游戏观察角色是否瞬移到墙外/目标平台。
6. 若一个分量不够，尝试同批候选中的其他地址（X/Y/Z），或结合“找出是什么改写了这个地址”定位坐标结构。

## PoC

CE 操作序列（无脚本，按 UI）：

```text
1) Process List -> 选择 game.exe
2) Scan Type: Unknown initial value | Value Type: Float -> First Scan
3) 角色前进 -> Scan Type: Increased value -> Next Scan
4) 角色后退 -> Scan Type: Decreased value -> Next Scan
5) 角色静止 -> Scan Type: Unchanged value + Repeat -> Next Scan
6) 重复 3-5，候选从 2 亿降到几十
7) 勾选候选 Active（冻结）-> 回游戏确认不能移动
8) 取消冻结 -> 双击 Value 改为 11（或更大）-> 回游戏穿墙
```

```text
# 示例（picoCTF Unity 游戏）：
# 首次扫描 Found: 215,168,000
# 前进/后退/静止交替筛选后 Found: 64
# 冻结 1B20D855BC (Float 2.301950693) 后角色不能移动 -> 锁定为坐标分量
# 改为 11 -> 角色越过空气墙，看到 WELCOME_TO_UNITY!!
```

## 变体与关联

- **已知初值/整数扫描**：如果知道金币/血量等初值，直接用 `Exact Value` + 改值再扫，收敛更快；见 [[code-analysis-reverse-windows-game-sun-pointer-scan-win32-write]]（整数阳光值 + 指针链）。
- **IL2CPP 触发型**：IL2CPP 游戏的字段也是内存值，可用精确值扫描改金币等触发条件，见 [[code-analysis-reverse-unity-il2cpp-ce-trigger-embedded-pe]]。
- **指针链**：坐标地址可能随场景/重分配变化；若要跨关卡稳定修改，需要继续找基址+偏移（“找出是什么访问了这个地址”/指针扫描），见 [[code-analysis-reverse-windows-game-control-pointer-chain]]。
- **变体**：`Value Type` 可换 4 Bytes/8 Bytes/Double；坐标可能以 `Vector3` 连续三个 float 存储，命中一个后可检查相邻地址；也可用“找出是什么改写了这个地址”直接定位移动函数。
- **边界**：服务器权威坐标、坐标加密/定点化、反作弊/内存完整性校验会让扫描失效；冻结错误地址可能导致游戏卡死，需分批验证。

## 检测与防御

- 这是本地单机游戏逆向/修改技术，不涉及远程攻击面。游戏厂商的对抗手段包括：服务器权威位置校验、坐标加密/压缩、内存完整性校验、反调试/反作弊驱动、检测 CE 进程与 `OpenProcess`/`WriteProcessMemory` 行为。
- 分析侧建议：先备份存档/进程状态；冻结候选时分批进行，避免一次冻结过多导致崩溃；改值幅度要小，避免坐标越界触发异常；记录命中地址与值以便复现。
- 检测信号（反作弊/游戏侧）：同一进程频繁 `ReadProcessMemory/WriteProcessMemory`、CE 窗口/驱动加载、坐标瞬移超出正常移动速度、角色位置与碰撞体不一致。
