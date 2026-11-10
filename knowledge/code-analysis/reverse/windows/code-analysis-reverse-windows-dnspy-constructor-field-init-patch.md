---
id: code-analysis-reverse-windows-dnspy-constructor-field-init-patch
title: dnSpy 构造器字段初值补丁：MinesVisible 全置 true 让扫雷胜利条件初始成立
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: dnspy-constructor-field-init-patch
aliases:
- dnSpy 改字段初始值
- 构造器补丁
- 数据初值补丁
- MinesVisible
- 扫雷胜利条件绕过
- dnSpy 编辑类
tags:
- reverse
- dotnet
- csharp
- dnspy
- patch
- field-initializer
- game
- ctf
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:21:35+08:00'
  notes: 已对照原文全文与全部21图核对：MineField 构造函数数组初值、TotalUnrevealedEmptySquares getter、SquareRevealedCallback 胜利判定与 GetKey 排序取前三格均与图14/17/18/19一致；CS0266 出自 GetKey XOR 循环的 (byte) 强转，与图15/16一致。与既有 IL patch 卡为控制流 vs 数据初值两种补丁面，不重复。未在本机用 dnSpy 编译/运行修改版。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

当 C#（WinForms/Unity Mono）程序的胜利或授权判定是从可变的成员字段/数组“算出来”的时候，不必去找并删改判定分支：用 dnSpy 的“分析 → 被使用”沿判定依赖回溯到构造函数，直接把字段初值改成让判定成立的值（如扫雷把 `MinesVisible` 二维数组全部初始化为 `true`），编译保存后判定从一开始就满足，触发一次判定即可弹出成功窗并显示 flag。

## 原理

- .NET 程序集保留完整元数据与 IL，dnSpy 既能反编译成接近原始源码的 C#，也能在源码级编辑类/方法后重新编译并保存为新的 exe/dll，这等价于在客户端做源码补丁。
- 示例扫雷（FlareOn5 Ultimate Minesweeper）的胜利判定不是直接比较某个布尔值，而是通过计算属性取得：
  ```csharp
  // MainForm.SquareRevealedCallback 中
  if (this.MineField.TotalUnrevealedEmptySquares == 0)
  {
      new SuccessPopup(this.GetKey(this.RevealedCells)).ShowDialog();
      Application.Exit();
  }

  // MineField.TotalUnrevealedEmptySquares getter：统计“不是雷且不可见”的格子数
  if (!this.MinesPresent[num2, num3] && !this.MinesVisible[num2, num3])
      num++;
  ```
  即胜利条件 `TotalUnrevealedEmptySquares == 0` 完全由 `MinesPresent`/`MinesVisible` 两个布尔数组的当前内容决定。
- `MinesVisible` 在 `MineField` 构造函数里只分配、不赋值，默认 `false`；把初始化循环改成 `this.MinesVisible[i, j] = true;` 后，所有格子初始即为“可见”，`TotalUnrevealedEmptySquares` 从游戏一开始就恒为 0。
- 为什么这样能过：判定只依赖客户端内存状态，且该状态由可被 dnSpy 改写的构造器初始化；改“数据初值”与改“判定逻辑”等价，但补丁面更小，不需要读懂/改对判定表达式，也不受判定分支有多少个 `&&` 条件影响。
- 这种补丁与删失败分支不同：失败分支（踩雷 `BombRevealed` → FailurePopup）保持不变，只是让程序在正常的“揭示格子”回调里直接命中胜利条件；因此适用于“失败/胜利两条路都在同一个回调、删失败分支较麻烦、但状态初值可直接利用”的场景。
- dnSpy 重新编译反编译出的 C# 时可能丢失原 IL 的隐式转换信息，编译期报 `CS0266: Cannot implicitly convert type 'int' to 'byte'`（示例出现在 `GetKey` 的 XOR 循环 `array3[(int)num2] = (byte)(array3[(int)num2] ^ array[(int)num1]);`），按提示补显式 `(byte)` 强转即可编译通过。

## 触发条件

- 目标为 C#/.NET 客户端（WinForms、Unity Mono 的 `Assembly-CSharp.dll` 等），核心判定逻辑在托管代码中，dnSpy 可打开且可保存模块。
- 胜利/授权判定依赖可变的成员字段或由其计算出的属性，且字段在构造函数（或字段初始化器）中赋初值。
- 程序集没有强名称/签名/完整性校验阻止保存或运行修改版；判定不涉及服务端。
- 允许在本地运行修改后的程序（CTF、单机游戏、本地授权验证）。

## 利用步骤

1. 用 dnSpy 打开目标 exe/dll，展开命名空间，先找成功/失败提示类或可疑判定方法（示例：`SuccessPopup`、`FailurePopup`、`verifyPasswd`、`button1_Click`）。
2. 右键目标类 → “分析”（Analyzer）→ 展开“被使用”，定位它被实例化的判定点（示例：`MainForm.SquareRevealedCallback` 中的成功 `if`）。
3. 阅读判定表达式，找出它依赖的属性/字段（示例：`TotalUnrevealedEmptySquares`）；跟进属性 getter，确认关心的字段（示例：`MinesPresent`、`MinesVisible`）。
4. 对字段的 get/set 再取“被使用”，跳回 `MineField` 构造函数，确认数组的初始化位置（示例：`new bool[size, size]` 后循环赋值）。
5. 右键类 → “编辑类（C#）”，在初始化循环中把目标值改成让判定成立的值（示例：`this.MinesVisible[i, j] = true;`），或直接改字段初值。
6. 点击“编译”。若报 `CS0266` 等隐式转换错误，按提示在相应表达式加显式强转；编译通过后“文件 → 全部保存”生成修改版 exe/dll（保存前备份原文件）。
7. 运行修改版，触发一次判定流程（示例：点击任意格子让程序进入 `SquareRevealedCallback`），即可看到成功弹窗及 flag/奖品串。

## PoC

```csharp
// 修改前：MineField 构造函数只分配数组，默认全 false
public MineField(uint size)
{
    this.Size = size;
    this.MinesPresent = new bool[(int)size, (int)size];
    this.MinesVisible = new bool[(int)size, (int)size];
    this.MinesFlagged = new bool[(int)size, (int)size];
}

// 修改后：初始化时把所有格子标记为可见，TotalUnrevealedEmptySquares 恒为 0
public MineField(uint size)
{
    this.Size = size;
    this.MinesPresent = new bool[(int)size, (int)size];
    this.MinesVisible = new bool[(int)size, (int)size];
    this.MinesFlagged = new bool[(int)size, (int)size];
    for (int i = 0; i < (int)size; i++)
    {
        for (int j = 0; j < (int)size; j++)
        {
            this.MinesVisible[i, j] = true;
        }
    }
}
```

```csharp
// 胜利判定（未修改）：依赖上述数组计算出的属性
private void SquareRevealedCallback(uint column, uint row)
{
    this.RevealedCells.Add(row * MainForm.VALLOC_NODE_LIMIT + column);
    if (this.MineField.TotalUnrevealedEmptySquares == 0)
    {
        new SuccessPopup(this.GetKey(this.RevealedCells)).ShowDialog();
        Application.Exit();
    }
}
```

```text
dnSpy 操作路径：
SuccessPopup -> 分析 -> 被使用 -> MainForm.SquareRevealedCallback
  -> TotalUnrevealedEmptySquares getter
  -> MinesVisible get/set -> 被使用 -> MineField(uint) 构造函数
  -> 编辑类 -> 循环赋值 true -> 编译 -> 文件/全部保存 -> 运行点击格子
```

说明：`GetKey` 会 `revealedCells.Sort()` 后取前 3 个元素拼随机种子再生成 32 字节密钥流；若 `RevealedCells` 元素不足 3 个会索引越界。复现时若单击即异常，可先在棋盘上多点几个格子，或改用断点读取 `GetKey` 生成的明文。以上为按原文案例整理的结构化 PoC，未在本机执行 dnSpy 编译/运行。

## 变体与关联

- **初值变体**：授权布尔字段 `isValid/licensed/activated` 由 `false` 改 `true`；试用期计数 `trialDays` 改为大数或负数判断绕过；分数/金币初始值改大；状态枚举（`Expired`→`Valid`）。
- **派生属性变体**：不改变量而改属性 getter，让 `TotalUnrevealedEmptySquares`、`IsLicensed` 等直接 `return 0/true`，效果等价但影响面更大。
- **对照手法**：删失败分支、把胜利条件改成 `RevealedCells.Count >= 3`、把 `GetKey` 返回值改成固定串，见 [[code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass]]；静态定位流程见 [[code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis]]；dnSpy/de4dot 基础与校验逆推见 [[ctf-reverse-dotnet-dnspy-de4dot-arithmetic-inverse]]。
- **边界**：构造函数之后字段被重置、从配置文件/服务端下发或惰性初始化时，改构造器无效；强名称/签名/完整性校验会阻止保存或运行；IL2CPP 没有可编辑 IL；服务端判定无法用客户端补丁绕过。

## 检测与防御

- **防御视角**：胜负/授权等关键判定应放服务端，客户端只展示结果；客户端可加程序集签名/哈希校验、反调试、字段加密与混淆，提高补丁成本，但这些都不是安全边界。
- **检测信号**：程序集哈希/签名与原版不一致；dnSpy 保存后元数据/强名称缺失或时间戳变化；运行目录中出现修改版 exe/dll。
- **分析安全**：修改和运行修改版前备份原始文件，在隔离环境进行；样本视为不可信数据。
