---
id: code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass
title: dnSpy 编辑 IL 绕过 Unity Mono 游戏校验：删地雷检测 + 改胜利条件
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: unity-mono-dnspy-il-patch-bypass
tags:
- reverse
- unity
- mono
- dnspy
- il-patch
- game
- csharp
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V165
  verified_at: '2026-11-06T10:02:53+08:00'
  notes: 已对照 content.md 与图 15 核对：SquareRevealedCallback 删除踩雷失败分支、把 TotalUnrevealedEmptySquares==0 改为 RevealedCells.Count>=3、GetKey 用排序后前三个格子拼 seed 均一致；Add 在判断前执行，点 3 格可满足。未在本机用 dnSpy 编译保存/运行修改版。frontmatter 无 sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-unity-mono-dnspy-il-patch-bypass/
draft: false
kb_aliases:
- dnSpy 编辑方法
- Unity 游戏 patch
- 删地雷检测
- 改胜利条件
- IL 修改绕过
---

## 一句话结论

Unity Mono 游戏的胜负校验通常写在 C# 的 `SquareRevealedCallback` 等回调里；用 dnSpy 编辑 IL/方法体，删掉“踩雷就退出”的分支、把“所有空格都揭示”改成“已揭示格子数 >= 3”，保存为新 exe 后随意点 3 个格子即可触发 `GetKey` 拿到 flag。

## 原理

- Mono 游戏的核心逻辑是 IL，dnSpy 不仅能反编译，还能编辑方法体、编译回程序集并保存为新的 exe/dll；这等价于在源码级修改游戏逻辑。
- 示例扫雷的 `SquareRevealedCallback` 有两段判断：
  1. `if (MineField.BombRevealed) { ... new FailurePopup().ShowDialog(); Application.Exit(); }`：踩雷直接失败退出；
  2. `if (MineField.TotalUnrevealedEmptySquares == 0) { ... new SuccessPopup(GetKey(RevealedCells)).ShowDialog(); Application.Exit(); }`：揭示所有空格后调用 `GetKey` 生成 flag。
- 删除第一段后，踩雷不再退出；把第二段条件改成 `RevealedCells.Count >= 3` 后，只要点过 3 个格子就会调用 `GetKey`。
- 为什么是 3：`GetKey` 用 `revealedCells.Sort()` 后的前三个元素拼种子 `random = new Random(revealedCells[0] << 20 | revealedCells[1] << 10 | revealedCells[2])`；少于 3 个会越界/异常，3 个正好足够生成 32 字节随机流并与固定密文异或。
- 修改后 `GetKey` 仍按“前三个格子位置”生成种子，所以点击哪 3 个格子会决定 seed，进而决定 `Random.NextBytes` 的输出；如果只想拿 flag，直接让程序跑原逻辑/在断点里看 `array2` 更稳。
- 该手法依赖 dnSpy 能编译回程序集；如果程序集有强名称、IL 完整性校验、反调试或 IL2CPP，需要先去掉保护或改用动态调试。

## 触发条件

- 目标为 Unity Mono/C# 程序，关键胜负/校验逻辑在客户端程序集内，且可用 dnSpy 编辑方法。
- 程序没有强名称/签名校验阻止保存，或校验可被 patch/NOP。
- 胜利条件只依赖客户端状态（如已揭示格子数、分数），服务端不参与判定。
- 允许运行修改后的程序（CTF/本地游戏）。

## 利用步骤

1. 用 dnSpy 打开 `Assembly-CSharp.dll` 或目标 exe，定位胜负回调（示例 `MainForm.SquareRevealedCallback`）。
2. 右键方法 → “编辑方法”（Edit Method），在 C# 视图里删除踩雷失败分支：
   ```csharp
   // 删除：
   if (this.MineField.BombRevealed) { ... FailurePopup ... Application.Exit(); }
   ```
3. 把胜利条件从“所有空格揭示”改为“已揭示至少 3 个格子”：
   ```csharp
   if (this.RevealedCells.Count >= 3) { ... SuccessPopup(this.GetKey(this.RevealedCells)) ... }
   ```
4. 点击 dnSpy 的“编译”（Compile），确认无语法错误；再“文件 → 全部保存”（Save Module）生成新的 exe/dll。
5. 运行修改后的程序，随意点击 3 个格子（不管是否地雷），成功弹窗会显示 `GetKey` 生成的 flag。
6. 若不想改文件，可在 `GetKey` 的 `return Encoding.ASCII.GetString(array2);` 行下断点，调试运行并通关/触发后，在局部变量或监视窗口查看 `Encoding.ASCII.GetString(array2)`。

## PoC

```csharp
// 修改前
private void SquareRevealedCallback(uint column, uint row)
{
    if (this.MineField.BombRevealed)
    {
        this.stopwatch.Stop();
        Application.DoEvents();
        Thread.Sleep(1000);
        new FailurePopup().ShowDialog();
        Application.Exit();
    }

    this.RevealedCells.Add(row * MainForm.VALLOC_NODE_LIMIT + column);

    if (this.MineField.TotalUnrevealedEmptySquares == 0)
    {
        this.stopwatch.Stop();
        Application.DoEvents();
        Thread.Sleep(1000);
        new SuccessPopup(this.GetKey(this.RevealedCells)).ShowDialog();
        Application.Exit();
    }
}
```

```csharp
// 修改后：删掉踩雷分支，条件改为至少 3 个格子
private void SquareRevealedCallback(uint column, uint row)
{
    this.RevealedCells.Add(row * MainForm.VALLOC_NODE_LIMIT + column);

    if (this.RevealedCells.Count >= 3)
    {
        this.stopwatch.Stop();
        Application.DoEvents();
        Thread.Sleep(1000);
        new SuccessPopup(this.GetKey(this.RevealedCells)).ShowDialog();
        Application.Exit();
    }
}
```

```text
dnSpy 操作：
1. 右键 SquareRevealedCallback -> 编辑方法
2. 删除第一个 if 块，修改第二个 if 条件
3. 编译 -> 文件 -> 全部保存
4. 运行新 exe，点击任意 3 个格子
```

## 变体与关联

- 变体：直接修改 `GetKey` 返回固定字符串/已知明文，或把 `GetKey` 的固定密文数组替换为已知值。
- 变体：修改 `OnClick`/`Start` 里的校验分支，跳过密码/序列号比较；或把 `if (flag)` 改成恒真。
- 变体：用 dnSpy 调试断点代替 patch，在 `GetKey` 返回前读取 `array2`；不需要修改文件。
- 关联卡片：[[code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis]]（静态定位）、[[code-analysis-reverse-windows-unity-mono-cheat-engine-dissect]]（CE Mono 动态分析）、[[code-analysis-reverse-windows-unity-mono-assembly-csharp-dnspy-analysis]] 中的 `GetKey` 随机种子分析。
- 边界：强名称/签名/完整性校验会阻止保存或运行；IL2CPP 没有可编辑的 IL；服务端校验无法用客户端 patch 绕过。

## 检测与防御

- 检测（游戏保护）：校验程序集哈希/签名、检测 dnSpy/调试器、对关键方法做控制流混淆/字符串加密、把胜负判定放到服务端。
- 加固：使用 IL2CPP、代码签名、完整性校验与反调试；重要奖励/flag 由服务端签发，客户端只显示。
- 分析安全：修改前备份原始程序集；只在本机/隔离环境运行修改后的游戏。
