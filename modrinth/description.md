**這個模組不做「偵測攻擊」，它直接讓攻擊沒有機會發生。**

Minecraft 允許伺服器發資源包給玩家，裡面可以放 `.ttf` 字型。有人證明：只要在字型裡藏對的
bytecode，玩家畫到那個字的瞬間就可能被執行任意程式（公開 PoC：`bikini/minecraft2shell`，
Windows + Minecraft 26.3）。問題出在遊戲內建的繪字引擎 FreeType 2.14.3，**Mojang 到目前
（26.3 / 26.4 快照）都還沒換版本**。

FontGuard 的做法是：**所有字型載入時都不執行 hinting**。攻擊的那一步就是「執行字型自帶的
程式碼」，關掉它，字型裡的程式就沒有機會跑。因為完全不需要認出攻擊長相，**還沒公開的變種
也一樣擋得住**。

### 代價（請先看過再裝）

少了 hinting，字會稍微變柔，**小字最明顯**：

- 9px（介面文字大小）：邊緣變柔、不再對齊像素格
- 16px：看得出來
- 32px：幾乎分不出來
- 中文因為筆畫密，比英文更不明顯

量化：DejaVu Sans 32px 前 300 字元，72% 點陣圖有變化、平均高度差 0.88px、最差 2px。

![hinting comparison](https://raw.githubusercontent.com/sunrisemc-tw/minecraft2shell-fix/main/docs/images/hinting-comparison.png)

如果你覺得小字糊到受不了，可以在 JVM 參數加 `-Dm2sfix.policy=detect`：只有可能執行到
出問題那條指令（SHZ）的字型才關 hinting，其他保持原樣（約 11% 的一般字型也會被降級）。

### 什麼時候會跳警告

只有**高信心**命中（`IDEF` 改寫位移類指令、或在字形程式裡定義指令）才會跳視窗：

> 檢測到伺服器的資源包疑似包含惡意內容（minecraft2shell），已經攔截。
> [我了解，繼續遊玩] [中斷連線]

一般字型只是安靜降級，不會打擾你。同一場遊戲只跳一次。

### 支援版本

| Minecraft | 內建 FreeType | 本模組 |
| --- | --- | --- |
| 26.3 / 26.4 快照 | 2.14.3 | ✅ |
| 26.1 – 26.2 | 2.14.1 | ✅ |
| 1.20.5 – 1.21.10 | 2.13.2 | ✅ |
| 1.20.4 及更早 | 沒用 FreeType | ⛔ 不適用 |

（以上是用 Mojang 版本清單＋實際原生函式庫驗證的版本號，不是猜的。）

### 免責聲明

此工具僅為臨時解方，不是 Mojang 官方修復。此工具可能存在誤判和漏判的可能，且不保證可以
攔截所有攻擊及異常警告是正確的。此工具不負任何誤判和漏判的直接／間接經濟損失和相應責任，
所有責任由使用者自行承擔。若您不同意，請**不要安裝，直接拒絕所有伺服器的資源包發送請求！**

---

## English

**This mod does not detect the attack — it removes the step the attack needs.**

A Minecraft server can send a resource pack containing a `.ttf` font. Someone proved that a crafted
font can turn glyph hinting into arbitrary code execution (public PoC: `bikini/minecraft2shell`,
Windows + Minecraft 26.3). The flaw is in the bundled FreeType 2.14.3, and Mojang has not shipped a
newer one yet (not in 26.3, not in the 26.4 snapshots).

FontGuard loads **every** font with hinting disabled. That step is exactly what runs the font's own
bytecode, so disabling it means the font's program never runs — no signature has to match, which
means unpublished variants are covered too.

**The cost:** text loses hinting and looks slightly softer, most visibly at small sizes (9 px HUD
text). Measured on DejaVu Sans at 32 px: 72% of glyph bitmaps change, mean height difference 0.88 px.
Use `-Dm2sfix.policy=detect` if you prefer sharpness and accept signature-only coverage.

**Warning dialog** appears only for high-confidence hits; ordinary fonts are just quietly degraded.

**Disclaimer.** This is a temporary workaround, not an official Mojang fix. It may produce false
positives and false negatives and makes no guarantee. The author accepts no liability; all
responsibility rests with the user. If you do not agree, do not install it.
