# ESurfingClient 工具

这是 ESurfingClient 的控制台工具分支，只保留文本加解密、Algo-ID 查找和 Key/IV 导出功能。

## 功能

- **加解密文本**：输入 Algo-ID 后，对文本进行加密或解密。一次操作结束后会询问是否继续使用同一个 Algo-ID；选择 `y` 可直接继续加密/解密，不必重新输入 Algo-ID。24 个固定算法和 56 个硬编码动态算法直接使用；都不在表中时才提示选择 UA 和最大查找次数（默认 1000，输入 0 表示一直查找），然后循环请求 ticket 接口，匹配过程中逐次显示解析到的 Algo-ID，匹配到相同 Algo-ID 后用该响应的 ZSM 自动解析 iOS/Windows 动态算法，匹配过程中按 `Ctrl+C` 可停止并返回主菜单。
- **查找 Algo-ID / 导出 Key/IV**：选择 UA 后询问是否导出 Key/IV。
  - 不导出：只收集 Algo-ID，可以指定查找次数，也可以一直查找直到连续 1000 次没有新的 Algo-ID。
  - 导出：从 iOS/Windows 动态 ZSM 中解析 key/iv、平台和 `Type`（cdy），按 Algo-ID 去重后追加写入 txt 文件；一直查找不按次数停止，按 `Ctrl+C` 停止（达到预计算法个数时也会停）。
  - 固定算法没有可解析的 ZSM key/iv，导出时会跳过。
- **算法代码**：算法实现已按算法名称统一放在 `esurfingclient/esurfing/src/cipher/algo/`，不再用 android/linux 命名，也不再保留 legacy 目录；能复用的旧实现已合并到主实现，独立旧算法也移到该目录。硬编码 Algo-ID 的 `strcmp` 分支统一放在 `CipherFactory.c`，key/iv 数据统一放在 `KeyData.c/.h`。

每个硬编码 Algo-ID 在 `CipherFactory.c` 中都有一个 `strcmp` 分支，直接调用对应的共享算法实现；key/iv 从 `KeyData.c` 传入。当前包含 56 条从 `windows_key_iv.txt`、`ios_key_iv.txt`、`macos_key_iv.txt` 收集的记录，未命中的 ID 仍会回退到动态 ZSM 获取。

合并后的功能 2 会询问预计算法个数：填 `0` 表示未知、不参考此项；填正数时，收集到对应数量后提前停止。不导出时按唯一 Algo-ID 数量计算，导出时按导出文件中的总条数计算（包括文件里已有的记录）。

导出文件格式：

```text
# Index / Platform / Type / Algo-ID / Key / IV

Index: 1
Platform: Windows
Type: 2
Algo-ID: 578FDB96-AF47-461D-AC36-D08EADF10130
Key: 0123456789ABCDEF...
IV: 0123456789ABCDEF

Index: 2
Platform: iOS
Type: 5
Algo-ID: ...
Key: ...
IV: (none)
```

序号按文件中的不重复算法连续编号，追加时会接着已有条数继续。`Type` 是 ZSM 的 `cdy` 算法类型；没有 IV 的动态算法会写成 `IV: (none)`。

查找和动态匹配使用 `curl_multi` 并发请求，默认 24 路，单次请求 1 秒超时，超时直接丢弃；并发数可通过 `esurfingclient/esurfing/src/AlgoFinder.c` 顶部的 `TICKET_BATCH_SIZE` 调整。

查找接口地址、POST 请求体（`tarce log algo auto compstr null value`，38 字节）和固定请求头在 `esurfingclient/esurfing/src/AlgoFinder.c` 顶部，如果抓包得到的 ticket 请求发生变化，改这里的常量即可。

## 编译

```bash
cmake -S esurfingclient/esurfing -B build
cmake --build build
```

Windows 使用 MinGW + vcpkg 的静态 libcurl 构建，Linux 需要安装 libcurl 开发包。
