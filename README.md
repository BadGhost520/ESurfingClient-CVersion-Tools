# ESurfingClient 工具

这是 ESurfingClient 的控制台工具分支，只保留文本加解密、Algo-ID 查找和 Key/IV 导出功能。

## 功能

- **加解密文本**：输入 Algo-ID 后，对文本进行加密或解密。固定算法表中的 24 个 Algo-ID 直接使用；不在表中的 ID 会提示选择 UA 和最大查找次数（默认 1000，输入 0 表示一直查找），然后循环请求 ticket 接口，匹配过程中逐次显示解析到的 Algo-ID，匹配到相同 Algo-ID 后用该响应的 ZSM 自动解析 iOS/Windows 动态算法，匹配过程中按 `Ctrl+C` 可停止并返回主菜单。
- **查找 Algo-ID**：选择 UA 后循环请求 ticket 接口，可以指定查找次数，也可以一直查找，直到连续 1000 次没有新的 Algo-ID 为止。查找流程中输入 `0` 可返回主菜单，查找过程中按 `Ctrl+C` 会停止查找并返回主菜单。
- **获取 Key/IV**：选择 UA 和查找方式后，循环请求 ticket 接口，从 iOS/Windows 动态 ZSM 中解析 key/iv，按 Algo-ID 去重后追加写入 txt 文件。固定算法没有可解析的 ZSM key/iv，会被跳过。默认文件名为 `key_iv.txt`，如果文件已存在会先读取其中的 Algo-ID，重复项跳过。功能 3 的“一直查找”不会按 1000 次无新增停止，而是一直查，按 `Ctrl+C` 停止（达到预计算法个数时也会停）。
- **算法代码**：已迁移 Android 新/旧、Linux 共 24 个固定 Algo-ID 的算法，以及 iOS/Windows 动态 ZSM 解包实现。

功能 2 和功能 3 会额外询问预计算法个数：填 `0` 表示未知、不参考此项；填正数时，收集到对应数量后提前停止。功能 3 的这个数量按导出文件中的总条数计算（包括文件里已有的记录）。

导出文件格式：

```text
# Index / Algo-ID / Key / IV

Index: 1
Algo-ID: 578FDB96-AF47-461D-AC36-D08EADF10130
Key: 0123456789ABCDEF...
IV: 0123456789ABCDEF

Index: 2
Algo-ID: ...
Key: ...
IV: (none)
```

序号按文件中的不重复算法连续编号，追加时会接着已有条数继续。没有 IV 的动态算法会写成 `IV: (none)`。

查找和动态匹配使用 `curl_multi` 并发请求，默认 24 路，单次请求 1 秒超时，超时直接丢弃；并发数可通过 `esurfingclient/esurfing/src/AlgoFinder.c` 顶部的 `TICKET_BATCH_SIZE` 调整。

查找接口地址和固定请求头在 `esurfingclient/esurfing/src/AlgoFinder.c` 顶部，如果抓包得到的 ticket 请求发生变化，改这里的常量即可。

## 编译

```bash
cmake -S esurfingclient/esurfing -B build
cmake --build build
```

Windows 使用 MinGW + vcpkg 的静态 libcurl 构建，Linux 需要安装 libcurl 开发包。
