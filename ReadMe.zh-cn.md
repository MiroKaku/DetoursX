# [DetoursX](https://github.com/mirokaku/DetoursX)

[![LICENSE](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/MiroKaku/DetoursX/blob/master/LICENSE)
![Windows](https://img.shields.io/badge/Windows-10+-orange.svg)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-2019-purple.svg)

## 1. 关于

DetoursX 是基于微软 [Detours 4.0.1](https://github.com/microsoft/Detours/tree/4.0.1) 修改的内核扩展版本。可以使用 DetoursX 在内核中安全的 Hook 函数。
（注：DetoursX 并不负责绕过 PatchGuard）

### 1.1 原理

* X64 模式下，在目标函数所在的区段尾部，寻找空白区存储跳板地址，用来支持远跳转。
* 在 `DetourTransactionCommitEx` 中，通过 `KeGenericCallDpc` 进行处理器同步处理 `CopyMemory`，来达到安全 Hook 的目的。

### 1.2 支持情况

- [x] DetourTransactionBegin
- [x] DetourTransactionAbort
- [x] DetourTransactionCommit
- [x] DetourTransactionCommitEx
- [x] DetourUpdateThread
- [x] DetourAttach
- [x] DetourAttachEx
- [x] DetourDetach
- [x] DetourDetachEx
- [x] DetourCodeFromPointer
- [x] DetourCopyInstruction
- [x] DetourUpdateProcessWithDll
- [x] DetourUpdateProcessWithDllEx
- [x] DetourCopyPayloadToProcess

## 文档

[Microsoft Detours Wiki](https://github.com/microsoft/Detours/wiki)

## 许可证

微软公司©版权所有，保留所有权利。

根据 [MIT](https://github.com/microsoft/Detours/blob/master/LICENSE.md) 许可证获得许可。
