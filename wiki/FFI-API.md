# FFI API（C ABI，供 Flutter / 原生）

手写的 C ABI，无 `flutter_rust_bridge`、无代码生成。Flutter/Dart、Kotlin、Swift、C/C++ 直接按下面的符号绑定。

## 符号总表

```c
// 响应结构体（内存布局固定，repr(C)）
typedef struct {
    int32_t code;   // 0=成功，非 0=错误
    char*   data;   // 成功: JSON 字符串；失败: 错误消息。用完调 corduit_string_free
} FfiResponse;

typedef struct {
    int32_t  code;
    uint8_t* data;  // rustbinary 字节
    size_t   len;
} FfiBinaryResponse;

// 入口
FfiResponse         corduit_call(const char* method, const char* args_json);
FfiBinaryResponse   corduit_call_binary(const char* method, const uint8_t* payload, size_t len);
void                corduit_init(void);
char*               corduit_api_version(void);   // 用完 corduit_string_free
char*               corduit_methods(void);       // 方法名 JSON 数组，用完 corduit_string_free
void                corduit_string_free(char* ptr);
void                corduit_binary_free(FfiBinaryResponse resp);
```

## 调用约定

1. `args_json` 是**命名参数对象**，例如 `{"tag":"ss-jp","test_url":"http://example.com","timeout_ms":3000}`；不需要参数时传 `NULL`。
2. 返回的 `data` 是**调用方负责释放**的堆内存（`corduit_string_free` / `corduit_binary_free`）。
3. 线程安全：内部是同步引擎（work-stealing 池 + 专用线程），无 async runtime；`corduit_call*` 可从任意线程调用。
4. **不会跨边界 panic**：内部 panic 会被捕获并转为 `code!=0` 的错误响应。

## C 语言示例

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { int code; char* data; } FfiResponse;
extern FfiResponse corduit_call(const char*, const char*);
extern void corduit_string_free(char*);
extern char* corduit_methods(void);

int main(void) {
    corduit_init();

    // 1) 获取版本
    FfiResponse r = corduit_call("get_version", NULL);
    if (r.code == 0) {
        printf("version: %s\n", r.data);
    }
    corduit_string_free(r.data);

    // 2) 带参数调用
    const char* args = "{\"tag\":\"ss-jp\",\"timeout_ms\":3000}";
    FfiResponse r2 = corduit_call("test_outbound_latency", args);
    if (r2.code == 0) {
        printf("latency result: %s\n", r2.data);
    }
    corduit_string_free(r2.data);

    // 3) 动态发现方法
    char* methods = corduit_methods();
    printf("methods: %s\n", methods);
    corduit_string_free(methods);
    return 0;
}
```

## Dart / Flutter 示例

用 `dart:ffi` 直接绑定：

```dart
import 'dart:ffi';
import 'dart:convert';
import 'package:ffi/ffi.dart';

final class FfiResponse extends Struct {
  @Int32() external int code;
  external Pointer<Utf8> data;
}

typedef _Call = Pointer<FfiResponse> Function(Pointer<Utf8>, Pointer<Utf8>);

late final DynamicLibrary _lib = Platform.isAndroid
    ? DynamicLibrary.open('libcorduit.so')
    : DynamicLibrary.process();

final _call = _lib.lookupFunction<Pointer<FfiResponse> Function(Pointer<Utf8>, Pointer<Utf8>),
    Pointer<FfiResponse> Function(Pointer<Utf8>, Pointer<Utf8>)>('corduit_call');
final _free = _lib.lookupFunction<Void Function(Pointer<Utf8>), void Function(Pointer<Utf8>)>('corduit_string_free');

String? invoke(String method, [Map<String, Object?>? args]) {
  final m = method.toNativeUtf8();
  final a = (args == null) ? nullptr : jsonEncode(args).toNativeUtf8();
  final resp = _call(m, a);
  final code = resp.ref.code;
  final text = code == 0 ? resp.ref.data.toDartString() : null;
  calloc.free(resp);
  malloc.free(m);
  if (a != nullptr) malloc.free(a);
  return text;
}

void main() {
  final version = invoke('get_version');
  print(version);
}
```

> 注意：Dart FFI 里 `FfiResponse` 要按 C 布局定义；释放顺序是先 `corduit_string_free(data)` 再释放外层结构体。

## 二进制通道（rustbinary）

`corduit_call_binary` 的参数和结果都是 **rustbinary** 编码（比 JSON 更紧凑，有 64MiB 上限 + 集合上限，拒绝尾部字节）。参数编码方式：把同一个 `{"method":...,"params":...}` 对象用 `rustbinary::serialize` 编码后传入；响应解码用 `rustbinary::deserialize`。

Kotlin/Swift 若没有 rustbinary 绑定，直接用 JSON 版 `corduit_call` 即可——两边共享同一张分发表。

## 方法列表

完整方法、参数、返回见 [Methods-Reference](Methods-Reference)。用 `corduit_methods()` 在运行时拿到的才是权威列表。
