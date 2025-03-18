# ARM64Emulator

基于 Unicorn 实现一个轻量级的 ARM64 模拟器，具备代码加载、内存映射、指令执行、反汇编、寄存器监控、Hook、Patch、字符串处理等功能，适合用于逆向分析或调试 ARM64 代码。

Implement a lightweight ARM64 emulator based on Unicorn, with features including code loading, memory mapping, instruction execution, disassembly, register monitoring, hooking, patching, and string manipulation. It is suitable for reverse engineering or debugging ARM64 code.

# 使用示例（Example）

```python
from unicorn.arm64_const import *
import struct
import re

from ARM64Emulator import ARM64Emulator


def modifiedCRC32(data):
    emulator = ARM64Emulator("libcrc32.so")

    mu = emulator.mu

    # 字符串地址
    str_addr = emulator.STACK_BASE + emulator.STACK_SIZE
    emulator.mu.mem_map(str_addr, 0x1000)  # 4KB

    # v49 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) + 40);
    emulator.patch_nop([0X1C05C, 0X1C068])

    # v33 = (*env)->GetStringUTFChars(env, input, 0LL);
    def get_string_utf_chars():
        emulator.get_string_utf_chars(data, str_addr)

    emulator.patch_nop_range(0X1C160, 0X1C174)
    emulator.register_hook(0X1C174, get_string_utf_chars)

    # v34 = strlen(v33);
    def strlen():
        emulator.set_x0(len(data))
    emulator.patch_nop([0x1c17c])
    emulator.register_hook(0x1c17c, strlen)

    # memmove(v36, v33, v35);
    def memmove():
        dest = mu.reg_read(UC_ARM64_REG_X0)
        src = mu.reg_read(UC_ARM64_REG_X1)
        n = mu.reg_read(UC_ARM64_REG_X2)

        if n == 0:
            return  # 不需要拷贝

        print(f"memmove Hooked: Copying {n} bytes from {hex(src)} to {hex(dest)}")

        # 读取 src 地址的数据，确保是 bytes
        data = bytes(mu.mem_read(src, n))

        # 如果 src 和 dest 有重叠，`memmove` 需要支持前后移动
        if src < dest < src + n:
            # `memmove` 需要从后往前复制以避免覆盖
            for i in range(n - 1, -1, -1):
                mu.mem_write(dest + i, data[i:i + 1])
        else:
            # 正常拷贝
            mu.mem_write(dest, data)

        # `memmove` 的返回值是 `dest`
        mu.reg_write(UC_ARM64_REG_X0, dest)

    emulator.patch_nop([0x1C1E0])
    emulator.register_hook(0x1C1E0, memmove)

    # (*env)->ReleaseStringUTFChars(env, input, v33);
    emulator.patch_nop([0x1C1FC, 0x1c1ec])

    # vsnprintf(a1, 9u, "%08x", arg)
    def vsnprintf():
        X0 = mu.reg_read(UC_ARM64_REG_X0)  # char *str
        X1 = mu.reg_read(UC_ARM64_REG_X1)  # size_t size
        X2 = mu.reg_read(UC_ARM64_REG_X2)  # const char *format
        X3 = mu.reg_read(UC_ARM64_REG_X3)  # va_list ap

        # 读取 format 字符串
        fmt_bytes = mu.mem_read(X2, 100)  # 读取格式字符串（假设最长 100 字节）
        fmt_str = fmt_bytes.split(b'\x00')[0].decode('utf-8')

        print(f"vsnprintf Hooked: format = '{fmt_str}', buffer = {hex(X0)}, size = {X1}, va_list = {hex(X3)}")

        # 解析 va_list 参数
        args = []
        ap = X3
        format_specifiers = re.findall(r"%[#0-9]*[dxslu]", fmt_str)  # 解析格式

        for spec in format_specifiers:
            if spec[-1] in 'di':  # 解析 %d, %i (整数)
                val = struct.unpack("<i", mu.mem_read(ap, 4))[0]
                args.append(val)  # 确保是整数
                ap += 8
            elif spec[-1] in 'xX':  # 解析 %x, %X (十六进制)
                val = struct.unpack("<I", mu.mem_read(ap, 4))[0]
                args.append(int(val))  # **关键修正：存储整数**
                ap += 8
            elif spec[-1] in 'lu':  # 解析 %lu (long unsigned)
                val = struct.unpack("<Q", mu.mem_read(ap, 8))[0]
                args.append(int(val))  # 确保是整数
                ap += 8
            elif spec[-1] in 's':  # 解析 %s (字符串)
                ptr = struct.unpack("<Q", mu.mem_read(ap, 8))[0]
                str_bytes = mu.mem_read(ptr, 100).split(b'\x00')[0]  # 读取字符串
                args.append(str_bytes.decode('utf-8'))
                ap += 8
            elif spec[-1] in 'c':  # 解析 %c (字符)
                val = struct.unpack("<B", mu.mem_read(ap, 1))[0]
                args.append(chr(val))
                ap += 8

        # 使用 Python 进行格式化
        try:
            formatted_str = fmt_str % tuple(args)
        except TypeError as e:
            print(f"Format error: {e}, fmt_str: '{fmt_str}', args: {args}")
            return

        print(f"vsnprintf result: '{formatted_str}'")

        # 写入目标缓冲区
        output_bytes = formatted_str.encode('utf-8')[:X1 - 1]  # 不能超过 size
        mu.mem_write(X0, output_bytes + b'\x00')

        # 返回字符串长度
        mu.reg_write(UC_ARM64_REG_X0, len(output_bytes))

    emulator.patch_nop([0x1C3A4])
    emulator.register_hook(0x1C3A4, vsnprintf)

    # result = (*env)->NewStringUTF(env, v48);
    def new_string_utf():
        # 获取 X1 = UTF-8 字符串地址
        utf8_addr = mu.reg_read(UC_ARM64_REG_X1)

        # 读取字符串内容
        utf8_string = emulator.read_c_string(utf8_addr)
        print(f"NewStringUTF Hooked: Creating Java String for '{utf8_string}'")

        # 返回字符串地址
        mu.reg_write(UC_ARM64_REG_X0, utf8_addr)

    emulator.patch_nop([0x1c288, 0x1c294])
    emulator.register_hook(0x1c294, new_string_utf)

    # __stack_chk_fail
    emulator.patch_nop([0x1C2E8, 0x1C320, 0x1C2BC])

    # 初始化传参
    emulator.set_x0(0) # JNIEnv*
    emulator.set_x1(0) # jobject
    emulator.set_x2(str_addr) # input

    # 监控寄存器X4的变化
    emulator.watch_registers("X4")

    # 运行
    emulator.run(0x1C040, 0x1C2D8)

    return hex(mu.reg_read(UC_ARM64_REG_X4))

if __name__ == "__main__":
    result = modifiedCRC32("546NBypEyvgBt")
    print(f"modifiedCRC32 result: '{result}'")

```
