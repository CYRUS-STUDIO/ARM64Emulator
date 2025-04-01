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



# **初始化与内存管理**

- 代码加载：通过 _load_binary() 将 so 文件加载到内存中。

- 内存映射：在 _setup_memory() 中分配 10MB 的代码区和 1MB 的栈区。

- 寄存器初始化：在 _setup_registers() 中设置栈指针（SP）和程序计数器（PC）。

- 寄存器设置：提供了 set_x0()、set_x1() 和 set_x2() 等方法，用于直接设置寄存器值。

```
import capstone
from unicorn import *
from unicorn.arm64_const import *


class ARM64Emulator:

    def __init__(self, so_file: str):
        self.so_file = so_file

        # 分配代码区（TEXT 段）
        self.CODE_BASE = 0x000000  # 假设代码段起始地址
        self.CODE_SIZE = 1024 * 1024 * 10  # 10MB

        # 分配栈区（STACK 段）
        self.STACK_BASE = self.CODE_BASE + self.CODE_SIZE
        self.STACK_SIZE = 1024 * 1024 * 1  # 1MB

        # 初始化 Unicorn
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        self._load_binary()
        self._setup_memory()
        self._setup_registers()
        self._setup_hooks()

    def _load_binary(self):
        with open(self.so_file, "rb") as f:
            self.CODE = f.read()

    def _setup_memory(self):
        self.mu.mem_map(self.CODE_BASE, self.CODE_SIZE)
        self.mu.mem_map(self.STACK_BASE, self.STACK_SIZE)
        # 写入指令
        self.mu.mem_write(self.CODE_BASE, self.CODE)

    def _setup_registers(self):
        self.mu.reg_write(UC_ARM64_REG_SP, self.STACK_BASE + self.STACK_SIZE - 4)  # 使 SP 从栈的顶部往下移动 4 字节，以 预留一点空间，避免越界错误。
        self.mu.reg_write(UC_ARM64_REG_PC, self.CODE_BASE)

    def set_x0(self, value):
        self.mu.reg_write(UC_ARM64_REG_X0, value)

    def set_x1(self, value):
        self.mu.reg_write(UC_ARM64_REG_X1, value)


    def set_x2(self, value):
        self.mu.reg_write(UC_ARM64_REG_X2, value)
```


# **打印寄存器**



dump_registers() 打印所有 ARM64 寄存器的当前值。

```
def dump_registers(self):
    """ 打印 Unicorn ARM64 CPU 的所有寄存器 """
    print("\n====== Registers Dump ======")

    # 遍历 X0 - X30
    for i in range(31):  # X0 ~ X30
        reg_id = getattr(arm64_const, f'UC_ARM64_REG_X{i}')
        value = self.mu.reg_read(reg_id)
        print(f"X{i:02}: 0x{value:016x}")

    # 打印 SP（栈指针）和 PC（程序计数器）
    sp = self.mu.reg_read(UC_ARM64_REG_SP)
    pc = self.mu.reg_read(UC_ARM64_REG_PC)

    print(f"\nSP:  0x{sp:016x}")
    print(f"PC:  0x{pc:016x}")
    print("============================\n")
```


# **运行程序**



run() 使用 emu_start() 运行从 start_address 到 end_address 的指令。

```
def run(self, start_address, end_address):
    print("\nBefore execution:")
    self.dump_registers()
    # 运行 Unicorn
    self.mu.emu_start(self.CODE_BASE + start_address, self.CODE_BASE + end_address)
    print("\nAfter execution:")
    self.dump_registers()
```


# **反汇编**



disassembly() 使用 Capstone 对指定地址的内存数据进行反汇编。

```
class ARM64Emulator:

    def __init__(self, so_file: str):
        
        # 初始化 Capstone 反汇编器 (针对 ARM64 架构)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    def disassembly(self, start_address, end_address):
        """
        反汇编指定地址的字节码
        :param start_address: 开始地址
        :param end_address: 结束地址
        """
        # 提取目标方法的字节码
        target_data = self.CODE[start_address:end_address]
        # 反汇编字节码
        print("Disassembly:")
        for instruction in self.cs.disasm(target_data, start_address):
            print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
            
```


# **Hook 管理**

- 代码 Hook：在 _setup_hooks() 中设置 UC_HOOK_CODE 钩子，每次执行到一条指令时触发 hook_code()。

- 注册 Hook：register_hook() 允许用户在特定地址注册自定义的 Hook 函数。

- 取消 Hook：unregister_hook() 提供取消 Hook 的功能。



```
class ARM64Emulator:

    def __init__(self, so_file: str):
        
        self._hooks = [] # 存储所有注册的 Hook
        
        self._setup_hooks()
        
    def _setup_hooks(self):
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        
    def hook_code(self, mu, address, size, user_data):
        code = mu.mem_read(address, size)
        # 反汇编并打印当前执行的指令
        for i in self.cs.disasm(code, 0, len(code)):
            print("[addr:%x;code:%s]:%s %s" % (address, code.hex(), i.mnemonic, i.op_str))
    
        # 遍历所有已注册的 Hook，并执行匹配的 Hook
        for hook_addr, hook_fn in self._hooks:
            if address == hook_addr:
                hook_fn()
                
    def register_hook(self, address: int, hook_fn):
        """
        注册 Hook
        :param address: 需要 Hook 的地址
        :param hook_fn: Hook 处理函数
        """
        self._hooks.append((address, hook_fn))
        print(f"Hook registered at {hex(address)}")
    
    def unregister_hook(self, address: int):
        """
        取消 Hook
        :param address: 需要解除 Hook 的地址
        """
        self._hooks = [(addr, fn) for addr, fn in self._hooks if addr != address]
        print(f"Hook unregistered at {hex(address)}")
```


# **寄存器监控**

- 监控寄存器变更：watch_registers() 支持监控特定寄存器的变化，并在变化时打印相关信息。

- 自动更新寄存器值：在 hook_code() 中检测变化，并输出变化信息。



```
class ARM64Emulator:

    def __init__(self, so_file: str):

        self._last_registers = {}  # 记录上次的寄存器值
        self._watch_registers = set()  # 存储需要监控的寄存器
    
    def hook_code(self, mu, address, size, user_data):
        code = mu.mem_read(address, size)
    
        insn = next(self.cs.disasm(code, 0, len(code)), None)
        if not insn:
            return
    
        # 检查监控的寄存器是否变化
        for reg in self._watch_registers:
            new_value = mu.reg_read(reg)
            if self._last_registers[reg] != new_value:
                print(f">> PC: 0x{address:X}, {insn.mnemonic} {insn.op_str}, {reg} changed: 0x{self._last_registers[reg]:X} -> 0x{new_value:X}")
                self._last_registers[reg] = new_value  # 更新值
    
    def watch_registers(self, *regs):
        """
        添加要监控的寄存器
    
        使用示例: emu.watch_registers("X4", "X8")  # 监控 X4 和 X8
    
        """
        reg_map = {
            "X0": UC_ARM64_REG_X0, "X1": UC_ARM64_REG_X1, "X2": UC_ARM64_REG_X2, "X3": UC_ARM64_REG_X3,
            "X4": UC_ARM64_REG_X4, "X5": UC_ARM64_REG_X5, "X6": UC_ARM64_REG_X6, "X7": UC_ARM64_REG_X7,
            "X8": UC_ARM64_REG_X8, "X9": UC_ARM64_REG_X9, "X10": UC_ARM64_REG_X10, "X11": UC_ARM64_REG_X11,
            "X12": UC_ARM64_REG_X12, "X13": UC_ARM64_REG_X13, "X14": UC_ARM64_REG_X14, "X15": UC_ARM64_REG_X15,
            "X16": UC_ARM64_REG_X16, "X17": UC_ARM64_REG_X17, "X18": UC_ARM64_REG_X18, "X19": UC_ARM64_REG_X19,
            "X20": UC_ARM64_REG_X20, "X21": UC_ARM64_REG_X21, "X22": UC_ARM64_REG_X22, "X23": UC_ARM64_REG_X23,
            "X24": UC_ARM64_REG_X24, "X25": UC_ARM64_REG_X25, "X26": UC_ARM64_REG_X26, "X27": UC_ARM64_REG_X27,
            "X28": UC_ARM64_REG_X28, "FP": UC_ARM64_REG_FP, "LR": UC_ARM64_REG_LR, "SP": UC_ARM64_REG_SP,
            "PC": UC_ARM64_REG_PC
        }
        for reg in regs:
            if reg in reg_map:
                self._watch_registers.add(reg_map[reg])
                self._last_registers[reg_map[reg]] = 0  # 初始化记录值
```


# **Patch NOP**

- patch_nop()：将给定地址列表中的指令替换为 NOP（0xD503201F）。

- patch_nop_range()：将指定地址范围内的所有指令替换为 NOP。



```
def patch_nop_range(self, start_addr: int, end_addr: int):
    """
    在指定范围内将指令 patch 为 NOP (0xD503201F)，**包括 end_addr 位置**

    :param start_addr: 需要 patch 的起始地址 (必须 4 字节对齐)
    :param end_addr: 需要 patch 的结束地址 (必须 4 字节对齐，包含此地址)
    """
    # 确保地址对齐
    if start_addr % 4 != 0 or end_addr % 4 != 0:
        raise ValueError("Start and end addresses must be 4-byte aligned.")

    if end_addr < start_addr:
        raise ValueError("End address must be greater than or equal to start address.")

    # NOP 指令在 AArch64 下的编码
    NOP_INSTRUCTION = b'\x1F\x20\x03\xD5'  # 0xD503201F

    # 计算 patch 的指令数量 (包括 end_addr)
    nop_count = ((end_addr - start_addr) // 4) + 1

    # 生成 NOP 指令序列
    nop_data = NOP_INSTRUCTION * nop_count

    # 写入 Unicorn 内存
    self.mu.mem_write(start_addr, nop_data)

    print(f"Patched {nop_count} instructions to NOP from {hex(start_addr)} to {hex(end_addr)} (inclusive)")

def patch_nop(self, addr_list: list):
    """
    将地址列表中的每个地址 patch 为 NOP (0xD503201F)

    :param addr_list: 需要 patch 的地址列表 (每个地址必须 4 字节对齐)
    """
    # NOP 指令在 AArch64 下的编码
    NOP_INSTRUCTION = b'\x1F\x20\x03\xD5'  # 0xD503201F

    for addr in addr_list:
        if addr % 4 != 0:
            raise ValueError(f"Address {hex(addr)} is not 4-byte aligned.")

        self.mu.mem_write(addr, NOP_INSTRUCTION)
        print(f"Patched NOP at {hex(addr)}")
```


# **字符串操作**

- get_string_utf_chars() 模拟了 GetStringUTFChars()，在指定内存地址写入 UTF-8 编码的字符串，并返回指针地址。

- read_c_string() 从仿真器内存中读取以 NULL 结尾的 C 语言字符串。

```
def get_string_utf_chars(self, input_str: str, str_addr: int):
    """
    模拟 GetStringUTFChars，把 Python 参数 `input_str` 作为返回的 UTF-8 字符串
    """
    utf8_str = input_str.encode("utf-8") + b"\x00"  # UTF-8 编码并加 NULL 终止符

    # 写入 Unicorn 内存
    self.mu.mem_write(str_addr, utf8_str)

    # 设置 X0 返回值 (UTF-8 字符串地址)
    self.mu.reg_write(UC_ARM64_REG_X0, str_addr)

    print(f"GetStringUTFChars Hooked: '{input_str}' -> {hex(str_addr)}")

def read_c_string(self, addr, max_len=256):
    """ 从 Unicorn 模拟内存中读取 C 语言字符串（以 null 结尾） """
    result = b""
    for i in range(max_len):
        byte = self.mu.mem_read(addr + i, 1)
        if byte == b"\x00":  # 遇到 null 终止符
            break
        result += byte
    return result.decode("utf-8", errors="ignore")
```


# **完整源码**



项目地址：[https://github.com/CYRUS-STUDIO/ARM64Emulator](https://github.com/CYRUS-STUDIO/ARM64Emulator)



```
import capstone
from unicorn import *
from unicorn.arm64_const import *


class ARM64Emulator:

    def __init__(self, so_file: str):
        self.so_file = so_file

        self._hooks = [] # 存储所有注册的 Hook
        self._last_registers = {}  # 记录上次的寄存器值
        self._watch_registers = set()  # 存储需要监控的寄存器

        # 分配代码区（TEXT 段）
        self.CODE_BASE = 0x000000  # 假设代码段起始地址
        self.CODE_SIZE = 1024 * 1024 * 10  # 10MB

        # 分配栈区（STACK 段）
        self.STACK_BASE = self.CODE_BASE + self.CODE_SIZE
        self.STACK_SIZE = 1024 * 1024 * 1  # 1MB

        # 初始化 Unicorn
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        # 初始化 Capstone 反汇编器 (针对 ARM64 架构)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        self._load_binary()
        self._setup_memory()
        self._setup_registers()
        self._setup_hooks()

    def _load_binary(self):
        with open(self.so_file, "rb") as f:
            self.CODE = f.read()

    def _setup_memory(self):
        self.mu.mem_map(self.CODE_BASE, self.CODE_SIZE)
        self.mu.mem_map(self.STACK_BASE, self.STACK_SIZE)
        # 写入指令
        self.mu.mem_write(self.CODE_BASE, self.CODE)

    def _setup_registers(self):
        self.mu.reg_write(UC_ARM64_REG_SP, self.STACK_BASE + self.STACK_SIZE - 4)  # 使 SP 从栈的顶部往下移动 4 字节，以 预留一点空间，避免越界错误。
        self.mu.reg_write(UC_ARM64_REG_PC, self.CODE_BASE)

    def set_x0(self, value):
        self.mu.reg_write(UC_ARM64_REG_X0, value)


    def set_x1(self, value):
        self.mu.reg_write(UC_ARM64_REG_X1, value)


    def set_x2(self, value):
        self.mu.reg_write(UC_ARM64_REG_X2, value)

    def _setup_hooks(self):
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)


    def dump_registers(self):
        """ 打印 Unicorn ARM64 CPU 的所有寄存器 """
        print("\n====== Registers Dump ======")

        # 遍历 X0 - X30
        for i in range(31):  # X0 ~ X30
            reg_id = getattr(arm64_const, f'UC_ARM64_REG_X{i}')
            value = self.mu.reg_read(reg_id)
            print(f"X{i:02}: 0x{value:016x}")

        # 打印 SP（栈指针）和 PC（程序计数器）
        sp = self.mu.reg_read(UC_ARM64_REG_SP)
        pc = self.mu.reg_read(UC_ARM64_REG_PC)

        print(f"\nSP:  0x{sp:016x}")
        print(f"PC:  0x{pc:016x}")
        print("============================\n")

    def run(self, start_address, end_address):
        print("\nBefore execution:")
        self.dump_registers()
        # 运行 Unicorn
        self.mu.emu_start(self.CODE_BASE + start_address, self.CODE_BASE + end_address)
        print("\nAfter execution:")
        self.dump_registers()

    def disassembly(self, start_address, end_address):
        """
        反汇编指定地址的字节码
        :param start_address: 开始地址
        :param end_address: 结束地址
        """
        # 提取目标方法的字节码
        target_data = self.CODE[start_address:end_address]
        # 反汇编字节码
        print("Disassembly:")
        for instruction in self.cs.disasm(target_data, start_address):
            print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")


    def hook_code(self, mu, address, size, user_data):
        code = mu.mem_read(address, size)
        # 反汇编并打印当前执行的指令
        for i in self.cs.disasm(code, 0, len(code)):
            print("[addr:%x;code:%s]:%s %s" % (address, code.hex(), i.mnemonic, i.op_str))

        # 遍历所有已注册的 Hook，并执行匹配的 Hook
        for hook_addr, hook_fn in self._hooks:
            if address == hook_addr:
                hook_fn()

        insn = next(self.cs.disasm(code, 0, len(code)), None)
        if not insn:
            return

        # 检查监控的寄存器是否变化
        for reg in self._watch_registers:
            new_value = mu.reg_read(reg)
            if self._last_registers[reg] != new_value:
                print(f">> PC: 0x{address:X}, {insn.mnemonic} {insn.op_str}, {reg} changed: 0x{self._last_registers[reg]:X} -> 0x{new_value:X}")
                self._last_registers[reg] = new_value  # 更新值


    def register_hook(self, address: int, hook_fn):
        """
        注册 Hook
        :param address: 需要 Hook 的地址
        :param hook_fn: Hook 处理函数
        """
        self._hooks.append((address, hook_fn))
        print(f"Hook registered at {hex(address)}")

    def unregister_hook(self, address: int):
        """
        取消 Hook
        :param address: 需要解除 Hook 的地址
        """
        self._hooks = [(addr, fn) for addr, fn in self._hooks if addr != address]
        print(f"Hook unregistered at {hex(address)}")

    def watch_registers(self, *regs):
        """
        添加要监控的寄存器

        使用示例: emu.watch_registers("X4", "X8")  # 监控 X4 和 X8

        """
        reg_map = {
            "X0": UC_ARM64_REG_X0, "X1": UC_ARM64_REG_X1, "X2": UC_ARM64_REG_X2, "X3": UC_ARM64_REG_X3,
            "X4": UC_ARM64_REG_X4, "X5": UC_ARM64_REG_X5, "X6": UC_ARM64_REG_X6, "X7": UC_ARM64_REG_X7,
            "X8": UC_ARM64_REG_X8, "X9": UC_ARM64_REG_X9, "X10": UC_ARM64_REG_X10, "X11": UC_ARM64_REG_X11,
            "X12": UC_ARM64_REG_X12, "X13": UC_ARM64_REG_X13, "X14": UC_ARM64_REG_X14, "X15": UC_ARM64_REG_X15,
            "X16": UC_ARM64_REG_X16, "X17": UC_ARM64_REG_X17, "X18": UC_ARM64_REG_X18, "X19": UC_ARM64_REG_X19,
            "X20": UC_ARM64_REG_X20, "X21": UC_ARM64_REG_X21, "X22": UC_ARM64_REG_X22, "X23": UC_ARM64_REG_X23,
            "X24": UC_ARM64_REG_X24, "X25": UC_ARM64_REG_X25, "X26": UC_ARM64_REG_X26, "X27": UC_ARM64_REG_X27,
            "X28": UC_ARM64_REG_X28, "FP": UC_ARM64_REG_FP, "LR": UC_ARM64_REG_LR, "SP": UC_ARM64_REG_SP,
            "PC": UC_ARM64_REG_PC
        }
        for reg in regs:
            if reg in reg_map:
                self._watch_registers.add(reg_map[reg])
                self._last_registers[reg_map[reg]] = 0  # 初始化记录值

    def patch_nop_range(self, start_addr: int, end_addr: int):
        """
        在指定范围内将指令 patch 为 NOP (0xD503201F)，**包括 end_addr 位置**

        :param start_addr: 需要 patch 的起始地址 (必须 4 字节对齐)
        :param end_addr: 需要 patch 的结束地址 (必须 4 字节对齐，包含此地址)
        """
        # 确保地址对齐
        if start_addr % 4 != 0 or end_addr % 4 != 0:
            raise ValueError("Start and end addresses must be 4-byte aligned.")

        if end_addr < start_addr:
            raise ValueError("End address must be greater than or equal to start address.")

        # NOP 指令在 AArch64 下的编码
        NOP_INSTRUCTION = b'\x1F\x20\x03\xD5'  # 0xD503201F

        # 计算 patch 的指令数量 (包括 end_addr)
        nop_count = ((end_addr - start_addr) // 4) + 1

        # 生成 NOP 指令序列
        nop_data = NOP_INSTRUCTION * nop_count

        # 写入 Unicorn 内存
        self.mu.mem_write(start_addr, nop_data)

        print(f"Patched {nop_count} instructions to NOP from {hex(start_addr)} to {hex(end_addr)} (inclusive)")

    def patch_nop(self, addr_list: list):
        """
        将地址列表中的每个地址 patch 为 NOP (0xD503201F)

        :param addr_list: 需要 patch 的地址列表 (每个地址必须 4 字节对齐)
        """
        # NOP 指令在 AArch64 下的编码
        NOP_INSTRUCTION = b'\x1F\x20\x03\xD5'  # 0xD503201F

        for addr in addr_list:
            if addr % 4 != 0:
                raise ValueError(f"Address {hex(addr)} is not 4-byte aligned.")

            self.mu.mem_write(addr, NOP_INSTRUCTION)
            print(f"Patched NOP at {hex(addr)}")

    def get_string_utf_chars(self, input_str: str, str_addr: int):
        """
        模拟 GetStringUTFChars，把 Python 参数 `input_str` 作为返回的 UTF-8 字符串
        """
        utf8_str = input_str.encode("utf-8") + b"\x00"  # UTF-8 编码并加 NULL 终止符

        # 写入 Unicorn 内存
        self.mu.mem_write(str_addr, utf8_str)

        # 设置 X0 返回值 (UTF-8 字符串地址)
        self.mu.reg_write(UC_ARM64_REG_X0, str_addr)

        print(f"GetStringUTFChars Hooked: '{input_str}' -> {hex(str_addr)}")

    def read_c_string(self, addr, max_len=256):
        """ 从 Unicorn 模拟内存中读取 C 语言字符串（以 null 结尾） """
        result = b""
        for i in range(max_len):
            byte = self.mu.mem_read(addr + i, 1)
            if byte == b"\x00":  # 遇到 null 终止符
                break
            result += byte
        return result.decode("utf-8", errors="ignore")
```



