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
