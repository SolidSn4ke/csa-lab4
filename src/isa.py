import re
from enum import Enum


class Sections(Enum):
    DATA = ".data"
    CODE = ".code"


class Directives(Enum):
    ORG = ".org"
    WORD = ".word"
    STRING = ".string"


class AddrType(Enum):
    IMM = "immediate_value"
    INDR = "indirect_load"
    REL = "pc_relative"
    DIR = "direct_load"


class Opcode(Enum):
    NO_ARG = "no_arg"
    BRANCH = "branch"
    AND = "and"
    OR = "or"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    MOD = "mod"
    LOAD = "load"
    SAVE = "save"
    SETVEC = "setvec"


class BranchType(Enum):
    JUMP = "jump"
    BEQZ = "beqz"
    BNEQZ = "bneqz"
    BLE = "ble"
    BGT = "bgt"
    BCS = "bcs"
    BCNS = "bcns"
    BVS = "bvs"
    BVNS = "bvns"


class NoArgType(Enum):
    HALT = "halt"
    CLA = "cla"
    CLC = "clc"
    CLV = "clv"
    SETC = "setc"
    SETV = "setv"
    NOT = "not"
    SHL = "shl"
    SHR = "shr"
    ASR = "asr"
    CSHL = "cshl"
    CSHR = "cshr"
    IRET = "iret"
    EI = "ei"
    DI = "di"


bin_to_addr_type = {
    0x0: AddrType.IMM,
    0x1: AddrType.DIR,
    0x2: AddrType.INDR,
    0x3: AddrType.REL
}

opcode_to_bin = {
    Opcode.AND: 0x1,
    Opcode.OR: 0x2,
    Opcode.ADD: 0x3,
    Opcode.SUB: 0x4,
    Opcode.MUL: 0x5,
    Opcode.DIV: 0x6,
    Opcode.MOD: 0x7,
    Opcode.LOAD: 0x8,
    Opcode.SAVE: 0x9,
    Opcode.SETVEC: 0xa
}

bin_to_opcode = {
    0x0: Opcode.NO_ARG,
    0x1: Opcode.AND,
    0x2: Opcode.OR,
    0x3: Opcode.ADD,
    0x4: Opcode.SUB,
    0x5: Opcode.MUL,
    0x6: Opcode.DIV,
    0x7: Opcode.MOD,
    0x8: Opcode.LOAD,
    0x9: Opcode.SAVE,
    0xa: Opcode.SETVEC,
    0xF: Opcode.BRANCH
}

branch_to_bin = {
    BranchType.JUMP: 0x0,
    BranchType.BEQZ: 0x1,
    BranchType.BNEQZ: 0x2,
    BranchType.BLE: 0x3,
    BranchType.BGT: 0x4,
    BranchType.BCS: 0x5,
    BranchType.BCNS: 0x6,
    BranchType.BVS: 0x7,
    BranchType.BVNS: 0x8
}

bin_to_branch = {
    0x0: BranchType.JUMP,
    0x1: BranchType.BEQZ,
    0x2: BranchType.BNEQZ,
    0x3: BranchType.BLE,
    0x4: BranchType.BGT,
    0x5: BranchType.BCS,
    0x6: BranchType.BCNS,
    0x7: BranchType.BVS,
    0x8: BranchType.BVNS,
}

no_operand_to_bin = {
    NoArgType.HALT: 0x0,
    NoArgType.CLA: 0x1,
    NoArgType.CLC: 0x2,
    NoArgType.CLV: 0x3,
    NoArgType.SETC: 0x4,
    NoArgType.SETV: 0x5,
    NoArgType.NOT: 0x6,
    NoArgType.SHL: 0x7,
    NoArgType.SHR: 0x8,
    NoArgType.ASR: 0x9,
    NoArgType.CSHL: 0xa,
    NoArgType.CSHR: 0xb,
    NoArgType.IRET: 0xc,
    NoArgType.EI: 0xd,
    NoArgType.DI: 0xe
}

bin_to_no_operand = {
    0x0: NoArgType.HALT,
    0x1: NoArgType.CLA,
    0x2: NoArgType.CLC,
    0x3: NoArgType.CLV,
    0x4: NoArgType.SETC,
    0x5: NoArgType.SETV,
    0x6: NoArgType.NOT,
    0x7: NoArgType.SHL,
    0x8: NoArgType.SHR,
    0x9: NoArgType.ASR,
    0xa: NoArgType.CSHL,
    0xb: NoArgType.CSHR,
    0xc: NoArgType.IRET,
    0xd: NoArgType.EI,
    0xe: NoArgType.DI
}


def to_binary(code):
    code_byte_array = bytearray()
    data_byte_array = bytearray()
    code_byte_array.extend(code["code_org"].to_bytes(4, byteorder="big"))
    data_byte_array.extend(code["data_org"].to_bytes(4, byteorder="big"))

    for addr, instruction in code.items():
        if not str.isdigit(str(addr)): continue
        command = instruction.split()[0]
        operand = instruction.split()[1] if len(instruction.split()) > 1 else None

        if command in [o.value for o in Opcode]:
            opcode = next(op for op in Opcode if op.value == command)

            if re.fullmatch(r"\[.*]", operand):
                addressing_type = 0b0001
                if operand.replace("[", "").startswith("0x"):
                    operand = int(operand[3:len(operand) - 1], 16)
                else:
                    operand = int(operand[1:len(operand) - 1])

            elif re.fullmatch(r"\*\[.*]", operand):
                addressing_type = 0b0010
                if operand.replace("*[", "").startswith("0x"):
                    operand = int(operand[4:len(operand) - 1], 16)
                else:
                    operand = int(operand[2:len(operand) - 1])

            elif re.fullmatch(r"(-?\d|0x[\da-f]{1,6})\(pc\)", operand, flags=re.IGNORECASE):
                addressing_type = 0b0011
                if operand.startswith("0x"):
                    operand = int(operand[2:len(operand) - 4], 16)
                else:
                    operand = int(operand[:len(operand) - 4])

            else:
                addressing_type = 0b0000
                if operand.startswith("0x"):
                    operand = int(operand, 16)
                else:
                    operand = int(operand)

            word = (opcode_to_bin[opcode] << 28) | (addressing_type << 24) | (operand & 0xFFFFFF)

        elif command in [b.value for b in BranchType]:
            opcode = 0xf
            branch_type = next(bt for bt in BranchType if bt.value == command)

            if re.fullmatch(r"(-?\d|0x[\da-f]{1,6})\(pc\)", operand):
                if operand.startswith("0x"):
                    operand = addr + int(operand[2:len(operand) - 4], 16)
                else:
                    operand = addr + int(operand[:len(operand) - 4])
            word = (opcode << 28) | (branch_to_bin[branch_type] << 24) | (int(operand) & 0xFFFFFF)

        elif command in [n.value for n in NoArgType]:
            opcode = 0x0
            no_operand_type = next(n for n in NoArgType if n.value == command)
            word = (opcode << 28) | (no_operand_to_bin[no_operand_type] << 24)

        elif command.startswith('word'):
            if command[4:].startswith("0x"):
                word = int(command[6:], 16) & 0xFFFFFFFF
            else:
                word = int(command[4:]) & 0xFFFFFFFF

        if command.startswith('str'):
            for char in instruction[3:] + '\0':
                data_byte_array.extend(ord(char).to_bytes(4, byteorder='big'))
        elif command.startswith('word'):
            data_byte_array.extend(word.to_bytes(4, byteorder="big"))
        else:
            code_byte_array.extend(word.to_bytes(4, byteorder="big"))
    return bytes(code_byte_array), bytes(data_byte_array)


def to_hex(code):
    result = ""
    binary_code, _ = to_binary(code)
    mem_addr = int.from_bytes(binary_code[0:4], byteorder="big") & 0xFFFFFFFF
    for i in range(4, len(binary_code), 4):
        instruction = int.from_bytes(binary_code[i:i + 4], byteorder='big') & 0xFFFFFFFF
        opcode, command_type, arg = instruction_from_bin(instruction)
        result += f"{mem_addr} - {hex(instruction)} - {instruction_to_str(opcode,command_type,arg)}\n"
        mem_addr += 1
    return result


def instruction_from_bin(b):
    opcode = bin_to_opcode[(b >> 28) & 0xF]
    if opcode == Opcode.BRANCH:
        command_type = bin_to_branch[(b >> 24) & 0x0F]
    elif opcode == opcode.NO_ARG:
        command_type = bin_to_no_operand[(b >> 24) & 0x0F]
    else:
        command_type = bin_to_addr_type[(b >> 24) & 0x0F]
    arg = b & 0x00FFFFFF
    return opcode, command_type, arg


def instruction_to_str(opcode, command_type, arg):
    if opcode == Opcode.NO_ARG:
        return f"{command_type.value}"
    elif opcode == Opcode.BRANCH:
        return f"{command_type.value} {arg}"
    else:
        if command_type == AddrType.IMM:
            return f"{opcode.value} {arg}"
        elif command_type == AddrType.DIR:
            return f"{opcode.value} [{arg}]"
        elif command_type == AddrType.INDR:
            return f"{opcode.value} *[{arg}]"
        elif command_type == AddrType.REL:
            return f"{opcode.value} [pc + ({arg})]"


def map_bytes_to_memory(mem, binary_code, binary_data):
    mem_addr = int.from_bytes(binary_data[0:4], byteorder="big") & 0xFFFFFFFF

    for i in range(4, len(binary_data), 4):
        mem[mem_addr] = int.from_bytes(binary_data[i:i + 4], byteorder="big") & 0xFFFFFFFF
        mem_addr += 1

    mem_addr = int.from_bytes(binary_code[0:4], byteorder="big") & 0xFFFFFFFF
    for i in range(4, len(binary_code), 4):
        mem[mem_addr] = int.from_bytes(binary_code[i:i + 4], byteorder="big") & 0xFFFFFFFF
        mem_addr += 1
    return mem


def hex_to_signed_int(hex_str):
    num = int(hex_str, 16)
    if num >= (1 << 31):
        num -= (1 << 32)
    return num
