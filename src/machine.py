import base64
import sys
import logging
from enum import Enum

from src.isa import (
    Opcode,
    NoArgType,
    BranchType,
    AddrType,
    hex_to_signed_int,
    instruction_to_str,
    instruction_from_bin,
    map_bytes_to_memory,
)
from src.utils.config_parser import MachineConfig


class State(Enum):
    STOP = (0,)
    RUNNING = (1,)
    INTERRUPTION = 2


class Step(Enum):
    COMMAND_FETCH = (0,)
    ADDRESS_FETCH = (1,)
    OPERAND_FETCH = (2,)
    EXECUTION = (3,)
    INTERRUPTION = 4


class DataPath:
    acc = 0
    c = 0
    v = 0
    ar = 0
    mem_size = 16777216
    memory = None
    input_buffer = None
    output_buffer_int = None
    output_buffer_hex = None
    output_buffer_str = None
    input_cell = None
    output_cell = None

    def __init__(self, init_memory, input_buffer, input_cell, output_cell):
        self.input_cell = input_cell
        self.output_cell = output_cell
        self.memory = init_memory
        self.input_buffer = input_buffer
        self.output_buffer_int = []
        self.output_buffer_hex = []
        self.output_buffer_str = []

    def signal_latch_acc(self, sel):
        if sel["opcode"] == Opcode.NO_ARG:
            if sel["type"] == NoArgType.CLA:
                self.acc = 0

            if sel["type"] == NoArgType.CLC:
                self.c = 0

            if sel["type"] == NoArgType.CLV:
                self.v = 0

            if sel["type"] == NoArgType.SETC:
                self.c = 1

            if sel["type"] == NoArgType.SETV:
                self.v = 1

            if sel["type"] == NoArgType.NOT:
                self.acc = ~self.acc

            if sel["type"] == NoArgType.SHL:
                self.acc = self.acc << 1

            if sel["type"] == NoArgType.SHR:
                self.acc = self.acc >> 1

            if sel["type"] == NoArgType.ASR:
                if self.acc & 0x80000000 == 0:
                    self.acc = self.acc >> 1
                else:
                    self.acc = (self.acc >> 1) | 0x80000000

            if sel["type"] == NoArgType.CSHL:
                acc = self.acc
                buf = self.c
                new_c = (acc >> 31) & 1
                self.c = new_c
                self.acc = (acc << 1) | buf

            if sel["type"] == NoArgType.CSHR:
                acc = self.acc
                buf = self.c
                new_c = acc & 1
                self.c = new_c
                self.acc = (acc >> 1) | (buf << 31)

        elif sel["opcode"] == Opcode.AND:
            self.acc = self.acc & sel["arg"]

        elif sel["opcode"] == Opcode.OR:
            self.acc = self.acc | sel["arg"]

        elif sel["opcode"] == Opcode.ADD:
            acc = self.acc
            self.acc = acc + sel["arg"]

            if (acc >> 31 == 0 and sel["arg"] >> 31 == 0 and self.acc >> 31 == 1) or (
                acc >> 31 == 1 and sel["arg"] >> 31 == 1 and self.acc >> 31 == 0
            ):
                self.v = 1
            else:
                self.v = 0

            if acc + sel["arg"] > 0xFFFFFFFF:
                self.c = 1
            else:
                self.c = 0

        elif sel["opcode"] == Opcode.SUB:
            acc = self.acc
            self.acc = acc - sel["arg"]

            if (acc >> 31 == 0 and sel["arg"] >> 31 == 1 and self.acc >> 31 == 1) or (
                acc >> 31 == 1 and sel["arg"] >> 31 == 0 and self.acc >> 31 == 0
            ):
                self.v = 1
            else:
                self.v = 0

            if acc < sel["arg"]:
                self.c = 1
            else:
                self.c = 0

        elif sel["opcode"] == Opcode.MUL:
            acc = self.acc
            self.acc = acc * sel["arg"]

            if (acc * sel["arg"] > 2**31 - 1) or (acc * sel["arg"] < -(2**31)):
                self.v = 1
            else:
                self.v = 0

            if abs(acc * sel["arg"]) > 0xFFFFFFFF:
                self.c = 1
            else:
                self.c = 0

        elif sel["opcode"] == Opcode.DIV:
            self.acc = self.acc // sel["arg"]

        elif sel["opcode"] == Opcode.MOD:
            self.acc = self.acc % sel["arg"]

        elif sel["opcode"] == Opcode.LOAD:
            self.acc = sel["arg"]

        elif sel["opcode"] == Opcode.SAVE:
            self.signal_latch_addr({"addr_type": AddrType.IMM, "arg": sel["arg"]})
            self.signal_wr()

    def signal_wr(self):
        self.memory[self.ar] = self.acc
        if self.ar == self.output_cell:
            self.output_buffer_int.append(hex_to_signed_int(hex(self.acc)))
            self.output_buffer_hex.append(hex(self.acc))
            if self.acc & 0xFFFFFF00 == 0:
                self.output_buffer_str.append(chr(self.acc))
            else:
                self.output_buffer_str.append("?")
            logging.debug(
                f"output:\tint: {self.output_buffer_int[-1]}\thex: {self.output_buffer_hex[-1]}\tstr: '{self.output_buffer_str[-1]}'"
            )

    def signal_latch_addr(self, sel):
        if sel["addr_type"] == AddrType.INDR:
            self.ar = self.memory[sel["arg"]] & 0xFFFFFF
        else:
            self.ar = sel["arg"]

    def signal_in(self):
        logging.debug(f" input: '{self.input_buffer[0][1]}'")
        self.memory[self.input_cell] = int.from_bytes(
            self.input_buffer[0][1].encode(), byteorder="big"
        )
        self.input_buffer = self.input_buffer[1:]

    def get_nearest_input_moment(self):
        if len(self.input_buffer) > 0:
            return int(self.input_buffer[0][0])
        else:
            return -1


class ControlUnit:
    state = State.RUNNING
    step = Step.COMMAND_FETCH
    pc = None
    data_path = None
    tick = 0
    interrupt_ready = False
    interruption_vector = 0
    return_addr = 0
    interruption_allowed = False
    current_instruction = None

    def __init__(self, pc, data_path):
        self.pc = pc
        self.data_path = data_path

    def next_iteration(self):
        opcode, command_type, arg = self.command_fetch()
        self.current_instruction = instruction_to_str(opcode, command_type, arg)
        if (
            opcode != Opcode.BRANCH
            and opcode != Opcode.NO_ARG
            and command_type != AddrType.IMM
        ):
            if command_type != AddrType.DIR:
                self.address_fetch(command_type, arg)
            arg = self.operand_fetch()
        self.execution(opcode, command_type, arg)
        if (
            self.interrupt_ready
            and self.state != State.INTERRUPTION
            and self.interruption_allowed
        ):
            self.interruption()

    def command_fetch(self):
        self.step = Step.COMMAND_FETCH
        self.tick_inc()
        opcode, command_type, arg = instruction_from_bin(self.data_path.memory[self.pc])
        self.signal_latch_pc({"next": True})
        if command_type == AddrType.DIR or command_type == AddrType.INDR:
            self.data_path.signal_latch_addr({"addr_type": command_type, "arg": arg})
        return opcode, command_type, arg

    def address_fetch(self, addr_type, arg):
        self.step = Step.ADDRESS_FETCH
        self.tick_inc()
        self.data_path.signal_latch_addr(sel={"addr_type": addr_type, "arg": arg})

    def operand_fetch(self):
        self.step = Step.OPERAND_FETCH
        self.tick_inc()
        return self.data_path.memory[self.data_path.ar]

    def execution(self, opcode, command_type, arg):
        self.step = Step.EXECUTION
        self.tick_inc()
        if command_type == NoArgType.HALT:
            self.state = State.STOP

        elif command_type == NoArgType.IRET:
            self.state = State.RUNNING
            self.signal_latch_pc({"next": False, "arg": self.return_addr})

        elif command_type == NoArgType.EI:
            self.interruption_allowed = True

        elif command_type == NoArgType.DI:
            self.interruption_allowed = False

        elif opcode == Opcode.BRANCH:
            if command_type == BranchType.JUMP:
                self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BEQZ:
                if self.data_path.acc == 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BNEQZ:
                if self.data_path.acc != 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BLE:
                if self.data_path.acc & 0x80000000 != 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BGT:
                if self.data_path.acc & 0x80000000 == 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BCS:
                if self.data_path.c == 1:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BCNS:
                if self.data_path.c == 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BVS:
                if self.data_path.v == 1:
                    self.signal_latch_pc({"next": False, "arg": arg})

            if command_type == BranchType.BVNS:
                if self.data_path.v == 0:
                    self.signal_latch_pc({"next": False, "arg": arg})

        elif opcode == Opcode.SETVEC:
            self.interruption_vector = arg

        else:
            self.data_path.signal_latch_acc(
                sel={"opcode": opcode, "type": command_type, "arg": arg}
            )

    def interruption(self):
        self.step = Step.INTERRUPTION
        self.tick_inc()
        self.state = State.INTERRUPTION
        self.return_addr = self.pc
        self.signal_latch_pc({"next": False, "arg": self.interruption_vector})
        self.interrupt_ready = False
        return

    def signal_latch_pc(self, sel):
        if sel["next"]:
            self.pc += 1
        else:
            self.pc = sel["arg"]

    def tick_inc(self):
        logging.log(
            logging.DEBUG,
            f"STATE: {self.state.name:12} STEP: {self.step.name:13} TICK: {self.tick:3} PC: {self.pc:4} ADDR: {self.data_path.ar:3} MEM[ADDR]: {self.data_path.memory[self.data_path.ar]:10} ACC: {self.data_path.acc:10} C: {self.data_path.c} V: {self.data_path.v}\tINSTR: {self.current_instruction}",
        )
        self.tick += 1
        if self.tick == self.data_path.get_nearest_input_moment():
            self.data_path.signal_in()
            self.interrupt_ready = True


def simulation(init_memory, start_pc, input_tokens, config):
    data_path = DataPath(
        init_memory, input_tokens, config.mmio.in_addr, config.mmio.out_addr
    )
    control_unit = ControlUnit(start_pc, data_path)
    while control_unit.tick < config.tick_limit and control_unit.state != State.STOP:
        control_unit.next_iteration()
    if config.output_type == "str":
        output = "".join(control_unit.data_path.output_buffer_str)
    elif config.output_type == "int":
        output = control_unit.data_path.output_buffer_int
    elif config.output_type == "hex":
        output = control_unit.data_path.output_buffer_hex
    return output, control_unit.tick


def main(binary_code_file, binary_data_file, input_file, config_file):
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s    root:%(filename)s:%(lineno)d %(message)s",
    )
    with open(binary_code_file, "rb") as file:
        binary_code = base64.b64decode(file.read())
    with open(binary_data_file, "rb") as file:
        binary_data = base64.b64decode(file.read())
    config = MachineConfig.from_yaml(config_file)
    input_tokens = [
        (line.split()[0], line.split()[1] if len(line.split()) > 1 else " ")
        for line in open(input_file)
    ]
    init_memory = map_bytes_to_memory([0] * 16777216, binary_code, binary_data)
    output, ticks = simulation(
        init_memory,
        int.from_bytes(binary_code[0:4], byteorder="big"),
        input_tokens,
        config,
    )
    print(output)
    print(f"ticks: {ticks}")


if __name__ == "__main__":
    assert len(sys.argv) == 5, (
        "Wrong arguments: machine.py <binary_code_file> <binary_data_file> <input_file> <config_file>"
    )
    _, source_code, source_data, target, config_file = sys.argv
    main(source_code, source_data, target, config_file)
