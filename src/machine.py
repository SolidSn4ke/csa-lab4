import base64
import sys
import logging

from src.isa import *
from src.utils.config_parser import MachineConfig


class State(Enum):
    STOP = 0,
    RUNNING = 1,
    INTERRUPTION = 2


class Step(Enum):
    COMMAND_FETCH = 0,
    ADDRESS_FETCH = 1,
    OPERAND_FETCH = 2,
    EXECUTION = 3,
    INTERRUPTION = 4


class DataPath:
    acc = None
    c = None
    v = None
    mem_size = None
    memory = None
    input_buffer = None
    output_buffer_int = None
    output_buffer_hex = None
    output_buffer_str = None
    address_register = None
    input_cell = None
    output_cell = None

    def __init__(self, init_memory, input_buffer, input_cell, output_cell):
        self.acc = 0
        self.c = 0
        self.v = 0
        self.input_cell = input_cell
        self.output_cell = output_cell
        self.mem_size = 16777216
        self.memory = init_memory
        self.input_buffer = input_buffer
        self.output_buffer_int = []
        self.output_buffer_hex = []
        self.output_buffer_str = []
        self.address_register = 0

    def save_mem_to_acc(self):
        self.acc = self.memory[self.address_register]

    def save_acc_to_mem(self):
        self.memory[self.address_register] = self.acc
        if self.address_register == self.output_cell:
            self.output_buffer_int.append(hex_to_signed_int(hex(self.acc)))
            self.output_buffer_hex.append(hex(self.acc))
            if self.acc & 0xFFFFFF00 == 0:
                self.output_buffer_str.append(chr(self.acc))
            else:
                self.output_buffer_str.append('?')
            logging.debug(
                f"output:\tint: {self.output_buffer_int[-1]}\thex: {self.output_buffer_hex[-1]}\tstr: '{self.output_buffer_str[-1]}'")

    def set_acc(self, new_acc):
        self.acc = new_acc & 0xFFFFFFFF

    def get_acc(self):
        return self.acc

    def set_address_register(self, addr):
        self.address_register = addr

    def set_v(self, new_v):
        self.v = new_v

    def get_v(self):
        return self.v

    def set_c(self, new_c):
        self.c = new_c

    def get_c(self):
        return self.c

    def read_from_mem(self):
        return self.memory[self.address_register]

    def update_value_in_input_cell(self):
        logging.debug(f" input: '{self.input_buffer[0][1]}'")
        self.memory[self.input_cell] = int.from_bytes(self.input_buffer[0][1].encode(), byteorder="big")
        self.input_buffer = self.input_buffer[1:]

    def get_nearest_input_moment(self):
        if len(self.input_buffer) > 0:
            return int(self.input_buffer[0][0])
        else:
            return -1


class ControlUnit:
    state = None
    step = None
    pc = None
    data_path = None
    tick = None
    interrupt_ready = None
    interruption_vector = None
    return_addr = None
    interruption_allowed = None
    current_instruction = None

    def __init__(self, pc, data_path):
        self.state = State.RUNNING
        self.step = Step.COMMAND_FETCH
        self.pc = pc
        self.data_path = data_path
        self.tick = 0
        self.interrupt_ready = False
        self.interruption_vector = 0
        self.interruption_allowed = False

    def next_iteration(self):
        opcode, command_type, arg = self.command_fetch()
        self.current_instruction = instruction_to_str(opcode, command_type, arg)
        if opcode != Opcode.BRANCH and opcode != Opcode.NO_ARG and command_type != AddrType.IMM:
            if command_type != AddrType.DIR:
                arg = self.address_fetch(command_type, arg)
            arg = self.operand_fetch(arg)
        self.execution(opcode, command_type, arg)
        if self.interrupt_ready and self.state != State.INTERRUPTION and self.interruption_allowed:
            self.interruption()

    def command_fetch(self):
        self.step = Step.COMMAND_FETCH
        self.tick_inc()
        self.data_path.set_address_register(self.pc)
        self.set_pc(self.get_pc() + 1)
        return instruction_from_bin(self.data_path.read_from_mem())

    def address_fetch(self, addr_type, arg):
        self.step = Step.ADDRESS_FETCH
        self.tick_inc()
        if addr_type == AddrType.INDR:
            self.data_path.set_address_register(arg)
            return self.data_path.read_from_mem()

        elif addr_type == AddrType.REL:
            return self.get_pc() + arg

    def operand_fetch(self, arg):
        self.step = Step.OPERAND_FETCH
        self.tick_inc()
        self.data_path.set_address_register(arg)
        return self.data_path.read_from_mem()

    def execution(self, opcode, command_type, arg):
        self.step = Step.EXECUTION
        self.tick_inc()
        if opcode == Opcode.NO_ARG:
            if command_type == NoArgType.HALT:
                self.state = State.STOP

            if command_type == NoArgType.CLA:
                self.data_path.set_acc(0)

            if command_type == NoArgType.CLC:
                self.data_path.set_c(0)

            if command_type == NoArgType.CLV:
                self.data_path.set_v(0)

            if command_type == NoArgType.SETC:
                self.data_path.set_c(1)

            if command_type == NoArgType.SETV:
                self.data_path.set_v(1)

            if command_type == NoArgType.NOT:
                self.data_path.set_acc(~self.data_path.get_acc())

            if command_type == NoArgType.SHL:
                self.data_path.set_acc(self.data_path.get_acc() << 1)

            if command_type == NoArgType.SHR:
                self.data_path.set_acc(self.data_path.get_acc() >> 1)

            if command_type == NoArgType.ASR:
                self.data_path.set_acc(
                    self.data_path.get_acc() / self.data_path.get_acc * (self.data_path.get_acc() >> 1))

            if command_type == NoArgType.CSHL:
                acc = self.data_path.get_acc()
                buf = self.data_path.get_c()
                new_c = (acc >> 31) & 1
                self.data_path.set_c(new_c)
                self.data_path.set_acc((acc << 1) | buf)

            if command_type == NoArgType.CSHR:
                acc = self.data_path.get_acc()
                buf = self.data_path.get_c()
                new_c = acc & 1
                self.data_path.set_c(new_c)
                self.data_path.set_acc((acc >> 1) | (buf << 31))

            if command_type == NoArgType.IRET:
                self.state = State.RUNNING
                self.pc = self.return_addr

            if command_type == NoArgType.EI:
                self.interruption_allowed = True

            if command_type == NoArgType.DI:
                self.interruption_allowed = False

        elif opcode == Opcode.BRANCH:
            if command_type == BranchType.JUMP:
                self.set_pc(arg)

            if command_type == BranchType.BEQZ:
                if self.data_path.get_acc() == 0:
                    self.set_pc(arg)

            if command_type == BranchType.BNEQZ:
                if self.data_path.get_acc() != 0:
                    self.set_pc(arg)

            if command_type == BranchType.BLE:
                if self.data_path.get_acc() & 0x80000000 != 0:
                    self.set_pc(arg)

            if command_type == BranchType.BGT:
                if self.data_path.get_acc() & 0x80000000 == 0:
                    self.set_pc(arg)

            if command_type == BranchType.BCS:
                if self.data_path.get_c() == 1:
                    self.set_pc(arg)

            if command_type == BranchType.BCNS:
                if self.data_path.get_c() == 0:
                    self.set_pc(arg)

            if command_type == BranchType.BVS:
                if self.data_path.get_v() == 1:
                    self.set_pc(arg)

            if command_type == BranchType.BVNS:
                if self.data_path.get_v() == 0:
                    self.set_pc(arg)

        elif opcode == Opcode.AND:
            self.data_path.set_acc(self.data_path.get_acc() & arg)

        elif opcode == Opcode.OR:
            self.data_path.set_acc(self.data_path.get_acc() | arg)

        elif opcode == Opcode.ADD:
            acc = self.data_path.get_acc()
            self.data_path.set_acc(acc + arg)
            self.data_path.set_v(1) if (acc >> 31 == 0 and arg >> 31 == 0 and self.data_path.get_acc() >> 31 == 1) or (acc >> 31 == 1 and arg >> 31 == 1 and self.data_path.get_acc() >> 31 == 0) else self.data_path.set_v(0)
            self.data_path.set_c(1) if acc + arg > 0xFFFFFFFF else self.data_path.set_c(0)

        elif opcode == Opcode.SUB:
            acc = self.data_path.get_acc()
            self.data_path.set_acc(acc - arg)
            self.data_path.set_v(1) if (acc >> 31 == 0 and arg >> 31 == 1 and self.data_path.get_acc() >> 31 == 1) or (acc >> 31 == 1 and arg >> 31 == 0 and self.data_path.get_acc() >> 31 == 0) else self.data_path.set_v(0)
            self.data_path.set_c(1) if acc < arg else self.data_path.set_c(0)

        elif opcode == Opcode.MUL:
            acc = self.data_path.get_acc()
            self.data_path.set_acc(acc * arg)
            self.data_path.set_v(1) if (acc * arg > 2**31 -1) or (acc * arg < -2**31) else self.data_path.set_v(0)
            self.data_path.set_c(1) if abs(acc * arg) > 0xFFFFFFFF else self.data_path.set_c(0)

        elif opcode == Opcode.DIV:
            self.data_path.set_acc(self.data_path.get_acc() // arg)

        elif opcode == Opcode.MOD:
            self.data_path.set_acc(self.data_path.get_acc() % arg)

        elif opcode == Opcode.LOAD:
            self.data_path.set_acc(arg)

        elif opcode == Opcode.SAVE:
            self.data_path.set_address_register(arg)
            self.data_path.save_acc_to_mem()

        elif opcode == Opcode.SETVEC:
            self.interruption_vector = arg

    def interruption(self):
        self.step = Step.INTERRUPTION
        self.tick_inc()
        self.state = State.INTERRUPTION
        self.return_addr = self.pc
        self.pc = self.interruption_vector
        self.interrupt_ready = False
        return

    def set_pc(self, new_pc):
        self.pc = new_pc

    def get_pc(self):
        return self.pc

    def tick_inc(self):
        logging.log(logging.DEBUG,
                    f"STATE: {self.state.name:12} STEP: {self.step.name:13} TICK: {self.tick:3} PC: {self.pc:4} ADDR: {self.data_path.address_register:3} MEM[ADDR]: {self.data_path.read_from_mem():10} ACC: {self.data_path.get_acc():10} C: {self.data_path.get_c()} V: {self.data_path.get_v()}\tINSTR: {self.current_instruction}")
        self.tick += 1
        if self.tick == self.data_path.get_nearest_input_moment():
            self.data_path.update_value_in_input_cell()
            self.interrupt_ready = True


def simulation(init_memory, start_pc, input_tokens, config):
    data_path = DataPath(init_memory, input_tokens, config.mmio.in_addr, config.mmio.out_addr)
    control_unit = ControlUnit(start_pc, data_path)
    while control_unit.tick < config.tick_limit and control_unit.state != State.STOP:
        control_unit.next_iteration()
    if config.output_type == 'str':
        output = "".join(control_unit.data_path.output_buffer_str)
    elif config.output_type == 'int':
        output = control_unit.data_path.output_buffer_int
    elif config.output_type == 'hex':
        output = control_unit.data_path.output_buffer_hex
    return output, control_unit.tick


def main(binary_code_file, binary_data_file, input_file, config_file):
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s    root:%(filename)s:%(lineno)d %(message)s')
    with open(binary_code_file, "rb") as file:
        binary_code = base64.b64decode(file.read())
    with open(binary_data_file, "rb") as file:
        binary_data = base64.b64decode(file.read())
    config = MachineConfig.from_yaml(config_file)
    input_tokens = [(line.split()[0], line.split()[1] if len(line.split()) > 1 else ' ') for line in open(input_file)]
    init_memory = map_bytes_to_memory([0] * 16777216, binary_code, binary_data)
    output, ticks = simulation(init_memory, int.from_bytes(binary_code[0:4], byteorder="big"), input_tokens, config)
    print(output)
    print(f"ticks: {ticks}")


if __name__ == "__main__":
    assert len(
        sys.argv) == 5, "Wrong arguments: machine.py <binary_code_file> <binary_data_file> <input_file> <config_file>"
    _, source_code, source_data, target, config_file = sys.argv
    main(source_code, source_data, target, config_file)
