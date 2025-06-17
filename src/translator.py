import base64
import sys
import re

from src.isa import Opcode, NoArgType, BranchType, to_binary, to_hex

labels = {}
macros = {}
instructions = [item.value for item in Opcode]
branch_instructions = [item.value for item in BranchType]
no_operand_instructions = [item.value for item in NoArgType]


def code_inspection(lines):
    mem_addr = 0
    error_counter = 0
    report = ""
    line_index = 0
    current_section = ""
    for line in lines:
        line = re.sub(r";.*", "", line)
        line_index += 1
        if line == "":
            continue
        command = line.split()[0]
        args = line.split()[1:]

        if command.startswith("."):
            if len(args) == 0:
                if not (re.fullmatch(r"\.(data|code)", line, flags=re.IGNORECASE)):
                    error_counter += 1
                    report += f'Error: Unknown section definition in line {line_index}: "{line}"\n'
                    report += 'Note: Expected names for sections: ".data", ".code"\n\n'
                else:
                    current_section = command
            else:
                if not (
                    re.fullmatch(r"\.org +0x[\da-f]{1,8}", line, flags=re.IGNORECASE)
                ):
                    error_counter += 1
                    report += f"Error: Incorrect origin definition in line {line_index}: {line}\n\n"
                else:
                    mem_addr = int(
                        re.search(r"0x[\da-f]{1,8}", line, flags=re.IGNORECASE).group(
                            0
                        ),
                        16,
                    )
            continue

        if command.endswith(":"):
            if current_section == ".data":
                if not (
                    re.fullmatch(
                        r".+: +\.(word +(0x[\da-f]{1,8}|0|-?[1-9]\d{0,9}|.+)|string .*)",
                        line,
                        flags=re.IGNORECASE,
                    )
                ):
                    error_counter += 1
                    report += f"Error: Incorrect variable definition in line {line_index}: {line}\n\n"
                else:
                    if (
                        args[0] == ".word"
                        and re.fullmatch(r"-?[1-9]\d{0,9}", args[1])
                        and not (-(2**31) <= int(args[1]) <= 2**31 - 1)
                    ):
                        error_counter += 1
                        report += f"Error: Defined value out of bounds in line {line_index}: {line}\n"
                        report += "Note: For .word value supposed to be between -2147483648 and 2147483647\n\n"
                    if args[0] == ".string" and not re.fullmatch(
                        r"\".*\", 0",
                        line.replace(command, "").replace(args[0], "").strip(),
                    ):
                        error_counter += 1
                        report += f"Error: Incorrect string definition in line {line_index}: {line}\n"
                        report += (
                            'Note: .string should be defined as: "<any symbol>", 0\n\n'
                        )
            labels[command[: len(command) - 1]] = mem_addr
            if current_section == ".data" and ".string" in line:
                mem_addr += (
                    len(
                        line.replace(command, "")
                        .replace(args[0], "")
                        .replace(", 0", "")
                        .strip()
                    )
                    - 1
                )
            elif current_section == ".data" and ".word" in line:
                mem_addr += 1
            continue

        if current_section == ".data":
            error_counter += 1
            report += f"Error: Instructions are not supported in .data section in line {line_index}: {line}\n\n"
            continue
        mem_addr += 1
        if (
            command not in instructions
            and command not in branch_instructions
            and command not in no_operand_instructions
            and command not in macros
        ):
            error_counter += 1
            report += f'Error: Unknown instruction "{command}" in line {line_index}: {line}\n\n'
        else:
            if command in instructions or command in branch_instructions:
                if len(args) == 0:
                    error_counter += 1
                    report += f"Error: Missing operand for instruction in line {line_index}: {line}\n\n"
                    continue
                if re.fullmatch(
                    r"-?[1-9]\d*",
                    args[0]
                    .replace("(pc)", "")
                    .replace("]", "")
                    .replace("[", "")
                    .replace("*", ""),
                ) and not (
                    -(2**23)
                    <= int(
                        args[0]
                        .replace("(pc)", "")
                        .replace("]", "")
                        .replace("[", "")
                        .replace("*", "")
                    )
                    <= 2**23 - 1
                ):
                    error_counter += 1
                    report += f'Error: Operand value for instruction "{command}" out of bounds in line {line_index}: {line}\n'
                    report += "Note: Operand value for instructions supposed to be between -8388608 and 8388607\n\n"

    if "_start" not in labels:
        error_counter += 1
        report += 'Error: "_start" label is missing\n'
        report += 'Note: "_start" label is crucial to define program\'s entry point\n\n'
    report += f"Code inspection finished. {error_counter} errors have been found\n"
    return (error_counter == 0), report


def translate(lines):
    report = ""
    line_index = 0
    code = {"data_org": 0x0, "code_org": 0x0}
    mem_addr = 0
    current_section = ""

    for line in lines:
        line_index += 1
        command = line.split()[0] if len(line.split()) > 0 else ""
        arg = line.split()[1] if len(line.split()) > 1 else ""

        if re.fullmatch(r"\.(data|code)", command):
            current_section = command[1:]
            code[command[1:] + "_org"] = mem_addr
            continue

        if re.fullmatch(r"\.org +0x[\da-f]{1,8}", line, flags=re.IGNORECASE):
            mem_addr = int(
                re.search(r"0x[\da-f]{1,8}", line, flags=re.IGNORECASE).group(0), 16
            )
            code[current_section + "_org"] = mem_addr
            continue

        if re.fullmatch(
            r"[^;]+: +\.(word +(0x[\da-f]{1,8}|0|-?[1-9]\d{0,9}|.+)|string .*)",
            line,
            flags=re.IGNORECASE,
        ):
            if ".word" in line:
                if re.fullmatch(r"0x[\da-f]{1,8}|0|-?[1-9]\d{0,9}", line.split()[2]):
                    code[mem_addr] = f"word{line.split()[2]}"
                elif line.split()[2] in labels:
                    code[mem_addr] = f"word{labels[line.split()[2]]}"
                else:
                    report += (
                        f"Translation Error: Unknown label in line {line_index}: {line}"
                    )
                mem_addr += 1
            else:
                code[mem_addr] = (
                    f"str{line.replace(command, '').replace(arg, '').strip()[1:-4]}"
                )
                mem_addr += (
                    len(line.replace(command, "").replace(arg, "").strip()[1:-4]) + 1
                )
            continue

        if (
            command == ""
            or command.startswith(".")
            or command.endswith(":")
            or command.startswith(";")
        ):
            continue

        if (
            command not in no_operand_instructions
            and not re.fullmatch(
                r"-?[1-9]\d*|0|0x[\da-f]{1,8}",
                re.sub(r"\*?\[|]|\(pc\)", "", arg),
                flags=re.IGNORECASE,
            )
            and re.sub("[*\[\]]", "", arg, 3) not in labels
        ):
            report += (
                f'Translation error: Unknown label "{arg}" in line {line_index}\n\n'
            )
            continue

        if command in branch_instructions and arg in labels:
            arg = arg.replace(arg, f"{labels[arg]}")

        if command in instructions and re.sub("[*\[\]]", "", arg, 3) in labels:
            arg = arg.replace(
                re.sub("[*\[\]]", "", arg, 3),
                str(labels[re.sub("[*\[\]]", "", arg, 3)]),
            )

        if command in no_operand_instructions:
            line = command
        else:
            line = f"{command} {arg}"

        code[mem_addr] = line
        mem_addr += 1
    return report, code


def replace_macro(code):
    for i in re.findall(r"macro[\s\w*\[\]\-();+/]*?endm\n", code):
        macro_name = re.findall(r"macro *.*", i)[0].split()[1]
        i = re.sub(r"endm\n", "", i)
        i = re.sub(r"macro *.*\n", "", i)
        macros[macro_name] = i
    for mac, body in macros.items():
        code = re.sub(r"macro[\s\w*\[\]\-();+/]*?endm\n", "", code)
        code = re.sub(rf" *{mac}\n", body, code)
    return code


def main(source, code_target, data_target):
    src = open(source)
    lines = [line.strip() for line in src]
    lines = replace_macro("\n".join(lines)).split("\n")
    no_errors, inspection_result = code_inspection(lines)
    if no_errors:
        translation_report, code = translate(lines)
        if translation_report == "":
            code_bytes, data_bytes = to_binary(code)
            with open(code_target, "wb") as f:
                f.write(base64.b64encode(code_bytes))
            with open(data_target, "wb") as f:
                f.write(base64.b64encode(data_bytes))
            with open(code_target.replace("bin", "hex"), "w") as f:
                f.write(to_hex(code)[:-1])
        else:
            print(translation_report)
    else:
        print(inspection_result)


if __name__ == "__main__":
    assert len(sys.argv) == 4, (
        "Wrong arguments: translator.py <input_file> <target_code_file> <target_data_file>"
    )
    _, source, code_target, data_target = sys.argv
    main(source, code_target, data_target)
