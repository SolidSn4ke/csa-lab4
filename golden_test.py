import contextlib
import io
import logging
import os
import tempfile

import pytest

from src import translator, machine


@pytest.mark.golden_test("golden/*_asm.yaml")
def test_translator_and_machine(golden, caplog):
    logging.getLogger().setLevel(logging.DEBUG)

    with tempfile.TemporaryDirectory() as tmpdirname:
        source = os.path.join(tmpdirname, "test.asm")
        input_stream = os.path.join(tmpdirname, "input.txt")
        code_target = os.path.join(tmpdirname, "code.bin")
        code_target_hex = os.path.join(tmpdirname, "code.hex")
        data_target = os.path.join(tmpdirname, "data.bin")
        config = os.path.join(tmpdirname, "machine_config.yaml")

        with open(source, "w", encoding="utf-8") as file:
            file.write(golden["in_source"])

        with open(input_stream, "w", encoding="utf-8") as file:
            file.write(golden["in_stdin"])

        with open(config, "w", encoding="utf-8") as file:
            file.write(golden["in_config"])

        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            translator.main(source, code_target, data_target)
            machine.main(code_target, data_target, input_stream, config)

        with open(code_target, "rb") as file:
            code = file.read()
        with open(data_target, "rb") as file:
            data = file.read()
        with open(code_target_hex, encoding="utf-8") as file:
            code_hex = file.read()

        assert code == golden.out["out_code"]
        assert data == golden.out["out_data"]
        assert code_hex == golden.out["out_code_hex"]
        assert stdout.getvalue() == golden.out["out_stdout"]
        assert caplog.text == golden.out["out_log"]
