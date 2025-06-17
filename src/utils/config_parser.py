import yaml
from dataclasses import dataclass


@dataclass
class MMIOConfig:
    in_addr: int
    out_addr: int


@dataclass
class MachineConfig:
    mmio: MMIOConfig
    tick_limit: int
    output_type: str

    @classmethod
    def from_yaml(cls, file_path):
        with open(file_path, "r") as f:
            config_data = yaml.safe_load(f)["machine"]

        mmio = MMIOConfig(
            in_addr=config_data["memory_mapped_io"]["in_addr"],
            out_addr=config_data["memory_mapped_io"]["out_addr"],
        )

        return cls(
            mmio=mmio,
            tick_limit=config_data["tick_limit"],
            output_type=config_data["output_type"],
        )
