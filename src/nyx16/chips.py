"""Documented Apple iPhone-class SoC identifiers (research labels only)."""
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class Chip:
    family: str
    silicon: str
    cpid: int
    research_status: str = "metadata_only"

CHIPS = (
    Chip("A12", "T8020", 0x8020),
    Chip("A13", "T8030", 0x8030),
    Chip("A14", "T8101", 0x8101),
    Chip("A15", "T8110", 0x8110),
    Chip("A16", "T8120", 0x8120),
)

def list_chips():
    return [{**asdict(chip), "cpid_hex": f"0x{chip.cpid:04x}"} for chip in CHIPS]
