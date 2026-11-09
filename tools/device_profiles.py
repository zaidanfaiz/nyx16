"""Public hardware identification reference for A12–A16 era iPhone models.

Board identifiers are hardware labels, not firmware eligibility or exploit claims.
Sources: https://ipsw.me/ and https://github.com/marcostolosa/shshshh
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

@dataclass(frozen=True)
class Device:
    name: str
    product_type: str
    chip: str
    boards: tuple[str, ...]

DEVICES = (
    Device("iPhone XR", "iPhone11,8", "A12", ("n841ap",)),
    Device("iPhone XS", "iPhone11,2", "A12", ("d321ap",)),
    Device("iPhone XS Max", "iPhone11,4", "A12", ("d331ap",)),
    Device("iPhone XS Max", "iPhone11,6", "A12", ("d331pap",)),
    Device("iPhone 11", "iPhone12,1", "A13", ("n104ap",)),
    Device("iPhone 11 Pro", "iPhone12,3", "A13", ("d421ap",)),
    Device("iPhone 11 Pro Max", "iPhone12,5", "A13", ("d431ap",)),
    Device("iPhone SE (2020)", "iPhone12,8", "A13", ("d79ap",)),
    Device("iPhone 12 mini", "iPhone13,1", "A14", ("d52gap",)),
    Device("iPhone 12", "iPhone13,2", "A14", ("d53gap",)),
    Device("iPhone 12 Pro", "iPhone13,3", "A14", ("d53pap",)),
    Device("iPhone 12 Pro Max", "iPhone13,4", "A14", ("d54pap",)),
    Device("iPhone 13 mini", "iPhone14,4", "A15", ("d16ap",)),
    Device("iPhone 13", "iPhone14,5", "A15", ("d17ap",)),
    Device("iPhone 13 Pro", "iPhone14,2", "A15", ("d63ap",)),
    Device("iPhone 13 Pro Max", "iPhone14,3", "A15", ("d64ap",)),
    Device("iPhone SE (2022)", "iPhone14,6", "A15", ("d49ap",)),
    Device("iPhone 14", "iPhone14,7", "A15", ("d27ap",)),
    Device("iPhone 14 Plus", "iPhone14,8", "A15", ("d28ap",)),
    Device("iPhone 14 Pro", "iPhone15,2", "A16", ("d73ap",)),
    Device("iPhone 14 Pro Max", "iPhone15,3", "A16", ("d74ap",)),
)

BY_PRODUCT = {d.product_type.casefold(): d for d in DEVICES}
CHIP_BY_CPID = {0x8020: "A12", 0x8030: "A13", 0x8101: "A14", 0x8110: "A15", 0x8120: "A16"}

def identify_product(product_type: str | None, hardware_model: str | None = None):
    """Return a model label only for an explicitly recognized ProductType.

    Board mismatch is informative but must not silently remap device identity.
    """
    device = BY_PRODUCT.get((product_type or "").casefold())
    if not device:
        return {"status": "UNKNOWN", "product_type": product_type or "UNKNOWN",
                "device": "UNKNOWN", "chip_family": "UNKNOWN", "board_match": "UNKNOWN"}
    board = (hardware_model or "").casefold()
    return {
        "status": "IDENTIFIED",
        "product_type": device.product_type,
        "device": device.name,
        "chip_family": device.chip,
        "hardware_board": hardware_model or "UNKNOWN",
        "board_match": "UNKNOWN" if not board else "MATCH" if board in device.boards else "MISMATCH",
    }

def identify_recovery(cpid: str | None):
    """CPID can identify an SoC family, not an individual iPhone model."""
    if not cpid:
        return "UNKNOWN"
    try:
        value = int(cpid, 0)
    except (ValueError, TypeError):
        return "UNKNOWN"
    return CHIP_BY_CPID.get(value, "UNKNOWN")
