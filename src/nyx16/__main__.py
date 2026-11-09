"""Nyx16 research command-line interface."""
import argparse
import json
import sys
from .audit import IPSWError, inspect_ipsw
from .chips import list_chips

def main(argv=None):
    parser = argparse.ArgumentParser(prog="nyx16", description="A12-A17 jailbreak research (current tools read-only)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("chips", help="Show A12-A17 Pro chip identifiers (not jailbreak support)")
    inspect = sub.add_parser("inspect", help="Inspect an IPSW locally without writing anything")
    inspect.add_argument("ipsw", help="Path to an IPSW ZIP archive")
    inspect.add_argument("--product-type", help="Expected Apple ProductType (e.g. iPhone13,2)")
    inspect.add_argument("--board", help="Expected DeviceClass (e.g. d53gap)")
    args = parser.parse_args(argv)
    if args.command == "chips":
        report = {"project": "Nyx16", "status": "research_only", "chips": list_chips()}
    else:
        try:
            report = inspect_ipsw(args.ipsw, product_type=args.product_type, board=args.board)
        except IPSWError as exc:
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
            return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if args.command == "inspect" and report["metadata_result"] == "mismatched" else 0

if __name__ == "__main__":
    raise SystemExit(main())
