import argparse
import sys
from pathlib import Path

import pefile

def main() -> int:
    ap = argparse.ArgumentParser(description="Extract Remcos RT_RCDATA SETTINGS")
    ap.add_argument("pe_path", type=Path, help="path to PE sample")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="output path (default: <pe_stem>_SETTINGS.bin)",
    )
    args = ap.parse_args()

    pe_path = args.pe_path
    if not pe_path.is_file():
        print(f"not found: {pe_path}", file=sys.stderr)
        return 1

    out = args.output or pe_path.with_name(f"{pe_path.stem}_SETTINGS.bin")
    pe = pefile.PE(str(pe_path), fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
    )

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("no resources", file=sys.stderr)
        return 1

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != pefile.RESOURCE_TYPE["RT_RCDATA"]:
            continue
        for e in entry.directory.entries:
            name = e.name.string.decode() if e.name else str(e.id)
            print(name, end="")
            data = e.directory.entries[0].data.struct
            blob = pe.get_data(data.OffsetToData, data.Size)
            print(f" {len(blob)} bytes")
            if str(name).upper() == "SETTINGS":
                out.write_bytes(blob)
                print(f"wrote {out} ({len(blob)} bytes)")
                return 0

    print("SETTINGS not found", file=sys.stderr)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())