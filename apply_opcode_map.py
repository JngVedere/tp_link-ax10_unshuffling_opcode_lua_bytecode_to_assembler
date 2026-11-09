"""Apply the adjacent JSON map to a luad --raw listing, without executing Lua.

Usage: python3 apply_opcode_map.py INPUT.txt OUTPUT.txt
Produces opcode names and encoded operands, not recovered Lua source.
"""
import json
import re
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(__doc__)
source, destination = map(Path, sys.argv[1:])
if source.resolve() == destination.resolve():
    raise SystemExit("INPUT and OUTPUT must be different files")
mapping_path = Path(__file__).with_name("tplink-opcode-map.json")
mapping = json.loads(mapping_path.read_text(encoding="utf-8-sig"))
lines = source.read_text(encoding="utf-8-sig").splitlines()
header = re.compile(r"; (proto:[0-9/]+)\s")
instruction = re.compile(r"\s*(\d+)\s+\[0x([0-9a-fA-F]{8})\]")
upvalues, counts, seen = {}, {}, {}
proto = None
for line in lines:
    match = header.match(line)
    if match:
        proto = match[1]
        upvalues[proto], seen[proto] = 0, []
    elif proto:
        if re.match(r";\s+upvalue\[\d+\]", line):
            upvalues[proto] += 1
        match = re.search(r"instructions:\s*(\d+)", line)
        if match:
            counts[proto] = int(match[1])
        match = instruction.match(line)
        if match:
            seen[proto].append(int(match[1]))
for proto, count in counts.items():
    if seen[proto] != list(range(count)):
        raise SystemExit(f"Incomplete raw word listing for {proto}; refusing partial decoding")

result = ["; Opcode names from tplink-opcode-map.json; ABC fields remain numeric.",
          "; Static field listing only. No firmware code executed; no Lua source recovered."]
proto, captures, extra = None, 0, False
for line in lines:
    match = header.match(line)
    if match:
        if captures or extra:
            raise SystemExit("Truncated companion data at prototype boundary")
        proto = match[1]
    match = instruction.match(line)
    if not match:
        result.append(line)
        continue
    pc, word = int(match[1]), int(match[2], 16)
    op, a = word & 63, (word >> 6) & 255
    b, c, bx = (word >> 23) & 511, (word >> 14) & 511, word >> 14
    prefix = f"{pc:4d}  [0x{word:08x}]  "
    if extra:
        result.append(prefix + f"SETLIST_EXTRA {word}")
        extra = False
        continue
    name = mapping.get(str(op))
    if name is None:
        raise SystemExit(f"Unknown opcode {op} at {proto}:pc:{pc}")
    if captures:
        if name not in ("MOVE", "GETUPVAL"):
            raise SystemExit(f"Unexpected closure capture opcode at {proto}:pc:{pc}")
        kind = "parent register" if name == "MOVE" else "parent upvalue"
        result.append(prefix + f"CAPTURE {name} {kind} {b} ; closure metadata")
        captures -= 1
        continue
    if name == "CLOSURE":
        child = f"{proto}/{bx}"
        if child not in upvalues:
            raise SystemExit(f"Missing metadata for {child}; export the whole file without --proto")
        captures = upvalues[child]
        operands = f"R({a}) Proto({bx}) ; {child}, {captures} captures"
    elif name in ("LOADK", "GETGLOBAL", "SETGLOBAL"):
        operands = f"R({a}) K({bx})"
    elif name in ("JMP", "FORLOOP", "FORPREP"):
        offset = bx - 131071
        operands = f"A={a} sBx={offset} ; target PC {pc + 1 + offset}"
    else:
        operands = f"A={a} B={b} C={c}"
        extra = name == "SETLIST" and c == 0
    result.append(prefix + f"{name:<12} {operands}")
if captures or extra:
    raise SystemExit("Truncated companion data at end of file")
destination.write_text("\n".join(result) + "\n", encoding="utf-8")
print(f"Saved: {destination}")
print(f"Checked {len(counts)} prototypes, {sum(counts.values())} raw words")
