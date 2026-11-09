"""Create an analysis copy with standard Lua 5.1 opcode numbers.

Usage: python3 normalize_opcodes.py INPUT.lua OUTPUT.luac
Reads luad facts for byte offsets; never executes target Lua or overwrites INPUT.
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 3:
    raise SystemExit(__doc__)
source, destination = map(Path, sys.argv[1:])
if source.resolve() == destination.resolve():
    raise SystemExit("INPUT and OUTPUT must differ")
original = source.read_bytes()
if original[:12] != bytes.fromhex("1b4c75615100010404040804"):
    raise SystemExit("This helper supports only the observed Lua 5.1 LNUM32 LE layout")
mapping = json.loads(Path(__file__).with_name("tplink-opcode-map.json").read_text())
standard = ("MOVE LOADK LOADBOOL LOADNIL GETUPVAL GETGLOBAL GETTABLE SETGLOBAL "
            "SETUPVAL SETTABLE NEWTABLE SELF ADD SUB MUL DIV MOD POW UNM NOT LEN "
            "CONCAT JMP EQ LT LE TEST TESTSET CALL TAILCALL RETURN FORLOOP "
            "FORPREP TFORLOOP SETLIST CLOSE CLOSURE VARARG").split()
if len(mapping) != 38 or set(mapping.values()) != set(standard):
    raise SystemExit("Opcode map must be a permutation of all 38 standard Lua 5.1 opcodes")
tool = Path.home() / "ax10-analysis/tools/luad-0.4.1-linux-x86_64/luad"
export = subprocess.run([str(tool), "export", str(source), "--format", "jsonl",
                         "--facts", "prototype,instruction"], text=True, capture_output=True)
# luad returns 5 for a parsed chunk that fails stock VM validation.
if export.returncode not in (0, 5):
    raise SystemExit(export.stderr)
prototypes, instructions = {}, {}
source_hash = hashlib.sha256(original).hexdigest()
for line in export.stdout.splitlines():
    record = json.loads(line)
    kind, data = record.get("record_type"), record.get("data", {})
    if kind in ("prototype", "instruction"):
        identity = record["context"]["input_identity"]
        if identity["sha256"] != source_hash:
            raise SystemExit("Fact input hash mismatch")
    if kind == "prototype":
        prototypes[data["id"]] = data
    elif kind == "instruction":
        proto = data["id"].rsplit(":pc:", 1)[0]
        instructions.setdefault(proto, []).append(data)
if not prototypes or set(prototypes) != set(instructions):
    raise SystemExit("Incomplete prototype export")

output = bytearray(original)
mapped_offsets, changed, extras, captures_total = set(), 0, 0, 0
for proto, metadata in prototypes.items():
    words = sorted(instructions[proto], key=lambda item: item["pc"])
    if [item["pc"] for item in words] != list(range(metadata["instructions_count"])):
        raise SystemExit(f"Incomplete raw words for {proto}")
    captures, extra = 0, False
    for item in words:
        word, offset = item["raw_word"], item["source"]["byte_offset"]
        if struct.unpack_from("<I", original, offset)[0] != word:
            raise SystemExit("Raw word / byte offset mismatch")
        if extra:
            extras += 1
            extra = False
            continue
        name = mapping.get(str(word & 63))
        if name not in standard:
            raise SystemExit(f"Unknown opcode at {item['id']}")
        if captures:
            if name not in ("MOVE", "GETUPVAL"):
                raise SystemExit(f"Unexpected closure capture at {item['id']}")
            captures -= 1
            captures_total += 1
        elif name == "CLOSURE":
            child = f"{proto}/{word >> 14}"
            if child not in prototypes:
                raise SystemExit(f"Missing child metadata: {child}")
            captures = prototypes[child]["upvalues_count"]
        elif name == "SETLIST" and ((word >> 14) & 511) == 0:
            extra = True
        if offset in mapped_offsets:
            raise SystemExit("Duplicate instruction byte offset")
        mapped_offsets.add(offset)
        normalized = (word & ~63) | standard.index(name)
        struct.pack_into("<I", output, offset, normalized)
        changed += normalized != word
    if captures or extra:
        raise SystemExit(f"Truncated companion data in {proto}")

if len(output) != len(original):
    raise SystemExit("Unexpected output length change")
for offset, (before, after) in enumerate(zip(original, output)):
    if before != after and (offset not in mapped_offsets or (before ^ after) & 0xC0):
        raise SystemExit("Change outside opcode bits")
if source.read_bytes() != original:
    raise SystemExit("Source changed during analysis")
destination.write_bytes(output)
print(f"Saved analysis copy: {destination}")
print(f"Prototypes: {len(prototypes)}; raw words: {sum(p['instructions_count'] for p in prototypes.values())}")
print(f"Changed opcode words: {changed}; closure captures remapped: {captures_total}; SETLIST data preserved: {extras}")
print(f"Original SHA256: {source_hash}")
print(f"Copy SHA256:     {hashlib.sha256(output).hexdigest()}")
