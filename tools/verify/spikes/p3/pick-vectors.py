# Picks the four signature vectors that brev-proto's tests commit
# (core/brev-proto/src/test_keys.rs) from the output of sigspike.
# Usage: python3 pick-vectors.py sigs.txt vectors.txt
# Prints the count per (kind, variant, DER length, high-S) and the picks.
import sys, collections
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
def der_rs(d):
    assert d[0] == 0x30 and d[1] == len(d) - 2
    assert d[2] == 2; rl = d[3]; r = int.from_bytes(d[4:4+rl], 'big')
    i = 4 + rl; assert d[i] == 2; sl = d[i+1]; s = int.from_bytes(d[i+2:i+2+sl], 'big')
    assert i + 2 + sl == len(d)
    return r, s, rl, sl
stats = collections.Counter()
rows = []
for line in open(sys.argv[1]):
    kind, variant, key, msg, der = line.split()
    d = bytes.fromhex(der); r, s, rl, sl = der_rs(d)
    high = s > N // 2
    stats[(kind, variant, len(d), high)] += 1
    rows.append((kind, variant, key, msg, der, len(d), high, len(msg)//2, rl, sl))
for k, v in sorted(stats.items()): print(k, v)
def first(pred):
    for r in rows:
        if pred(r): return r
# Digest variant (what Brev's Swift side signs), 366-byte messages (the
# shortest the spike made).
picks = {
 'software-low': first(lambda r: r[0]=='software' and r[1]=='digest' and not r[6] and r[7]==366 and r[5]==70),
 'software-high': first(lambda r: r[0]=='software' and r[1]=='digest' and r[6] and r[7]==366),
 'enclave': first(lambda r: r[0]=='enclave-seckey' and r[1]=='digest' and r[6] and r[7]==366),
 'der69': first(lambda r: r[5]==69 and r[7]==366) or first(lambda r: r[5]==69),
}
with open(sys.argv[2], 'w') as f:
    for name, r in picks.items():
        print(name, r[0], r[1], 'derlen', r[5], 'high', r[6], 'msglen', r[7], 'rl', r[8], 'sl', r[9])
        f.write(' '.join(r[:5]) + '\n')
