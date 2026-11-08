"""Restore the verified S09 delivery; never modify other repositories."""
from pathlib import Path, PurePosixPath
from urllib.request import urlopen, Request
from zipfile import ZipFile, ZIP_DEFLATED
import base64, hashlib, json, lzma, struct, zlib

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = 'aaa1e13ceb0bf91c7f7eab9130b7494b2d5c62141b60966822fdfc5647b5fa22'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def compress(data):
    c = zlib.compressobj(6, zlib.DEFLATED, 15, 9, 0)
    return c.compress(data) + c.flush()

def pixels(png):
    """Decode this RGB8, non-interlaced PNG using only the standard library."""
    if png[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('Invalid PNG signature')
    pos, data = 8, bytearray()
    while pos < len(png):
        length = struct.unpack('>I', png[pos:pos+4])[0]
        kind, chunk = png[pos+4:pos+8], png[pos+8:pos+8+length]
        if kind == b'IHDR':
            w, h, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', chunk)
            if (depth, color, compression, filtering, interlace) != (8, 2, 0, 0, 0):
                raise ValueError('Unexpected PNG encoding')
        elif kind == b'IDAT':
            data.extend(chunk)
        pos += length + 12
    scan, stride = zlib.decompress(data), w * 3
    if len(scan) != h * (stride+1):
        raise ValueError('Unexpected PNG data length')
    out, prior, offset = bytearray(), bytearray(stride), 0
    for _ in range(h):
        mode = scan[offset]
        row = bytearray(scan[offset+1:offset+1+stride])
        offset += stride+1
        for i in range(stride):
            a, b, c = (row[i-3] if i >= 3 else 0), prior[i], (prior[i-3] if i >= 3 else 0)
            if mode == 0: predictor = 0
            elif mode == 1: predictor = a
            elif mode == 2: predictor = b
            elif mode == 3: predictor = (a+b)//2
            elif mode == 4:
                p = a+b-c
                pa, pb, pc = abs(p-a), abs(p-b), abs(p-c)
                predictor = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
            else: raise ValueError('Unknown PNG filter')
            row[i] = (row[i] + predictor) & 255
        out.extend(row)
        prior = row
    return bytes(out)

def main():
    parts = sorted((ROOT/'.build').glob('part_*.txt'))
    packed = base64.b64decode(''.join(p.read_text().strip() for p in parts), validate=True)
    if sha(packed) != EXPECTED:
        raise ValueError('Transfer checksum mismatch; no files were written')
    payload = lzma.decompress(packed)
    count = struct.unpack('>I', payload[:4])[0]
    manifest = json.loads(payload[4:4+count])
    literals = payload[4+count:]
    bases = {}
    for name, expected in manifest['base_hashes'].items():
        req = Request(manifest['base_url']+name, headers={'User-Agent':'S09-verified-transfer'})
        with urlopen(req, timeout=60) as response:
            data = response.read()
        if sha(data) != expected:
            raise ValueError('Reference checksum mismatch: '+name)
        bases[name] = data
    restored, images = {}, {}
    for name, info in manifest['files'].items():
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('Unsafe destination')
        chunks = []
        for part in info['parts']:
            if part[0] == 'L': chunks.append(literals[part[1]:part[1]+part[2]])
            elif part[0] == 'B': chunks.append(bases[part[1]][part[2]:part[3]])
            elif part[0] == 'Z': chunks.append(compress(literals[part[1]:part[1]+part[2]]))
            elif part[0] == 'I':
                if part[1] not in images: images[part[1]] = compress(pixels(bases[part[1]]))
                chunks.append(images[part[1]])
            else: raise ValueError('Unknown recipe')
        data = b''.join(chunks)
        if len(data) != info['size'] or sha(data) != info['sha256']:
            raise ValueError('Output checksum mismatch: '+name)
        restored[name] = data
    # Write only after ALL 13 files match the original delivery exactly.
    for name, data in restored.items():
        destination = ROOT/name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    archive = ROOT/'S09_Document_pret_a_rendre.zip'
    with ZipFile(archive, 'w', compression=ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in restored.items(): z.writestr(name, data)
    with ZipFile(archive) as z:
        if z.testzip() is not None: raise ValueError('Archive integrity check failed')
        for name, data in restored.items():
            if z.read(name) != data: raise ValueError('Archive content mismatch')
    (ROOT/'SHA256SUMS.txt').write_text('\n'.join(sha(d)+'  '+n for n,d in restored.items())+'\n'+sha(archive.read_bytes())+'  '+archive.name+'\n', encoding='utf-8')
    print('SUCCESS:', len(restored), 'files restored byte-for-byte; archive integrity verified.')

if __name__ == '__main__':
    main()
