"""Structured views of bounded GNU tool output; no sample execution."""

import re


def readelf_tables(raw):
    sections, symbols, segments = [], [], []
    for line in raw.get('sections', {}).get('text', '').splitlines():
        match = re.match(r'\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+\S+\s*(.*?)\s+\d+\s+\d+\s+\d+\s*$', line)
        if match and int(match[1]) > 0:
            _, name, kind, address, offset, size, flags = match.groups()
            sections.append({'name': name, 'type': kind, 'address': hex(int(address, 16)),
                             'offset': int(offset, 16), 'size': int(size, 16), 'permissions': flags.strip()})
    for line in raw.get('symbols', {}).get('text', '').splitlines():
        match = re.match(r'\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s*(.*)', line)
        if match:
            address, size, kind, binding, index, name = match.groups()
            symbols.append({'name': name, 'address': hex(int(address, 16)), 'size': int(size),
                            'type': 'STT_' + kind, 'binding': binding,
                            'direction': 'import' if index == 'UND' else 'defined/export candidate'})
    for line in raw.get('segments', {}).get('text', '').splitlines():
        match = re.match(r'\s*(\S+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+([RWE ]+)\s+0x[0-9a-fA-F]+', line)
        if match:
            kind, offset, address, size, memory, perms = match.groups()
            flags = sum(value for char, value in [('R', 4), ('W', 2), ('E', 1)] if char in perms)
            segments.append({'type': kind, 'offset': int(offset, 16), 'address': address,
                             'file_size': int(size, 16), 'memory_size': int(memory, 16),
                             'flags': flags, 'permissions': perms.strip().replace(' ', '').replace('E', 'X')})
    dependencies = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', raw.get('dependencies', {}).get('text', ''))
    return {'sections': sections[:20000], 'symbols': symbols[:20000],
            'segments': segments[:20000], 'dependencies': dependencies[:20000]}


def objdump_rows(text):
    rows, section, function = [], '', ''
    for line in text.splitlines():
        heading = re.match(r'Disassembly of section (.+):', line)
        label = re.match(r'[0-9a-fA-F]+ <(.+)>:', line)
        instruction = re.match(r'\s*([0-9a-fA-F]+):\t([^\t]+)\t\s*(\S+)(?:\s+(.*))?$', line)
        if heading:
            section = heading[1]
        elif label:
            function = label[1]
        elif instruction:
            address, data, mnemonic, operands = instruction.groups()
            rows.append({'address': hex(int(address, 16)), 'bytes': ''.join(data.split()),
                         'mnemonic': mnemonic, 'operands': operands or '', 'section': section,
                         'function': function})
            if len(rows) >= 20000:
                break
    return rows
