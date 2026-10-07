import os
import re

def strip_comments(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    content = re.sub(r'', '', content)
    content = re.sub(r"", '', content)

    lines = content.split('\n')
    new_lines = []
    for line in lines:
        if line.strip().startswith('#'):
            continue
        if '#' in line:
            parts = line.split('#')
            if '"' not in parts[0] and "'" not in parts[0]:
                line = parts[0]
        new_lines.append(line.rstrip())

    content = '\n'.join(new_lines)
    content = re.sub(r'\n{3,}', '\n\n', content)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content.strip() + '\n')

for root, _, files in os.walk(r"C:\Users\Kenchi\Desktop\Projects for PC\PenTest"):
    if "venv" in root or "__pycache__" in root:
        continue
    for file in files:
        if file.endswith('.py'):
            strip_comments(os.path.join(root, file))
