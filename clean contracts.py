import os
import re

INPUT_DIR = "labelled_dataset"
OUTPUT_DIR = "unlabelled_dataset"

def clean_contract(source):
    # Remove multiline metadata comment blocks
    source = re.sub(
        r'/\*.*?(?:@source|@vulnerable_at_lines|@author).*?\*/',
        '',
        source,
        flags=re.DOTALL
    )

    lines = []
    for line in source.splitlines():
        # Remove lines with metadata tags
        if re.search(r'@vulnerable_at_lines|@source|@author', line):
            continue
        # Remove SmartBugs tags like // <yes>
        line = re.sub(r'//\s*<.*?>.*', '', line)
        lines.append(line)

    # Remove first two empty or whitespace-only lines
    while lines and lines[0].strip() == '':
        lines.pop(0)
    if lines and lines[0].strip() == '':
        lines.pop(0)

    return "\n".join(lines)

for root, _, files in os.walk(INPUT_DIR):
    for file in files:
        if file.endswith(".sol"):
            input_path = os.path.join(root, file)

            # Derive relative path and output path
            rel_path = os.path.relpath(input_path, INPUT_DIR)
            output_path = os.path.join(OUTPUT_DIR, rel_path)

            # Ensure output subdirectory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # Clean and save
            with open(input_path, "r", encoding="utf-8") as f:
                source = f.read()
            cleaned = clean_contract(source)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(cleaned)

print(f"Unlabelled dataset created at: {OUTPUT_DIR}")
