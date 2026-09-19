import sys

file_path = "internal/pipeline/pipeline.go"
with open(file_path, "r") as f:
    lines = f.readlines()

new_lines = []
in_soft_stages = False
for line in lines:
    new_lines.append(line)
    if 'softStages = map[string]bool{' in line:
        in_soft_stages = True
    if in_soft_stages and '}' in line:
        # Insert the new soft stages before the closing brace
        # But first, remove the newline from the closing brace line to insert before it
        closing_brace_line = line
        # we need to check if the previous line had a comma
        # but it's easier to just find the line before the brace.
        # Wait, I can just insert before the closing brace.
        in_soft_stages = False
        # We already added the closing brace line, so we need to insert before it.
        # Let's fix the list.
        pass

# A better way: replace the closing brace of softStages with the new entries + closing brace
# The closing brace for softStages is around line 114.
