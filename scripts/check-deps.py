import json
import re
import subprocess
import sys

def main():
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--all-features", "--format-version", "1"]))
    packages = {p["name"]: p["version"] for p in meta["packages"]}

    with open("DEPENDENCIES.md", "r", encoding="utf-8") as f:
        content = f.read()

    tool_exclusions = {"cargo-deny", "gitleaks", "semgrep"}
    row_pattern = re.compile(r"\|\s*`([a-zA-Z0-9_\-]+)`\s*\|\s*`([^`]+)`\s*\|")
    rows = row_pattern.findall(content)

    errors = []
    checked = 0
    for name, ver in rows:
        if name in tool_exclusions:
            continue
        checked += 1
        if name not in packages:
            errors.append(f"Phantom crate in DEPENDENCIES.md: '{name}'")
        elif packages[name] != ver and not (name == "libc" and ver == "0.2"):
            if not packages[name].startswith(ver):
                errors.append(f"Version drift for '{name}': DEPENDENCIES.md='{ver}', cargo metadata='{packages[name]}'")

    if errors:
        print("DEPENDENCIES.md verification failed:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    print(f"deps-check passed: successfully verified {checked} crates against cargo metadata.")

if __name__ == "__main__":
    main()
