import os
import re

def extract_strings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Simple regex for strings (min length 4)
    strings = re.findall(b'[a-zA-Z0-9_/]{4,}', data)
    return [s.decode('ascii', errors='ignore') for s in strings]

def main():
    root_dir = r"D:\unpack\extracted\extracted"
    target_pattern = ["System", "Chat", "Actor", "Player", "print"]
    
    count = 0
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".lua"):
                path = os.path.join(root, file)
                strs = extract_strings(path)
                
                found = []
                for s in strs:
                    for p in target_pattern:
                        if p.lower() in s.lower():
                            found.append(s)
                
                if found:
                    print(f"File: {path}")
                    for f in list(set(found))[:10]:
                        print(f"  String: {f}")
                    count += 1
                    if count > 20:
                        return

if __name__ == "__main__":
    main()
