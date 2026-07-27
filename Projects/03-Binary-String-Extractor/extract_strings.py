import sys
import os

def extract(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # Simple ASCII string extraction
        strings = []
        current_str = bytearray()
        
        for byte in data:
            if 32 <= byte <= 126: # printable ASCII
                current_str.append(byte)
            else:
                if len(current_str) >= 4:
                    strings.append(current_str.decode('ascii'))
                current_str = bytearray()
                
        if len(current_str) >= 4:
             strings.append(current_str.decode('ascii'))
        
        print(f"--- Extracted from {os.path.basename(filepath)} ---")
        for s in strings:
            if 'api_' in s or 'Show' in s or 'Clear' in s or 'Monster' in s or 'Kill' in s or 'Buff' in s:
                print(s)
    except Exception as e:
        print(f"Error reading {filepath}: {e}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        extract(sys.argv[1])
