#!/usr/bin/env python3
"""Generate a bcrypt hash for a given key.

Usage:
  python tools/hash_key.py "my-plaintext-key"

It prints a bcrypt hash to stdout which can be placed in `API_KEYS_FILE`.
"""
import sys
import bcrypt


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/hash_key.py <plaintext-key>")
        sys.exit(2)
    key = sys.argv[1].encode()
    hashed = bcrypt.hashpw(key, bcrypt.gensalt())
    print(hashed.decode())


if __name__ == "__main__":
    main()
