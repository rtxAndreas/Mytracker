#!/usr/bin/env python3
import argparse
import sys
import signal

from charset import PRESETS, generate, resolve_charset

signal.signal(signal.SIGPIPE, signal.SIG_DFL)

def main():
    presets_help = ", ".join(sorted(PRESETS))
    parser = argparse.ArgumentParser(
        description="Generate all possible password combinations from a charset.")
    parser.add_argument("--charset", default="alphanumeric",
                        help=f"Character set or preset name ({presets_help}) "
                             "(default: alphanumeric)")
    parser.add_argument("--min", type=int, default=8,
                        help="Minimum password length (default: 8)")
    parser.add_argument("--max", type=int, default=8,
                        help="Maximum password length (default: 8)")
    parser.add_argument("--limit", type=int, default=0,
                        help="Stop after this many passwords (0 = unlimited)")
    args = parser.parse_args()

    charset = resolve_charset(args.charset)

    if args.min < 1:
        print("error: --min must be >= 1", file=sys.stderr)
        sys.exit(1)
    if args.max < args.min:
        print("error: --max must be >= --min", file=sys.stderr)
        sys.exit(1)

    count = 0
    for pw in generate(charset, args.min, args.max):
        print(pw)
        count += 1
        if args.limit and count >= args.limit:
            break


if __name__ == "__main__":
    main()
