#!/usr/bin/env python3
import argparse

# ------------------------------------------------------------
# load_layout(path)
# ------------------------------------------------------------
# Reads a keyboard layout from a text file.
# Each line represents a keyboard row, keys separated by spaces.
# Returns a 2D list (matrix) of keys.
# ------------------------------------------------------------
def load_layout(path):
    layout = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            row = line.strip().split()
            if row:
                layout.append(row)
    return layout


# ------------------------------------------------------------
# neighbors(layout, r, c)
# ------------------------------------------------------------
# Returns all adjacent keys (horizontal, vertical, diagonal)
# for the key at position (r, c).
# ------------------------------------------------------------
def neighbors(layout, r, c):
    h = len(layout)
    w = [len(row) for row in layout]
    adj = []

    for dr in [-1, 0, 1]:
        for dc in [-1, 0, 1]:
            if dr == 0 and dc == 0:
                continue
            nr, nc = r + dr, c + dc
            if 0 <= nr < h and 0 <= nc < w[nr]:
                adj.append((nr, nc))

    return adj


# ------------------------------------------------------------
# dfs(layout, r, c, depth, path, results)
# ------------------------------------------------------------
# Depth‑first search to generate all keyboard walks.
# path = current sequence of characters
# depth = target length
# When path reaches target length, store it.
# ------------------------------------------------------------
def dfs(layout, r, c, depth, path, results):
    if len(path) == depth:
        results.add("".join(path))
        return

    for nr, nc in neighbors(layout, r, c):
        dfs(layout, nr, nc, depth, path + [layout[nr][nc]], results)


# ------------------------------------------------------------
# generate(layout, min_len, max_len)
# ------------------------------------------------------------
# Generates all keyboard walks for lengths in the given range.
# Returns a set of all generated strings.
# ------------------------------------------------------------
def generate(layout, min_len, max_len):
    results = set()

    for r in range(len(layout)):
        for c in range(len(layout[r])):
            for length in range(min_len, max_len + 1):
                dfs(layout, r, c, length, [layout[r][c]], results)

    return results


# ------------------------------------------------------------
# main()
# ------------------------------------------------------------
# Linux‑style CLI interface using argparse.
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Maximalistic keyboard-walk generator (layout-aware)"
    )

    parser.add_argument(
        "--layout",
        required=True,
        help="Path to keyboard layout file (2D array, space-separated)"
    )

    parser.add_argument(
        "--min",
        type=int,
        default=4,
        help="Minimum walk length (default: 4)"
    )

    parser.add_argument(
        "--max",
        type=int,
        default=10,
        help="Maximum walk length (default: 10)"
    )

    args = parser.parse_args()

    layout = load_layout(args.layout)
    words = generate(layout, args.min, args.max)

    for w in words:
        print(w)


if __name__ == "__main__":
    main()
