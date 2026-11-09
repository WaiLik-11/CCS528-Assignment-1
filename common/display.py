"""Console formatting helpers shared by the task walkthroughs."""

COLOUR_CODES = {
    "grey": "\033[90m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
}

def section(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)

def preview(data: bytes, n: int = 16) -> str:
    return f"{data[:n].hex()}... ({len(data)} bytes)"

def flip_bit(data: bytes, index: int = 0, bit: int = 0) -> bytes:
    """Return a copy of data with one bit of byte `index` inverted."""
    index %= len(data)
    return data[:index] + bytes([data[index] ^ (1 << bit)]) + data[index + 1:]

def format_colour(message: str, colour: str = "grey") -> str:
    return f"{COLOUR_CODES.get(colour, '')}{message}\033[0m"

def boolean_colour(value: bool) -> str:
    return format_colour(str(value), "green" if value else "red")
