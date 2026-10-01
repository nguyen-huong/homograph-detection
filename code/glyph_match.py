import difflib
import unicodedata

from PIL import Image, ImageDraw, ImageFont
import imagehash

# Only for rendering Unicode

GLYPH_SIZE = 64
ASCII_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

try:
    FONT = ImageFont.truetype("arial.ttf", GLYPH_SIZE)
except OSError:
    FONT = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf",GLYPH_SIZE)


def render_glyph(char):
    """Render a character as a centered grayscale image."""
    img = Image.new("L", (GLYPH_SIZE, GLYPH_SIZE), color=255)
    draw = ImageDraw.Draw(img)

    left, top, right, bottom = draw.textbbox((0, 0),char,font=FONT)

    width = right - left
    height = bottom - top
    x = (GLYPH_SIZE - width) / 2 - left
    y = (GLYPH_SIZE - height) / 2 - top

    draw.text((x, y),char,font=FONT,fill=0)
    return img


# perceptual hashes for ASCII characters.
ASCII_HASHES = {
    char: imagehash.phash(render_glyph(char))
    for char in ASCII_ALPHABET
}
cache = {}


def closest_ascii(char, max_distance=15):
    """
    Find the visually closest ASCII character to a given character.

    Returns:
        The closest ASCII character if its perceptual hash distance
        is within max_distance. Otherwise, returns None.
    """
    if char not in cache:
        char_hash = imagehash.phash(render_glyph(char))
        best_letter, best_distance = min(
            (
                (letter, char_hash - letter_hash)
                for letter, letter_hash in ASCII_HASHES.items()
            ),
            key=lambda pair: pair[1]
        )
        cache[char] = (
            best_letter
            if best_distance <= max_distance
            else None
        )

    return cache[char]


def visual_skeleton(string):
    decomposed = unicodedata.normalize("NFKD", string)

    # Remove combining marks such as accents.
    decomposed = "".join(
        char
        for char in decomposed
        if unicodedata.category(char) != "Mn"
    )

    skeleton_chars = []
    for char in decomposed:
        if ord(char) < 128:
            skeleton_chars.append(char)
            continue

        # Replace visually similar Unicode characters with ASCII.
        nearest = closest_ascii(char)
        if nearest is not None:
            skeleton_chars.append(nearest)
        else:
            skeleton_chars.append(char)
    return "".join(skeleton_chars)