from PIL import Image
from utils import bits_to_text

def decode_image(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    width, height = img.size
    bits = ""
    for y in range(height):
        for x in range(width):
            r, g, b = img.getpixel((x, y))
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)
    from utils import bits_to_text
    return bits_to_text(bits)

