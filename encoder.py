from PIL import Image
from utils import text_to_bits

def load_image(path):
    img = Image.open(path)
    img = img.convert("RGB")
    return img

def encode_image(img, message_bits, output_path):
    encoded = img.copy()
    width, height = img.size
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx < len(message_bits):
                r, g, b = img.getpixel((x, y))
                if idx < len(message_bits):
                    r = (r & ~1) | int(message_bits[idx])
                    idx += 1
                if idx < len(message_bits):
                    g = (g & ~1) | int(message_bits[idx])
                    idx += 1
                if idx < len(message_bits):
                    b = (b & ~1) | int(message_bits[idx])
                    idx += 1
                encoded.putpixel((x, y), (r, g, b))
    encoded.save(output_path)
    print(f"Message encoded successfully into {output_path}")