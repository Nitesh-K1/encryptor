def text_to_bits(message):
    message = message + "<<<END>>>"
    return ''.join(format(ord(char), '08b') for char in message)

def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    message = ''.join([chr(int(c, 2)) for c in chars])
    return message.split("<<<END>>>")[0]
