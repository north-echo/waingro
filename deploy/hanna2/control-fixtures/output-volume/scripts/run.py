import os

block = b"WAINGRO_OUTPUT_CONTROL\n" * 2048
while True:
    os.write(1, block)
