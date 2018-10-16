import os, sys
import codecs
import re
from datetime import datetime

arg_names = ['command', 'rom_path', 'encoding']
args = dict(zip(arg_names, sys.argv))

rom_path = args.get('rom_path')

if rom_path is None:
	print("Usage:")
	print("py extractor.py <path to 3dsrom.bin or wiiurom.elf> [encoding]")
	exit()

possible_keys = []
pos = 0

rom = codecs.open(rom_path, encoding=args.get('encoding') or 'UTF-16LE')
rom_size = os.path.getsize(rom_path)

def is_valid(string):
	# The access key is always lowercase, no need to allow uppercase hex chars
	return re.fullmatch(r'[0-9a-f]+', string) is not None

# https://stackoverflow.com/a/37630397
def progressBar(value, endvalue, bar_length=30):

	percent = float(value) / endvalue
	arrow = '-' * int(round(percent * bar_length)-1) + '>'
	spaces = ' ' * (bar_length - len(arrow))

	sys.stdout.write("\rProgress: [{0}] {1}%".format(arrow + spaces, int(round(percent * 100))))
	sys.stdout.flush()

startTime = datetime.now()

print("Scanning rom for possible keys... (this might take a while)")

# I'm sure this can be improved.
while True:
	progressBar(pos, rom_size, 30)

	try:
		chunk = rom.read(8)
		if not chunk:
			break

		if chunk not in possible_keys and is_valid(chunk):
			possible_keys.append(chunk)
	except UnicodeDecodeError:
		# silently skip the error chunk
		pass

	pos += 1
	rom.seek(pos)

print("\nPossible keys")
print(possible_keys)
print("Scan time: ", datetime.now() - startTime)
