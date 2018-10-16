# Access Key Extractor

Extracts server access keys from 3DS and WiiU dumps

## Usage

`py extractor.py <path to 3dsrom.bin or wiiurom.elf> [encoding]`

## Arguments

- `path to 3dsrom.bin or wiiurom.elf` The path to the game dump [Required]
- `encoding` Encoding to read the file with. Defaults to UTF-16LE [Optional]

## Notes

- This was tested with Python 3.6.2, it may not work in older/newer versions of Python.
- `encoding` defaults to UTF-16LE, which seems to work for all games, but is still an option just in case.
- Not all games store the server access key in the rom. Because of this, this script may not return any usable outputs. For example, Metroid Prime FF (3DS) keeps it's server access key in `romfs/ini/skuinfo/`
- Access keys are always 8 lowercase hex chars, with the exception of the Friends server access key. Because of this, this script may return multiple possible keys (trial and error is your friend).
- To get the access key for a WiiU title you must first decompress the RPX file in the `code/` folder of the decrypted title into an ELF, then run the extractor on the ELF.