# Access Key Extractor

Extracts server access keys from 3DS and WiiU ROM dumps

## Usage

`node extractor <path> [packet]`

## Arguments

- `path` The path to the game dump (WiiU ROM decompressed ELF or 3DS ROM bin) [Required]
- `packet` A PRUDP packet to test found access keys against. For simplicity, the packet is expected to be of type SYN [Optional]

## Notes

- Encoding defaults to utf16le, which seems to work for all titles. Has not been tested on every title
- Access keys are always 8 lowercase characters a-f0-9, except for the Friends server access key. Because of this, this may return multiple possible keys. You may provide a test packet to attempt to find the exact access key, or try all returned possible keys one by one
- To get the access key for a WiiU title you must first decompress the RPX file in the `code/` folder of the decrypted title into an ELF, then run the extractor on the ELF. See [wiiurpxtool](https://github.com/0CBH0/wiiurpxtool)