# Access Key Extractor

Extracts server access keys from 3DS and Wii U ROM dumps

## Usage

`go run main.go <rom-path> [test-packet]`

## Arguments

- `rom-path` ***Required***. The path to the game dump. For the Wii U, this must be a decompressed `.elf` of the RPX. For the 3DS, this must be the titles decompressed `.code`. See [Notes](#notes) for more info
- `test-packet` ***Optional***. A PRUDP packet to test found access keys against. For simplicity, the packet is expected to be of type `SYN`

## Notes

- Access keys are always 8 lowercase hex characters, except for the Friends server access key. Because of this, this may return multiple possible keys. You may provide a test packet to attempt to find the exact access key, or try all returned possible keys one by one
- To get the access key for a Wii U title you must first decompress the RPX file in the `code/` folder of the decrypted title into an ELF, then run the extractor on the ELF. See [Wii Urpxtool](https://github.com/0CBH0/Wii Urpxtool)
- To get the access key for a 3DS title you must first decompress the games `.code` section. Open the title in GM9 and select the largest `.app` file. Then select `NCCH image options > Extract .code`. This will dump the decompressed data to your SD card at `SD:/gm9/out/[titleid].dec.code` where `[titleid]` is the title ID of the title