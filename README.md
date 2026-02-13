# Access Key Extractor

CLI tool for extracting NEX game server access keys from 3DS and Wii U dumps.

***This is not intended for use with games that do not use the Nintendo NEX libraries. Games which use the original Rendez-Vous library, or a derivative of it, may have different structures to their game server access keys.***

***This program may not work with all titles. If a title stores it's game server access key outside of the main executable, such as Metroid Prime: Federation Force which stores it's key in the game ROMFS, then this program will not find it.***

## Usage

Either download the latest build from the [Releases](https://github.com/PretendoNetwork/access-key-extractor/releases) page, or `git clone` the source code locally. If downloading from source, the program may be used uncompiled using `go run main.go`.

To extract potential access keys for a title, run the program with the `-rom` flag set to the path of the dump to scan. Dumps are expected to be the decompressed versions of the titles main executable. For the Wii U, this means decompressing the titles RPX (located in the `code/` folder) into an ELF (see [wiiurpxtool](https://github.com/0CBH0/wiiurpxtool)). For the 3DS, this means decompressing the titles `.code` section via GM9. Open the title in GM9 and select the largest `.app` file. Then select `NCCH image options > Extract .code`. This will dump the decompressed data to your SD card at `SD:/gm9/out/[titleid].dec.code` where `[titleid]` is the title ID of the title.

NEX game server access keys are always 8 lowercase hex characters, with the exception of the friends server whose game server access key is `ridfebb9`. Because of this, the program may return many multitudes of possible keys. In cases where a large number of potential game server access keys are found, pass the `-packet` flag set to a hex encoded PRUDP `SYN` packet sent by the game client. To obtain the PRUDP `SYN` packet, create a basic UDP server and log the first packet the game sends. This is the target packet. If a packet is provided, the program will loop over all potential keys and check them against the packet, returning any successful matches.

***Example:***

```
go run main.go -rom=TerrariaWiiU.elf -packet=ead0011b0000afa1c0000000000047cdc13045c9fda980d5db81456feff1000404010000011000000000000000000000000000000000040100
```

```
go run main.go -bruteforce -packet=ead0011b0000afa1c0000000000047cdc13045c9fda980d5db81456feff1000404010000011000000000000000000000000000000000040100
```

## Flags

| Name               | Description                                                                                                                                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-help`            | Show usage information                                                                                                                                                                                                                                         |
| `-rom`             | Optional. Path to game dump to scan. Not required if using `-bruteforce`                                                                                                                                                                                       |
| `-packet`          | Optional. Packet to test possible access keys against. Required if using `-bruteforce`                                                                                                                                                                         |
| `-prefer-encoding` | Optional. Reorder potential access keys to place those which use this encoding at the start of the list. Can be one of UTF8, UTF16BE, or UTF16LE. Will default to UTF16LE for 3DS .code dumps and UTF16BE for Wii U .elf dumps. Ignored if using `-bruteforce` |
| `-bruteforce`      | Optional. Bruteforce valid game server access keys without scanning a game dump. Valid access keys may not be the original access key. Requires `-packet` to be set. Will take a long time                                                                     |
| `-stop-after`      | Optional. Stop bruteforcing after finding this number of valid access keys. Defaults to 1. Setting to 0 will check all keys from 00000000-ffffffff                                                                                                             |

