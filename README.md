# Access Key Extractor

CLI tool for extracting NEX game server access keys from 3DS and Wii U dumps.

***This is not intended for use with games that do not use the Nintendo NEX libraries. Games which use the original Rendez-Vous library, or a derivative of it, may have different structures to their game server access keys.***

***This program may not work with all titles. If a title a non-standard game server access key format, or has custom implementations of the PPRUDPv0 checksum/PRUDPv1 signature algorithms, this tool will not find it's game server access key.***

## Usage

Either download the latest build from the [Releases](https://github.com/PretendoNetwork/access-key-extractor/releases) page, or `git clone` the source code locally. If downloading from source, the program may be used uncompiled using `go run main.go`.

To extract potential access keys for a title, the program has 2 modes; ROM scanning mode and bruteforcing mode. In most cases, ROM scanning mode is the correct mode.

### ROM Scanning Mode

This is the preferred mode, as it is the fastest of the 2 modes. This mode also almost always finds the original game server access key, as opposed to any valid key that happens to collide with the original.

Run the program with the `-rom` flag set to the path of the dump to scan. Dumps are expected to be the decompressed versions of the titles main executable. For the Wii U, this means decompressing the titles RPX (located in the `code/` folder) into an ELF (see [wiiurpxtool](https://github.com/0CBH0/wiiurpxtool)). For the 3DS, this means decompressing the titles `.code` section via GM9. Open the title in GM9 and select the largest `.app` file. Then select `NCCH image options > Extract .code`. This will dump the decompressed data to your SD card at `SD:/gm9/out/[titleid].dec.code` where `[titleid]` is the title ID of the title.

Depending on the size of the application and it's strings, this mode may find many multitudes of potential access keys. Providing a sample packet will reduce this number to only valid game server access keys.

If this mode fails to find any valid access keys, the title may not be storing the access key in the main executable (such as Metroid Prime: Federation Force, which stores it's key in its ROMFS). Move on to the bruteforcing mode.

***Example:***

```
./accesskeyextractor -rom=TerrariaWiiU.elf -packet=ead0011b0000afa1c0000000000047cdc13045c9fda980d5db81456feff1000404010000011000000000000000000000000000000000040100
```

### Bruteforcing Mode

This mode is not preferred over the ROM scanning mode. This mode is slower and uses more system resources compared to the ROM scanning mode, and should only be used when the ROM scanning mode fails.

Run the program with the `-bruteforce` flag and a sample packet. The program will try all game server access keys from `00000000` to `ffffffff` against the sample packet. The program will exit once `-stop-after` number of valid access keys has been found, defaulting to 1. This process is split into `-threads` number of goroutines, defaulting to `runtime.NumCPU()`. Setting this higher than your CPU core count may result in slowdowns.

This mode can be very slow depending on the title (some may have valid access keys very close to the end of the uint32 space) and on your system details (slower systems/less CPU cores will take longer). In a test running a 2024 Mac Mini with a 14 CPU core M4 Pro chip, it took around 2 minutes to find the Terraria game server access key.

If this mode fails to find any valid access keys, this indicates one of the following:

1. The `-packet` data is incorrect. Ensure you are using the correct packet
2. The games game server access key uses a different structure. Most known game server access keys used by NEX are 8 lowercase hex characters, however this just a convention set by Nintendo and not a limitation of the game clients/servers. Thus, this structure is not guranteed. The friends server game server access key is `ridfebb9`, which violates the convention, and there may be others which do as well. A game server access key may, technically, be any string up to 128 characters. The program only targets the standard NEX convention of game server access keys
3. The game uses non-standard PRUDP checksum/signature calculations. These functions are, technically, able to be overridden and customized. WATCH_DOGS on the Wii U for example uses it's own custom algorithm. The program only targets the standard NEX implementations of these calculation functions

In the 2nd and 3rd case, it is impossible for the program to find the game server access key and you will need to reverse engineer the game client to find it.

***Example:***

```
./accesskeyextractor -bruteforce -packet=ead0011b0000afa1c0000000000047cdc13045c9fda980d5db81456feff1000404010000011000000000000000000000000000000000040100
```

## Sample Packet

Providing a sample packet is optional for the ROM scanning mode, and required for the bruteforcing mode. This packet is passed to the program in the `-packet` flag, where the value is the hex encoded PRUDP `SYN` packet sent by the expected game client. To obtain the PRUDP `SYN` packet, create a basic UDP server using any method of your choosing and log the first packet the game sends. This is the target packet.

When a sample packet is provided, the program will loop over all potential access keys and run the checksum/signature calculations against the sample packet to find any valid access keys.

## Collision

The standard convention for NEX game server access keys is 8 lower case hex characters, and the sum of the access key bytes are used in the PRUDP signature/checksum calculations. Because of this, the program may find multiple valid access keys. When using the ROM scanning mode, the chances of a collision being found are extremely low, if not impossible, as the number of candidate access keys is very limited. Thus, you can be confident that if a valid access key is found, it is the original. However when using the bruteforcing mode, this is not guaranteed.

Since PRUDPv0 uses the sum of the access key bytes as part of the checksum calculation, and there are only 429 unique byte sums for the strings `00000000` to `ffffffff`, every game which uses PRUDPv0 will have multiple valid access keys. PRUDPv1 uses the access key directly, meaning every game which uses PRUDPv1 will have exactly 1 valid access key.

## Flags

| Name               | Description                                                                                                                                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-help`            | Show usage information                                                                                                                                                                                                                                         |
| `-rom`             | Optional. Path to game dump to scan. Not required if using `-bruteforce`                                                                                                                                                                                       |
| `-packet`          | Optional. Packet to test possible access keys against. Required if using `-bruteforce`                                                                                                                                                                         |
| `-prefer-encoding` | Optional. Reorder potential access keys to place those which use this encoding at the start of the list. Can be one of UTF8, UTF16BE, or UTF16LE. Will default to UTF16LE for 3DS .code dumps and UTF16BE for Wii U .elf dumps. Ignored if using `-bruteforce` |
| `-bruteforce`      | Optional. Bruteforce valid game server access keys without scanning a game dump. Valid access keys may not be the original access key. Requires `-packet` to be set. Will take a long time                                                                     |
| `-stop-after`      | Optional. Stop bruteforcing after finding this number of valid access keys. Defaults to 1. Setting to 0 will check all keys from 00000000-ffffffff                                                                                                             |
| `-threads`         | Optional. Number of goroutines to use during bruteforce searching. Defaults to `runtime.NumCPU()`. Setting this higher than your CPU core count may result in slowdowns                                                                                        |
