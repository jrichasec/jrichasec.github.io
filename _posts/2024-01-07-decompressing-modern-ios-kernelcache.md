## Decompressing the iOS KernelCache

Apple stopped encrypting the kernelcache in iOS 10, however, the kernelcache is still stored in a compressed format within the ipsw package, in this blog we'll be taking a look at how to extract, decompress and decompile the kernelcache for reverse engineering.  We'll also take a look at ghidra_kernelcache to assist with symbolication in ghidra.  

---

### Kernelcache Extraction

The kernelcache resides within the .ipsw.  Rename the .ipsw to a .zip file and extract it.

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ unzip ipsw.zip 
Archive:  ipsw.zip
 extracting: 078-33721-080.dmg       
  inflating: 078-33939-081.dmg       
  inflating: 078-34285-081.dmg       
[snipped]
```

There may be two kernelcache files extracted from the .ipsw:

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ find . | grep kernelcache
./kernelcache.release.iphone9
./kernelcache.release.iphone10
```

In this example I'll be using the ./kernelcache.release.iphone10 file as that algins with kernel running on the device:

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ ssh mobile@192.168.68.104 uname -a 
Darwin Jacks-iPhone 21.6.0 Darwin Kernel Version 21.6.0: Wed Aug 10 15:38:24 PDT 2022; root:xnu-8020.142.2~1/RELEASE_ARM64_T8015 iPhone10,1 arm Darwin
```

### Kernelcache Decompression

On initial analysis with off-the-shelf tools like "file" and "binwalk", there are no magic bytes found.

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ file kernelcache.release.iphone10
kernelcache.release.iphone10: data
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ binwalk kernelcache.release.iphone10

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ 
```

When we manually take a look at the header structure using xxd, the following can be observed;

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ xxd kernelcache.release.iphone10  | head -10
00000000: 3083 ec39 c416 0449 4d34 5016 046b 726e  0..9...IM4P..krn
00000010: 6c16 254b 6572 6e65 6c43 6163 6865 4275  l.%KernelCacheBu
00000020: 696c 6465 725f 7265 6c65 6173 652d 3232  ilder_release-22
00000030: 3338 2e31 3230 2e32 0483 ec39 8162 7678  38.120.2...9.bvx
00000040: 3214 c500 0080 3ad0 3d03 960a 309d b75f  2.....:.=...0.._
00000050: bdfd 2215 40c6 0000 003d 10c0 05f7 87ab  ..".@....=......
00000060: aa51 5555 05d6 5e77 174d a259 d147 e0bc  .QUU..^w.M.Y.G..
00000070: 8e71 9383 c3ae 93ae 1edc b47b 8db5 563b  .q.........{..V;
00000080: 471d 6d9b 24da b6a9 2a02 00f0 40fc 03a7  G.m.$...*...@...
00000090: efc2 e9c1 c93c b998 f360 8d83 35c6 581d  .....<...`..5.X.

```

This aligns with the IMG4 payload described on the iphone wiki (https://www.theiphonewiki.com/wiki/IMG4_File_Format), in our case, the payload will look something like the following

```
sequence [
   0: string: "IM4P"
   1: string type: "krnl"
   2: string description: "KernelCacheBuilder_release-2238.120.2"
   3: octetstring: raw_data
   4: octetstring    - containing DER encoded KBAG values (Not applicable to us, since kernelcache is no longer encrypted)
         sequence [
            sequence [
                0: int: 01
                1: octetstring: iv
                2: octetstring: key
            ]
            sequence [
                0: int: 02
                1: octetstring: iv
                2: octetstring: key
            ]
         ]
      ]
```

Near the start of the raw_data section, we can observe a ```bvx2``` string in the hex dump, by taking a look at the list of file signatures on wikipedia (https://en.wikipedia.org/wiki/List_of_file_signatures), we can see that bvx2 are the magic bytes for an lzfse compressed blob.  From wikipedia: "LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding. OSS by Apple."

Luckily for us, there's an lzfse.h header we can use to perform decompression on the blob.  
  
With help from ChatGPT I managed to wangle the following C code together.  It's a fairly simple program with the following steps:

* Open compressed kernelcache file
* Seek to the first instance of the bvx2 magic bytes (0x62, 0x76, 0x78, 0x32)
* Copy everything from there until EOF into a buffer in memory
* Decompress the buffer using lzfse_decode_buffer from lzfse.h 
* Write the decompressed buffer to an output file



```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lzfse.h"

#define PATTERN_SIZE 4
#define BUFFER_SIZE 1024

// Function to decode with LZFSE and write to a file
void decode_and_write(const unsigned char *data, size_t size, const char *output_filename) {
    size_t out_size = size * 4;  // Estimate the maximum possible decompressed size
    unsigned char *out_buffer = malloc(out_size);

    if (!out_buffer) {
        fprintf(stderr, "Failed to allocate memory for output buffer\n");
        return;
    }

    size_t decompressed_size = lzfse_decode_buffer(out_buffer, out_size, data, size, NULL);
    if (decompressed_size == 0) {
        fprintf(stderr, "Decompression failed or output buffer too small\n");
    } else {
        FILE *out_file = fopen(output_filename, "wb");
        if (!out_file) {
            perror("Failed to open output file");
        } else {
            fwrite(out_buffer, 1, decompressed_size, out_file);
            fclose(out_file);
            printf("Data decompressed and written to %s\n", output_filename);
        }
    }

    free(out_buffer);
}

// Function to find the pattern and copy from offset to end of file
void find_pattern_and_process(FILE *file, const char *output_filename) {
    unsigned char pattern[PATTERN_SIZE] = {0x62, 0x76, 0x78, 0x32}; // Byte pattern to search for
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;
    int found = 0;

    // Create a buffer to hold data from the offset to the end of the file
    unsigned char *data_buffer = NULL;
    size_t data_size = 0;

    // Read chunks of the file
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0 && !found) {
        for (size_t i = 0; i < bytes_read; ++i) {
            // Check if the current byte matches the start of the pattern
            if (buffer[i] == pattern[0] && (i + PATTERN_SIZE <= bytes_read) &&
                memcmp(pattern, &buffer[i], PATTERN_SIZE) == 0) {
                // Calculate the size of the data from this point to the end of the file
                long offset = ftell(file) - bytes_read + i;
                fseek(file, offset, SEEK_SET);
                data_size = 0;
                // Allocate buffer and copy data
                while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
                    data_buffer = realloc(data_buffer, data_size + bytes_read);
                    memcpy(data_buffer + data_size, buffer, bytes_read);
                    data_size += bytes_read;
                }
                found = 1;
                break;
            }
        }
    }

    if (found && data_buffer) {
        // Decode and write the data to a file
        decode_and_write(data_buffer, data_size, output_filename);
        free(data_buffer);
    } else {
        printf("Pattern not found or no data after pattern.\n");
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_filename> <output_filename>\n", argv[0]);
        return EXIT_FAILURE;
    }
    printf("bvx2 kernelcache decoder (iOS kernel decompression helper) - jack richardson 2024");
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }

    find_pattern_and_process(file, argv[2]);
    fclose(file);
    return EXIT_SUCCESS;
}
```

Compile & run:

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ ../decode_file kernelcache.release.iphone10 kernelcache.release.iphone10.decoded
bvx2 kernelcache decoder (iOS kernel decompression helper) - jack richardson 2024
Data decompressed and written to kernelcache.release.iphone10.decoded
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ file kernelcache.release.iphone10.decoded
kernelcache.release.iphone10.decoded: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|PIE>
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ 
```

Perfect!  We now get the magic bytes for an arm64 mach-O file:

```bash
jack@jack-NUC8i3BEH:~/Downloads/ipsw-unzip$ xxd kernelcache.release.iphone10.decoded | head -1
00000000: cffa edfe 0c00 0001 0000 0000 0200 0000  ................
```

This file is now ready for further reverse engineering and will be parsed correctly in Ghidra/IDA.


