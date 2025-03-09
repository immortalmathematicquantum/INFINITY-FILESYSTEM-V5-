This code is a program for compressing and decompressing files using a special algorithm. Here's what it does, explained in simple terms:
Main functions:

File compression:

Splits data into small bit blocks (2 bits each)

Gradually replaces repeating patterns with short identifier codes

Uses 4 compression levels for better optimization

Saves the result to a file with the .ctxt extension

Unpacking:

Restores the original data from the compressed format

Uses saved dictionaries for reverse code conversion

Graphical interface:

Allows you to select files via a dialog box

Shows a list of processed files

Has buttons for compression/unpacking

Algorithm features:

Uses a unique alphabet of 256 characters (Latin, Chinese characters, Indian and Georgian letters)

Automatically saves compression dictionaries to the data.pickle file

Adds special marks for restoring the data structure

For the user:

Run the program → a window with buttons will appear

Click "Compress" to compress the file

Select a file → a compressed version (.ctxt) will appear

Select the file in the list and click "Decompress" to restore

Important!

To unpack, you need the original dictionary (data.pickle file)

The program remembers all processed files between launches

The efficiency of compression depends on the content of the files

This tool is useful for reducing the size of text and binary files, but requires saving service data (data.pickle) for correct operation.

Put the processed file in a zlib, rar or zip archive and get 5-8 times compression of any data!




Here's how the 4-level dictionary works in this compression algorithm:
1. Hierarchical structure

The dictionary consists of 4 separate levels (0-3), each with its own lookup table:

dictionary = [
{}, # Level 0
{}, # Level 1
{}, # Level 2
{} # Level 3
]

2. How compression works

Each level processes pairs of values:

Level 0:

Works with the original 2-bit blocks (00, 01, 10, 11)

Example of replacement: (0,1) → "A1b3C"

Level 1:

Works with pairs of hashes from level 0

Example: ("A1b3C", "Xy9ZQ") → "P0oLk"

Level 2:

Works with pairs of hashes of level 1

Example: ("P0oLk", "Mn8Jh") → "W5tFv"

Level 3:

Processes pairs of level 2 hashes

Finalizes compression: ("W5tFv", "Qw7Er") → "RtY2U"

3. Replacement mechanics

At each level:

Data is split into pairs of elements

For each unique pair, a 5-character hash is generated

Replacement occurs according to the scheme:

Original data → [Pairs] → [Hashes] → New data level

4. Transformation example

Original 8 bits: 10110001

Split into 2-bit blocks: 10 11 00 01

Level 0: replaces pairs of 2-bit values

Level 1: compresses the result of level 0

And so on through all 4 levels

5. Features of hash generation

The int_to_hash() function is used

The hash is always 5 characters long

Based on a unique alphabet of 256 characters

Example of generation: number 42 → "k9LjW"

6. When unpacking

The process is in reverse order (from level 3 to 0)

Reverse dictionaries (reverse_dict) are used

Each hash is sequentially expanded into pairs

7. Why exactly 4 levels?

Optimal depth for processing 2-bit blocks

Allows:

Level 1: compress by 2 times

Level 2: by 4 times

Level 3: by 8 times

Level 4: by 16 times

8. Important nuances

Dictionaries are dynamically expanded during operation

Require saving (data.pickle) for unpacking

Efficiency depends on the repeatability of patterns in the data

This multi-level approach allows achieving better compression by identifying complex patterns in the data that are not visible during single-level analysis.


Important! the program is in beta status, you need to remove the RAM dependence and also make a dictionary on SSD -HDD
