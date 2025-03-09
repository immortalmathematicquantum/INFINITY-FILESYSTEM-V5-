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

Important! the program is in beta status, you need to remove the RAM dependence and also make a dictionary on SSD -HDD
