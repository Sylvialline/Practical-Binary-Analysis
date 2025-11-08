# Practical-Binary-Analysis

## Chapter 4

### 1. Dumping Section Contents
For brevity, the current version of the loader_demo program does not display section contents. Expand it with the ability to take a binary and
the name of a section as input. Then dump the contents of that section to the screen in hexadecimal format.

### 2. Printing Data Symbols
Expand the binary loader and the loader_demo program so that they can handle local and global data symbols as well as function symbols. You will need to add handling for data symbols in the loader, add a new SymbolType in the Symbol class, and add code to the loader_demo program to print the data symbols to screen. Be sure to test your modifications on a nonstripped binary to ensure the presence of some data symbols. Note that data items are called objects in symbol terminology. If you are unsure about the correctness of your output, use readelf to verify it.