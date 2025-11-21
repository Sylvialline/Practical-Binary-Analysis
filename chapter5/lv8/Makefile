CXX = g++
CXXFLAGS = -O2 -std=c++11 -Wall -Wextra

PROGS = \
    text2bits \
    bits2bin \
	bmp2rgb \
	rgb2json \
	rgb2bits

FILES = \
	bits1.txt \
	elf.bmp \
	rgb.txt \
	rgb.json \
	bits2.txt \
	elf_untruncated \
	elf \
	elf_repaired

all: $(PROGS)

flag: elf_repaired
	./elf_repaired

text2bits: text2bits.cc
	$(CXX) $(CXXFLAGS) $< -o $@

bits2bin: bits2bin.cc
	$(CXX) $(CXXFLAGS) $< -o $@

bmp2rgb: bmp2rgb.cc
	$(CXX) $(CXXFLAGS) $< -o $@

rgb2json: rgb2json.cc
	$(CXX) $(CXXFLAGS) $< -o $@

rgb2bits: rgb2bits.cc
	$(CXX) $(CXXFLAGS) $< -o $@


bits1.txt: text2bits lvl8
	./text2bits < lvl8 > bits1.txt

elf.bmp: text2bits lvl8 bits2bin
	./text2bits < lvl8 | ./bits2bin > elf.bmp

rgb.txt: bmp2rgb elf.bmp
	./bmp2rgb < elf.bmp > rgb.txt

rgb.json: bmp2rgb rgb2json elf.bmp
	./bmp2rgb < elf.bmp | ./rgb2json > rgb.json

bits2.txt: rgb2bits bits2bin
	./rgb2bits < rgb.txt > bits2.txt

elf_untruncated: rgb2bits bits2bin rgb.txt
	./rgb2bits < rgb.txt | ./bits2bin > elf_untruncated

elf: elf_untruncated
	dd count=8896 if=elf_untruncated of=elf bs=1

elf_repaired: elf
	cp elf elf_repaired
	printf "\360" | dd of=elf_repaired bs=1 seek=$$((0x6a1)) conv=notrunc
	chmod 777 elf_repaired

debug:
	printf "\xf0" | hexdump -C

clean:
	rm -f $(PROGS) $(FILES)

.PHONY: all flag clean
