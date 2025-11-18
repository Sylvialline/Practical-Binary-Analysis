
## Level 2

strings 的结果发现了 srand 和 time，似乎程序结果有随机性。

几次运行 `./ctf` 结果都不一样。但是结果都是由数字或字母构成的长度为 2 的字符串。似乎是一个 16 进制数。

尝试同时运行两个参数不同的命令，消除 srand(time(0)) 的影响

```
$ ./lvl2 foo bar; ./lvl2 baz
81
81
```

似乎结果不受参数影响？也许是根本没有解析参数。

`nm -D -C lvl2` 的结果很没意思。说明它没怎么用库函数，没什么符号可以解析。

```
$ ltrace -i ./lvl2
[0x400569] __libc_start_main(0x400500, 1, 0x7ffc5bb79fa8, 0x400640 <unfinished ...>
[0x40050b] time(0)                                                        = 1763373967
[0x400512] srand(0x691af38f, 0x7ffc5bb79fa8, 0x7ffc5bb79fb8, 0)           = 0
[0x400517] rand(0x7fd98abdb620, 0x7ffc5bb79e8c, 0x7fd98abdb0a4, 0x7fd98abdb11c) = 0x52d08ce6
[0x400531] puts("f2"f2
)                                                     = 3
[0xffffffffffffffff] +++ exited (status 0) +++
```

```
$ printf "%d\n" 0x691af1b5
1763373967
```

果然在用 srand(time(0))。

现在的问题是 0x52d08ce6 怎么算出 f2 的？

我们来看看 srand 附近的代码

```
$ objdump -d -M intel -j .text lvl2 | grep srand -nC 13
1-
2-lvl2:     file format elf64-x86-64
3-
4-
5-Disassembly of section .text:
6-
7-0000000000400500 <.text>:
8-  400500:     48 83 ec 08             sub    rsp,0x8
9-  400504:     31 ff                   xor    edi,edi
10-  400506:    e8 c5 ff ff ff          call   4004d0 <time@plt>
11-  40050b:    89 c7                   mov    edi,eax
12:  40050d:    e8 ae ff ff ff          call   4004c0 <srand@plt>
13-  400512:    e8 c9 ff ff ff          call   4004e0 <rand@plt>
14-  400517:    99                      cdq
15-  400518:    c1 ea 1c                shr    edx,0x1c
16-  40051b:    01 d0                   add    eax,edx
17-  40051d:    83 e0 0f                and    eax,0xf
18-  400520:    29 d0                   sub    eax,edx
19-  400522:    48 98                   cdqe
20-  400524:    48 8b 3c c5 60 10 60    mov    rdi,QWORD PTR [rax*8+0x601060]
21-  40052b:    00
22-  40052c:    e8 6f ff ff ff          call   4004a0 <puts@plt>
23-  400531:    31 c0                   xor    eax,eax
24-  400533:    48 83 c4 08             add    rsp,0x8
25-  400537:    c3                      ret 
```

可以看到，在 rand 返回后，用这个在 rax 中的结果一顿操作（14~19 行），得到了一个位于 0x601060 的数组的索引。看上去是一个字符串指针数组（`const char *[]`），因为每个元素占 8 字节，并且其中某个元素存在 rdi 中后可以直接作为 puts 的参数。

我们直接看一下 0x601060 有什么。先看它在哪个节：

```
$ readelf -S --wide lvl2
There are 29 section headers, starting at offset 0x1210:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
...
  [25] .data             PROGBITS        0000000000601040 001040 0000a0 00  WA  0   0 32
  [26] .bss              NOBITS          00000000006010e0 0010e0 000008 00  WA  0  ...
```

所以 0x601060 在 `.data` 节。看一下 `.data` 节的内容。

```
$ readelf -x .data lvl2

Hex dump of section '.data':
  0x00601040 00000000 00000000 00000000 00000000 ................
  0x00601050 00000000 00000000 00000000 00000000 ................
  0x00601060 c4064000 00000000 c7064000 00000000 ..@.......@.....
  0x00601070 ca064000 00000000 cd064000 00000000 ..@.......@.....
  0x00601080 d0064000 00000000 d3064000 00000000 ..@.......@.....
  0x00601090 d6064000 00000000 d9064000 00000000 ..@.......@.....
  0x006010a0 dc064000 00000000 df064000 00000000 ..@.......@.....
  0x006010b0 e2064000 00000000 e5064000 00000000 ..@.......@.....
  0x006010c0 e8064000 00000000 eb064000 00000000 ..@.......@.....
  0x006010d0 ee064000 00000000 f1064000 00000000 ..@.......@.....
```

这个位于 0x601060 的指针数组存着从 0x4006c4 到 0x4006f1 的一共 16 个字符串，并且都在 `.rodata` 节中。继续看一下 `.rodata` 节。

```
$ readelf -x .rodata lvl2

Hex dump of section '.rodata':
  0x004006c0 01000200 30330034 66006334 00663600 ....03.4f.c4.f6.
  0x004006d0 61350033 36006632 00626600 37340066 a5.36.f2.bf.74.f
  0x004006e0 38006436 00643300 38310036 63006466 8.d6.d3.81.6c.df
  0x004006f0 00383800                            .88.
```

很明显了，这就是那 16 个长度为 2 的字符串，每次运行 `./lvl2` 时都会从这些字符串中随机选一个输出。

也许密码就是把他们按顺序连起来。这个猜测是有充分依据的，因为上次的密码就是长度为 32 的十六进制字符串，而如果我们把在 `.rodata` 中的这 16 个长度为 2 的十六进制字符串连起来，也是一个长度为 32 的十六进制字符串。

```
$ ./oracle 034fc4f6a536f2bf74f8d6d3816cdf88
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 2 completed, unlocked lvl3         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

成功解锁 `lvl3`

## Level 3

### 损坏的 elf 可执行文件

#### 被篡改的 `e_phoff`

看看 lvl3 是个啥

```
$ file lvl3
lvl3: ERROR: ELF 64-bit LSB executable, Motorola Coldfire, version 1 (Novell Modesto) error reading (Invalid argument)
```

是个 elf 文件，但是不知道为什么报错 `Invalid argument`

读一下它的 elf 头试试

```
$ readelf -h lvl3
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 0b 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            Novell - Modesto
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Motorola Coldfire
  Version:                           0x1
  Entry point address:               0x4005d0
  Start of program headers:          4022250974 (bytes into file)
  Start of section headers:          4480 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28
readelf: Error: Reading 0x1f8 bytes extends past end of file for program headers
```

提示读程序头表的时候超出文件大小了。难道是文件被截断了吗？但是不应该啊，readelf 没有报节头表的错，说明至少是可以读到节头表的。又因为节头表在 elf 文件的结尾，这证明 lvl3 作为一个 elf 文件是完整的。

（注：当节头表无法读取到的时候，是会报类似的错的，证据在第五章我们用 `readelf` 读 `elf_header` 的时候，就报了这样的错（见下）。反过来讲，没有报节头表的错，说明 readelf 能够读到节头表）

```
$ readelf -h ../lv1/elf_header
...
readelf: Error: Reading 0x6c0 bytes extends past end of file for section headers
readelf: Error: Reading 0x188 bytes extends past end of file for program headers
```

我们也可以直接验证节头表和程序头表的可读性。

```
readelf --wide -S lvl3
There are 29 section headers, starting at offset 0x1180:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 
...
```

```
readelf --wide -l lvl3

Elf file type is EXEC (Executable file)
Entry point 0x4005d0
There are 9 program headers, starting at offset 4022250974
readelf: Error: Reading 0x1f8 bytes extends past end of file for program headers
```

**这说明不是文件被截断了，而是程序头表偏移是错的**！

我们看一下 elf 头中写的程序头表偏移是多少。

```
Start of program headers:          4022250974 (bytes into file)
```

大的有点离谱了！至少要比节头表的偏移要小吧！此处肯定需要被我们修复。

正常的程序头应该正好在 elf 头的后面，因此正确的偏移应该是 64.

我们用 xxd 看一下应该在哪里写 64，顺便看看这个乱数究竟是啥

```
$ xxd lvl3 | head -5
00000000: 7f45 4c46 0201 010b 0000 0000 0000 0000  .ELF............
00000010: 0200 3400 0100 0000 d005 4000 0000 0000  ..4.......@.....
00000020: dead beef 0000 0000 8011 0000 0000 0000  ................
00000030: 0000 0000 4000 3800 0900 4000 1d00 1c00  ....@.8...@.....
00000040: 0600 0000 0500 0000 4000 0000 0000 0000  ........@.......
```

映入眼帘的是这个位于 0x20 的 `deadbeef`（实际上是 `0xefbeadde`，它就等于 `4022250974`），看来它已经帮我们标记好了我们要改的位置了。（实际上经过计算，`e_phoff` 确实在 `Elf64_Ehdr` 中的偏移 0x20）

我们使用 dd 将位于 `0x20` 的八个字节修改成 `0x00000040`。

```
$ printf "\x40\0\0\0\0\0\0\0" | dd of=lvl3 bs=1 seek=$((0x20)) conv=notrunc
8+0 records in
8+0 records out
8 bytes copied, 0,00830675 s, 1,0 kB/s
```

我们发现 `file` `readelf -h` `readelf --segments` 都不报错了。

```
$ file lvl3
lvl3: ELF 64-bit LSB executable, Motorola Coldfire, version 1 (Novell Modesto), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b6c0e8d914c6433e661b2cac794108671bdcaa06, stripped
```

#### 被篡改的 `e_machine`

给予执行权限后，尝试运行 lvl3 程序

```
$ ./lvl3
-bash: ./lvl3: cannot execute binary file: Exec format error
```

无法执行，可能是因为不能运行 Motorola Coldfire 架构。

回头看 xxd 的输出，`e_machine` 对应的偏移 `0x12` 处的值是 `0x34` ，对应的是 `EM_COLDFIRE`。我们把它强行改成 `EM_X86_64` 试试。

```
$ printf "\x3e" | dd of=lvl3 bs=1 seek=$((0x12)) conv=notrunc
1+0 records in
1+0 records out
```

```
$ file lvl3
lvl3: ELF 64-bit LSB executable, x86-64, version 1 (Novell Modesto), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b6c0e8d914c6433e661b2cac794108671bdcaa06, stripped
```

变成 x86-64 架构了。现在能运行了吗？

```
$ ./lvl3
6218c46c1d2fdde6e5ed85eeee63aea1  ./lvl3
```

### lvl3 的行为

我们得到了一串 32 字节的十六进制字符串，看上去很像一个合法的 flag。虽然后面还跟上了一个不知所以的 `./lvl3`，但我们先不管，看看这个 flag 能不能解锁下一关。

```
$ ./oracle 6218c46c1d2fdde6e5ed85eeee63aea1
Invalid flag: 6218c46c1d2fdde6e5ed85eeee63aea1
```

看来这一关还没有结束。我们尝试其他的运行方式，看看结果有何变化。

```
$ ./lvl3 foo bar
6218c46c1d2fdde6e5ed85eeee63aea1  ./lvl3
$ ../lv3/lvl3
6218c46c1d2fdde6e5ed85eeee63aea1  ../lv3/lvl3
```

看上去 `lvl3` 对参数不敏感，但是对执行它自己的命令名称敏感：其输出的第二个部分刚好是调用它自己的命令名称。不过第一个部分始终没有变化。

我们来看看第一个看起来像 flag 的输出到底是什么。为此，我们进一步分析 `lvl3`。

```
$ readelf -s lvl3

Symbol table '.dynsym' contains 7 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __strcat_chk@GLIBC_2.3.4 (2)
     2: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail@GLIBC_2.4 (3)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.2.5 (4)
     4: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (4)
     5: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __strncat_chk@GLIBC_2.3.4 (2)
```

```
$ readelf -x .rodata lvl3

Hex dump of section '.rodata':
  0x00400750 01000200 6d643573 756d2000          ....md5sum .
```

我们比较感兴趣的部分是 `system` `md5sum `。看上去 `lvl3` 使用 `system` 运行了一个 `md5sum` 的 bash 命令。参数是什么呢？

```
$ ltrace ./lvl3
__libc_start_main(0x400550, 1, 0x7ffea99769c8, 0x4006d0 <unfinished ...>
__strcat_chk(0x7ffea99764c0, 0x400754, 1024, 0)                           = 0x7ffea99764c0
__strncat_chk(0x7ffea99764c0, 0x7ffea9978719, 1016, 1024)                 = 0x7ffea99764c0
system("md5sum ./lvl3"6218c46c1d2fdde6e5ed85eeee63aea1  ./lvl3
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                    = 0
+++ exited (status 0) +++
```

我们已经能够将 `lvl3` 做的事情刻画得很清楚了。它将位于 `.rodata` 的 `md5sum `
与 `argv[0]` 用 `strcat` 连接成命令 `md5sum ./lvl3` ，并使用 `system` 运行这个命令。这个过程会产生子进程，当子进程结束后，命令输出到标准输出中，`lvl3`
正常退出。

而先前的两部分输出实际上是 `md5sum` 的行为。

验证如下：

```
$ md5sum lvl3
6218c46c1d2fdde6e5ed85eeee63aea1  lvl3
```

可以看到我们的猜想成立。那么接下来该怎么办呢？

### 不影响运行的篡改

#### 被篡改的 `e_ident[EI_OSABI]`

我们现在得到了一个计算自己的 MD5 校验和的程序，但是目前的输出并不是有效的 flag。这意味着什么？也许是 `lvl3` 中还有被人为篡改的地方，我们还没发现。虽然该程序现在已经能够正常运行了，但是这并不代表就没有不影响运行的篡改。

目前为止我们都在 `lvl3` 的 elf 头部操作，我们看看这里面是否还有奇怪的地方。

```
$ readelf -h lvl3
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 0b 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            Novell - Modesto
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4005d0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          4480 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28
```

找到了！原来是这一行

```
  OS/ABI:                            Novell - Modesto
```

`e_ident[EI_OSABI(=7)]` 应当是 `ELFOSABI_SYSV(=0)`，但是被错误设置成了 `ELFOSABI_MODESTO(=11)`。

我们需要把该文件的第 7 个字节从 `0x0b` 改为 `0x00`。

```
$ printf "\0" | dd of=lvl3 bs=1 seek=7 conv=notrunc
```

确实变成了 `version 1 (SYSV)`

```
$ file lvl3
lvl3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b6c0e8d914c6433e661b2cac794108671bdcaa06, stripped
```

得到新的校验和

```
$ ./lvl3
0e2ada7381d04d4d2ed31be82b121aa3  ./lvl3
```

```
$ ./oracle 0e2ada7381d04d4d2ed31be82b121aa3
Invalid flag: 0e2ada7381d04d4d2ed31be82b121aa3
```

但这个 flag 仍然不对。

#### 被篡改的 `sh_type`

实在不知道怎么进行下去了，我们使用 objdump 检查指令集行为看看。

```
$ objdump -d -C -M intel lvl3 > lvl3.dumped
```

结果在 `lvl3.dumped` 里面找半天，怎么没看到 `.text` 节的内容呢？让 `objdump` 指定反汇编 `.text` 节试试。

```
$ objdump -d -C -M intel -j .text lvl3

lvl3:     file format elf64-x86-64


Disassembly of section .text:

0000000000400550 <.text>:
        ...
```

这个省略号是输出原本的内容。

程序可以正常运行，代表 `.text` 里面肯定是有正确内容的，可为什么 `objdump` 没法输出 `.text` 的内容？

我们检查一下节头表。

```
$ readelf -S --wide lvl3
There are 29 section headers, starting at offset 0x1180:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
...
  [14] .text             NOBITS          0000000000400550 000550 0001f2 00  AX  0   0 16
...
```

我们只关注 `.text` 节，很快就发现了不寻常的地方：`.text` 的 `sh_type` 居然是 `SHT_NOBITS(=8)` 而非 `SHT_PROGBITS(=1)`。正是这一点让 `objdump -d` 决定不打印 `.text` 节的内容，因为**它通过 `SHT_NOBITS` 把 `.text` 误认为是 `.bss` 了**。（正常情况下只有 `.bss` 是 `SHT_NOBITS`）

我们来计算一下需要改的几个字节的偏移。

节头表的偏移是 `4480`，每个条目大小 `64`，`.text` 在第 `14` 个条目（0-indexed，前面有 `14` 个条目）。`sh_type` 在 `Elf64_Shdr` 内部的偏移是 `4`，其大小也是 `4`。

因此偏移是
$$
\text{offset}=4480+14\times 64+4=5380
$$
所以我们要将 `5380~5383` 的四个字节从 `0x00000008` 改成 `0x00000001`。（实际上只需要把 `5380` 处的一个字节从 `0x08` 改成 `0x01`）

我们先确认计算是否有误，看一下 `5380` 处是不是 `0x08`。

```
$ xxd -seek 5376 lvl3 | head -4
00001500: 8d00 0000 0800 0000 0600 0000 0000 0000  ................
00001510: 5005 4000 0000 0000 5005 0000 0000 0000  P.@.....P.......
00001520: f201 0000 0000 0000 0000 0000 0000 0000  ................
00001530: 1000 0000 0000 0000 0000 0000 0000 0000  ................
```

可以看到计算无误。使用 `dd` 修改指定位置的内容。

```
$ printf "\x01" | dd of=lvl3 bs=1 seek=5380 conv=notrunc
1+0 records in
1+0 records out
1 byte copied, 0,00539035 s, 0,2 kB/s
```

经过了这个修改，我们的 `objdump -d` 可以识别 `.text` 节了。

```
$ objdump -d -C -M intel -j .text lvl3

lvl3:     file format elf64-x86-64


Disassembly of section .text:

0000000000400550 <.text>:
  400550:       55                      push   rbp
  400551:       53                      push   rbx
  400552:       b9 80 00 00 00          mov    ecx,0x80
  400557:       48 89 f5                mov    rbp,rsi
  40055a:       ba 00 04 00 00          mov    edx,0x400
  40055f:       be 54 07 40 00          mov    esi,0x400754
  400564:       48 81 ec 18 04 00 00    sub    rsp,0x418
  40056b:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
...
```

计算新的校验和，看看是否是有效 flag

```
$ ./lvl3
3a5c381e40d2fffd95ba4452a0fb4a40  ./lvl3
```

```
$ ./oracle 3a5c381e40d2fffd95ba4452a0fb4a40
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 3 completed, unlocked lvl4         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

成功通过 Level 3！

### 总结

回头来反思一下我们修复的所有篡改，我们每次发现一个被篡改的地方，都是通过与本机上的正常程序对应位置相比较而发现的。（即使这个比较的过程我在上文中并没有显式地提及。我实际上是与 `/bin/ls` 比较的）

对于一个相同机器上的正常的程序，它的 `e_phoff=64`, `e_machine=EM_X86_64`, `e_ident[EI_OSABI]=ELFOSABI_SYSV`, `Elf64_Shdr[".text"].sh_type=SHT_PROGBITS`，因此我们能够发现 `lvl3` 对应的可疑之处。

换句话说，我们或许可以得到这样的结论：实际上 ELF 提供的信息有相当一部分是冗余的，很多时候一些参数可以被唯一确定。因此，存在很多无关紧要的地方，即使被篡改，程序依然能正常运行。

Level 3 的关卡通过将文件的校验和作为 flag，要求我们发现 ELF 文件中所有被篡改的地方，即使这个文件已经可以正常运行。
