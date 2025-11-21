
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
与 `argv[0]` 用 `strcat` 连接成命令 `md5sum ./lvl3` ，并使用 `system` 运行这个命令。这个过程会产生子进程，当子进程结束后，命令输出到标准输出中，`lvl3` 正常退出。

而先前的两部分输出实际上是 `md5sum` 的行为。

验证如下：

```
$ md5sum lvl3
6218c46c1d2fdde6e5ed85eeee63aea1  lvl3
```

可以看到我们的猜想成立。那么接下来该怎么办呢？

### 不影响运行的篡改

#### 被篡改的 `e_ident[EI_OSABI]`

我们现在得到了一个计算自己的 MD5 校验和的程序，但是目前的输出并不是有效的 flag。这意味着什么？也许是 `lvl3` 中还有被人为篡改的地方，我们还没发现。虽然该程序现在已经能够正常运行了，但是这**并不代表就没有不影响运行的篡改**。

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

## Level 4

直接运行 `lvl4`，什么都没有输出，并且正常退出。

```
$ ./lvl4
$ echo $?
0
```

`.rodata` 中有两个字符串 `XaDht-+1432=/as4?0129mklqt!@cnz^` 和 `FLAG`

```
$ readelf -x .rodata lvl4

Hex dump of section '.rodata':
  0x004006d0 01000200 00000000 58614468 742d2b31 ........XaDht-+1
  0x004006e0 3433323d 2f617334 3f303132 396d6b6c 432=/as4?0129mkl
  0x004006f0 71742140 636e7a5e 00000000 00000000 qt!@cnz^........
  0x00400700 464c4147 00                         FLAG.
```

使用了库函数 `setenv`，似乎不是 C++ 程序。

```
$ nm -D lvl4
                 w __gmon_start__
                 U __libc_start_main
                 U setenv
                 U __stack_chk_fail
```

看一下 `lvl4` 在拿 `setenv` 干啥。

```
$ ltrace ./lvl4
__libc_start_main(0x4004a0, 1, 0x7ffc94aeb308, 0x400650 <unfinished ...>
setenv("FLAG", "656cf8aecb76113a4dece1688c61d0e7"..., 1)                  = 0
+++ exited (status 0) +++
```

里面有个像 flag 的东西 `656cf8aecb76113a4dece1688c61d0e7`，试一下

```
$ ./oracle 656cf8aecb76113a4dece1688c61d0e7
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 4 completed, unlocked lvl5         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

没想到这么轻松就通过了。

这里的 `656cf8aecb76113a4dece1688c61d0e7` 应该是由 `XaDht-+1432=/as4?0129mklqt!@cnz^` 生成的，因为 `.rodata` 里没有。但具体的生成方式这里就不深究了。

## Level 5

### 收集线索

不论参数，总是输出 `nothing to see here` 并异常退出。

```
$ ./lvl5
nothing to see here
$ ./lvl5 foo bar
nothing to see here
$ ./lvl5 show_me_the_flag
nothing to see here
$ echo $?
1
```

`.rodata` 段的内容

```
$ readelf -x .rodata lvl5

Hex dump of section '.rodata':
  0x00400770 01000200 6b657920 3d203078 25303878 ....key = 0x%08x
  0x00400780 0a006465 63727970 74656420 666c6167 ..decrypted flag
  0x00400790 203d2025 730a006e 6f746869 6e672074  = %s..nothing t
  0x004007a0 6f207365 65206865 726500            o see here.

```

如何用上分别位于 `0x400774` 的 `"key = 0x%08x\n"` 和位于 `0x400782` 的 `decrypted flag = %s\n` 这两个字符串呢？

`ltrace` 也没有提供特别的信息。

```
$ ltrace -i ./lvl5
[0x400549] __libc_start_main(0x400500, 1, 0x7ffed6430f78, 0x4006f0 <unfinished ...>
[0x40050e] puts("nothing to see here"nothing to see here
)                                    = 20
[0xffffffffffffffff] +++ exited (status 1) +++
```

`__libc_start_main` 的第一个参数 `0x400500` 应该就是 `main` 的地址，我们看看这附近的代码。

```
$ objdump -d -M intel lvl5 | grep 400500 -A 7 -B 2 -n
49-Disassembly of section .text:
50-
51:0000000000400500 <.text>:
52:  400500:    48 83 ec 08             sub    rsp,0x8
53-  400504:    bf 97 07 40 00          mov    edi,0x400797
54-  400509:    e8 a2 ff ff ff          call   4004b0 <puts@plt>
55-  40050e:    b8 01 00 00 00          mov    eax,0x1
56-  400513:    48 83 c4 08             add    rsp,0x8
57-  400517:    c3                      ret
58-  400518:    0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
59-  40051f:    00
--
67-  40052f:    49 c7 c0 60 07 40 00    mov    r8,0x400760
68-  400536:    48 c7 c1 f0 06 40 00    mov    rcx,0x4006f0
69:  40053d:    48 c7 c7 00 05 40 00    mov    rdi,0x400500 // main 函数地址在第一个参数
70-  400544:    e8 87 ff ff ff          call   4004d0 <__libc_start_main@plt>
71-  400549:    f4                      hlt
72-  40054a:    66 0f 1f 44 00 00       nop    WORD PTR [rax+rax*1+0x0]
73-  400550:    b8 4f 10 60 00          mov    eax,0x60104f
74-  400555:    55                      push   rbp
75-  400556:    48 2d 48 10 60 00       sub    rax,0x601048
76-  40055c:    48 83 f8 0e             cmp    rax,0xe
```

从结果可以看出来，main 函数的代码只有这样一小段

```
52:  400500:    48 83 ec 08             sub    rsp,0x8
53-  400504:    bf 97 07 40 00          mov    edi,0x400797
54-  400509:    e8 a2 ff ff ff          call   4004b0 <puts@plt>
55-  40050e:    b8 01 00 00 00          mov    eax,0x1
56-  400513:    48 83 c4 08             add    rsp,0x8
57-  400517:    c3                      ret
```

它仅仅是输出位于 `0x400797` 的 `nothing to see here` 后，就 `return 1`。

看来我们需要改变 `main` 函数的行为，让它与 `.rodata` 中另外的两个字符串交互。

### 寻找真正应该执行的代码段

我们直接用文本编辑器打开 `objdump` 后的 `lvl5`，找到 `.text` 段中提到 `0x400774` 和 `0x400782` 的地方。

```
$ objdump -d -M intel lvl5 > lvl5.dumped
$ code lvl5.dumped
// 手动寻找地址 0x400774 0x400782
$ nl lvl5.dumped | sed -n '136,182p'
   122    40061d:       00 00 00
   123    400620:       53                      push   rbx // callee-saved
   124    400621:       be 74 07 40 00          mov    esi,0x400774 // 第一个地址
   125    400626:       bf 01 00 00 00          mov    edi,0x1
   126    40062b:       48 83 ec 30             sub    rsp,0x30 // 设置当前函数的栈帧
   127    40062f:       64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28
   128    400636:       00 00
   129    400638:       48 89 44 24 28          mov    QWORD PTR [rsp+0x28],rax
   130    40063d:       31 c0                   xor    eax,eax
   131    40063f:       48 b8 10 60 21 33 15    movabs rax,0x6223331533216010 // 奇怪的计算逻辑
   132    400646:       33 23 62
   133    400649:       c6 44 24 20 00          mov    BYTE PTR [rsp+0x20],0x0
   134    40064e:       48 89 04 24             mov    QWORD PTR [rsp],rax
   135    400652:       48 b8 45 65 76 34 41    movabs rax,0x6675364134766545
   136    400659:       36 75 66
   137    40065c:       48 89 44 24 08          mov    QWORD PTR [rsp+0x8],rax
   138    400661:       48 b8 17 67 75 64 10    movabs rax,0x6570331064756717
   139    400668:       33 70 65
   140    40066b:       48 89 44 24 10          mov    QWORD PTR [rsp+0x10],rax
   141    400670:       48 b8 18 35 76 62 11    movabs rax,0x6671671162763518
   142    400677:       67 71 66
   143    40067a:       48 89 44 24 18          mov    QWORD PTR [rsp+0x18],rax
   144    40067f:       8b 1c 25 40 05 40 00    mov    ebx,DWORD PTR ds:0x400540
   145    400686:       31 c0                   xor    eax,eax
   146    400688:       89 da                   mov    edx,ebx
   147    40068a:       e8 51 fe ff ff          call   4004e0 <__printf_chk@plt>
   148    40068f:       48 8d 54 24 20          lea    rdx,[rsp+0x20]
   149    400694:       48 89 e0                mov    rax,rsp
   150    400697:       66 0f 1f 84 00 00 00    nop    WORD PTR [rax+rax*1+0x0]
   151    40069e:       00 00
   152    4006a0:       31 18                   xor    DWORD PTR [rax],ebx
   153    4006a2:       48 83 c0 04             add    rax,0x4
   154    4006a6:       48 39 d0                cmp    rax,rdx
   155    4006a9:       75 f5                   jne    4006a0 <__printf_chk@plt+0x1c0>
   156    4006ab:       31 c0                   xor    eax,eax
   157    4006ad:       48 89 e2                mov    rdx,rsp
   158    4006b0:       be 82 07 40 00          mov    esi,0x400782 // 第二个地址
   159    4006b5:       bf 01 00 00 00          mov    edi,0x1
   160    4006ba:       e8 21 fe ff ff          call   4004e0 <__printf_chk@plt>
   161    4006bf:       31 c0                   xor    eax,eax
   162    4006c1:       48 8b 4c 24 28          mov    rcx,QWORD PTR [rsp+0x28]
   163    4006c6:       64 48 33 0c 25 28 00    xor    rcx,QWORD PTR fs:0x28
   164    4006cd:       00 00
   165    4006cf:       75 06                   jne    4006d7 <__printf_chk@plt+0x1f7>
   166    4006d1:       48 83 c4 30             add    rsp,0x30 // 清除当前函数的栈帧
   167    4006d5:       5b                      pop    rbx // 恢复
   168    4006d6:       c3                      ret
```

我猜测这个从 `0x400620` 开始到 `0x4006d6` 的部分才是我们真正需要执行的代码段。理由如下：
- 首先，它很有可能是一个完整的函数。因为：
	- 以 `push rbx` 开始，以 `pop rbx` 结束，而 `rbx` 是 `callee-saved` 的，的确会在函数开头出现
	- 操作栈帧：在开头 `sub rsp,0x30`，并在最后 `add rsp,0x30`
	- 函数地址 16 字节对齐，并且前面有两个零字节填充
	- 在 `0x4006d6` 第一次出现 `ret`
- 其次，这个函数很有可能包含关键逻辑
	- 存在 `0x400774` 和 `0x400782` 这两个地址，作为 `__printf_chk` 的参数。运行这段代码应该就可以输出两个未出现的字符串。
	- 有一些奇怪的计算逻辑。出现了多次类似于 `movabs rax,0x6223331533216010` 的命令，估计与最后 flag 的计算有关。
		- 如果是，那么这段代码和之前的挑战一样，是在避免 flag 的值直接明文出现在数据节当中。只不过这次是把解码 flag 的相关数据直接写在代码节当中了。

### 重定向 `__libc_start_main` 的目标

接下来的问题是怎么让程序的执行流到达这段代码。我们把目光转向先前的 `__libc_start_main`。

```
69:  40053d:    48 c7 c7 00 05 40 00    mov    rdi,0x400500
70-  400544:    e8 87 ff ff ff          call   4004d0 <__libc_start_main@plt>
```

通过修改它的参数，我们可以让另一个完全不同的函数被当成是“main 函数”。

我们把这里的 `0x400500` 改成 `0x400620` 试试。

`0x40053d` 对应在 ELF 文件中的偏移应该是 `0x53d`。先用 `xxd` 确认一下。

```
$ xxd -seek $((0x53d)) -len 7 lvl5
0000053d: 48c7 c700 0540 00                        H....@.
```

没问题。用 `dd` 改一下。

```
$ cp lvl5 lvl5.1
$ printf "\x20\x06" | dd of=lvl5.1 bs=1 seek=$((0x53d+3)) conv=notrunc
```

运行一下试试。

```
$ ./lvl5.1
key = 0x00400620
decrypted flag = 0fa355cbec64a05f7a5d050e836b1a1f
```

成功了。不过看上去我们好像跳了一步，应该先知道 `key = 0x00400620` 的，而我们直接通过观察代码得到了这个值。

### 反思

重新看了一下 `lvl5.dumped` 的内容，注意到了这两行

```
   144    40067f:       8b 1c 25 40 05 40 00    mov    ebx,DWORD PTR ds:0x400540
   146    400688:       89 da                   mov    edx,ebx
```

意思是把 `0x400540` 开始的四个字节赋值到 `ebx` 中，接着赋值到 `edx` 中，作为接下来 `__printf_chk` 的参数。而这里的 `0x400540` 正好对应着我们之前算的 `0x53d+3`，即 `call __libc_start_main` 之前准备的参数 `mov rdi,???`。

也就是说，正常的操作是先注意到反汇编代码中的神秘地址 `0x400540`，知道这是我们要改的部分，然后继续后面的操作，而不是冒险直接修改 `__libc_start_main` 的操作（虽然后来我们知道这是可行的）。

实际上之前是注意到了 `0x400540` 这个神秘地址的，只不过之前的判断是这是一个在命令中间的地址，并且有个莫名其妙的 `ds:` 在前面，就没有太在意。

不论如何，我们成功通过了 Level 5.

```
$ ./oracle 0fa355cbec64a05f7a5d050e836b1a1f
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 5 completed, unlocked lvl6         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

## Level 6

### 混淆视听的质数

直接运行，打印了 100 以内的质数。

```
$ ./lvl6
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
```

`strings` 中的一些字符串

```
$ strings -t x -n 2 lvl6
    3a3 __printf_chk
    3b0 __stack_chk_fail
    3c1 putchar
    3c9 __sprintf_chk
    3d7 strcmp
    3de __libc_start_main
    3f0 setenv
    3f7 __gmon_start__
    914 DEBUG: argv[1] = %s
    929 get_data_addr
    937 0x%jx
    93d DATA_ADDR
    947 %d
```

`ltrace` 看上去就是把这些质数输出了，最后又有个 `putchar` 不知道在干什么。

```
$ ltrace ./lvl6
__libc_start_main(0x4005f0, 1, 0x7ffcbb770a78, 0x400890 <unfinished ...>
__printf_chk(1, 0x400947, 2, 100)                                         = 2
__printf_chk(1, 0x400947, 3, 0x7ffffffe)                                  = 2
...
__printf_chk(1, 0x400947, 89, 0x7ffffffd)                                 = 3
__printf_chk(1, 0x400947, 97, 0x7ffffffd)                                 = 3
putchar(10, 3, 0, 0x7ffffffd2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
)                                             = 10
```

### 代码节中的数据

回头看看 `strings` 的结果，`DEBUG: argv[1] = %s` 提示我们这次需要提供参数，而 `get_data_addr` 看上去很适合担任这个角色。

```
$ ./lvl6 get_data_address
2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
```

结果没有变化？别这么快就认定没变化了，看看 `ltrace` 怎么说。

```
$ ltrace ./lvl6 get_data_addr
__libc_start_main(0x4005f0, 2, 0x7ffe6115e598, 0x400890 <unfinished ...>
strcmp("get_data_addr", "get_data_addr")                                  = 0
__sprintf_chk(0x7ffe6115e090, 1, 1024, 0x400937)                          = 8
setenv("DATA_ADDR", "0x4006c1", 1)                                        = 0
__printf_chk(1, 0x400947, 2, 100)                                         = 2
__printf_chk(1, 0x400947, 3, 0x7ffffffe)                                  = 2
...
__printf_chk(1, 0x400947, 89, 0x7ffffffd)                                 = 3
__printf_chk(1, 0x400947, 97, 0x7ffffffd)                                 = 3
putchar(10, 3, 0, 0x7ffffffd2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
)                                             = 10
+++ exited (status 0) +++
```

在开头多了几个调用，说明我们的参数是选对了。`setenv` 似乎在提示我们 `0x4006c1` 的地方是数据，但是这里不是代码节吗？

```
$ objdump -d -M intel lvl6 | grep 4006c1 -A 5 -n
132:  4006c1:   2e 29 c6                cs sub esi,eax
133-  4006c4:   4a 0f 03 a6 ee 2a 30    rex.WX lsl rsp,WORD PTR [rsi+0x7f302aee]
134-  4006cb:   7f
135-  4006cc:   ec                      in     al,dx
136-  4006cd:   c8 c3 ff 42             enter  0xffc3,0x42
137-  4006d1:   48 8d ac 24 90 01 00    lea    rbp,[rsp+0x190]
...
```

仔细一看这连着 4 个命令咋都不认识呢？中间甚至还滑稽地插进去了一个 `7f`。看来从 `0x4006c1` 开始的这 16 个字节都是数据而不是代码。

用 `xxd` 直接提取。

```
$ xxd -skip $((0x6c1)) -len 16 -g 0 lvl6
000006c1: 2e29c64a0f03a6ee2a307fecc8c3ff42  .).J....*0.....B
```

```
$ ./oracle 2e29c64a0f03a6ee2a307fecc8c3ff42
Invalid flag: 2e29c64a0f03a6ee2a307fecc8c3ff42
```

用 `xxd -e` 再试一下呢？选项 `-e` 表示将目标内容**当作一个小端序的整体**输出，即最后的输出内容高地址位在前。

```
$ xxd -skip $((0x6c1)) -len 16 -g 0 -e lvl6
000006c1: 42ffc3c8ec7f302aeea6030f4ac6292e  .).J....*0.....B
```

```
$ ./oracle 42ffc3c8ec7f302aeea6030f4ac6292e
Invalid flag: 42ffc3c8ec7f302aeea6030f4ac6292e
```

看来我们还需要进一步分析。但我已经确定 `2e29c64a0f03a6ee2a307fecc8c3ff42` 应该就是密码了，也许问题出在 `oracle` 文件。

### 更新软件版本

官网的更新脚本我总是卡在 `Fetching updates...`

```
$ cd /home/binary && rm -f auto-update.sh \
>         && wget -q --no-check-certificate https://practicalbinaryanalysis.com/patch/auto-update.sh \
>         && chmod 755 auto-update.sh && ./auto-update.sh
Fetching stage 2... OK
Launching stage 2 updater
Fetching updates... 
```

手动从官网上面下载新的 `oracle` 和 `levels.db` 并用 `scp` 传入虚拟机，比较一下跟我们的有没有区别。

```
$ cmp oracle test/oracle
oracle test/oracle differ: byte 645, line 1
$ cmp levels.db test/levels.db
levels.db test/levels.db differ: byte 42960, line 32
```

看来的确如此。我们使用新版本的 `oracle` 应该就能通过本关了。

```
$ ./oracle 2e29c64a0f03a6ee2a307fecc8c3ff42
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 6 completed, unlocked lvl7         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

## Level 7

终于还是遇到一开始只给个压缩包的玩法了。

```
$ file lvl7
lvl7: gzip compressed data, last modified: Sat Dec  1 17:30:15 2018, from Unix
$ file -z lvl7
lvl7: POSIX tar archive (GNU) (gzip compressed data, last modified: Sat Dec  1 17:30:15 2018, from Unix)
```

是经典的 `.tar.gz` 格式，用 `tar xzf` 解压。

```
$ tar xvzf lvl7
stage1
stage2.zip
```

得到两个文件。我们先研究一下 `stage1`。

### stage 1

经过若干尝试，最终发现 `.rodata` 节有一段奇怪的内容。

```
$ readelf -x .rodata stage1

Hex dump of section '.rodata':
  0x004005a0 01000200 20532954 411147fa deff4532 .... S)TA.G...E2
  0x004005b0 204b458a 5900                        KE.Y.
```

看起来这串从 `0x5a5` 开始的 16 字节字符串就是 stage2 的密码。（不得不说这种自我指涉的提示方法真的很有趣）

```
$ xxd -skip $((0x5a5)) -len 16 -g 0 stage1
000005a5: 532954411147fadeff4532204b458a59  S)TA.G...E2 KE.Y
```

`stage2_key` = `532954411147fadeff4532204b458a59`

这个 key 应该是解压 `stage2.zip` 的密码。试试看

```
$ unzip -P 532954411147fadeff4532204b458a59 stage2.zip
Archive:  stage2.zip
   skipping: tmp                     incorrect password
   skipping: stage2                  incorrect password
```

不对？也许只有 `STAGE2 KEY` 对应的字节才是答案？手动提取一下得到 `stage2_key` = `535441474532204b4559`。同样不行。

在这 16 个字符中把可见字符去掉的剩下部分？不行。

最后发现原来密码就是 `STAGE2KEY`，也许我的过度解释可以归因为 32 字符密码的先入为主，因为之前的密码都是这个形式，然后看到 `S)TA.G...E2 KE.Y` 写成 16 进制字节也是这个形式，就掉进坑里了。

```
$ unzip -P STAGE2KEY stage2.zip
Archive:  stage2.zip
  inflating: tmp
  inflating: stage2
```

不过我还是认为把密码设置为 `532954411147fadeff4532204b458a59` 是很合理的。

### stage 2

#### quine?

解压得到了两个可执行文件。但这两个文件似乎是相同的

```
$ md5sum stage2
1eb7e8a43c001ecc3ab13de2dd999f75  stage2
$ md5sum tmp
1eb7e8a43c001ecc3ab13de2dd999f75  tmp
```

我们运行 `stage2` 试试。

```
$ ./stage2
#include <stdio.h>
#include <string.h>
#include <vector>
#include <algorithm>

int main()
{
std::vector<char> hex;
char q[] = "#include <stdio.h>\n#include <string.h>\n#include <vector>\n#include <algorithm>\n\nint main()\n{\nstd::vector<char> hex;\nchar q[] = \"%s\";\nint i, _0F;\nchar c, qc[4096];\n\nfor(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);\nfor(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);\nstd::srand(55);\nstd::random_shuffle(hex.begin(), hex.end());\n\n_0F = 0;\nfor(i = 0; i < strlen(q); i++)\n{\nif(q[i] == 0xa)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 'n';\n}\nelse if(q[i] == 0x22)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 0x22;\n}\nelse if(!strncmp(&q[i], \"0F\", 2) && (q[i-1] == '_' || i == 545))\n{\nchar buf[3];\nbuf[0] = q[i];\nbuf[1] = q[i+1];\nbuf[2] = 0;\nunsigned j = strtoul(buf, NULL, 16);\nqc[_0F++] = q[i++] = hex[j];\nqc[_0F] = q[i] = hex[j+1];\n}\nelse qc[_0F] = q[i];\n_0F++;\n}\nqc[_0F] = 0;\n\nprintf(q, qc);\n\nreturn 0;\n}\n";
int i, _0F;
char c, qc[4096];

for(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);
for(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);
std::srand(55);
std::random_shuffle(hex.begin(), hex.end());

_0F = 0;
for(i = 0; i < strlen(q); i++)
{
if(q[i] == 0xa)
{
qc[_0F++] = 0x5c;
qc[_0F] = 'n';
}
else if(q[i] == 0x22)
{
qc[_0F++] = 0x5c;
qc[_0F] = 0x22;
}
else if(!strncmp(&q[i], "0F", 2) && (q[i-1] == '_' || i == 545))
{
char buf[3];
buf[0] = q[i];
buf[1] = q[i+1];
buf[2] = 0;
unsigned j = strtoul(buf, NULL, 16);
qc[_0F++] = q[i++] = hex[j];
qc[_0F] = q[i] = hex[j+1];
}
else qc[_0F] = q[i];
_0F++;
}
qc[_0F] = 0;

printf(q, qc);

return 0;
}
```

看上去返回了一串代码，仔细读一读，这是一份 quine（自指程序）？看来 Level 7 的主题就是**自指**了。我们看一下它是不是真的自指。

```
$ ./stage2 > stage2.cc
$ g++ stage2.cc -o stage2.1
$ ./stage2.1 > stage2.1.cc
```

```
$ diff stage2 stage2.1
Binary files stage2 and stage2.1 differ
$ cmp stage2.cc stage2.1.cc
stage2.cc stage2.1.cc differ: byte 279, line 9
```

我们发现用 `stage2` 生成的代码 `stage2.cc` 重新编译为可执行文件 `stage2.1` 后，其输出与 `stage2` 的输出不同。看来不是完美的 quine，但具体有哪些不同呢？

通过 `diff` 工具或者直接查看可以发现，`stage2.cc` 中的变量 `_0F` 变成了 `_25`，包括 `char q[]` 中 `0F` 的所有出现。即输出中所有的 `0F` 都变成了 `25`， 而其他部分没有任何变化。

也许这是个 Cyclic Quine。多运行几次，把这个变量的名字变化记录下来，或许就是 flag。

不过多次运行太过麻烦，我们还是分析一下代码，找一下变量名的循环规律吧。

#### `state2.cc` 代码分析

首先，这一步 `printf` 的结果就是整份代码

```
printf(q, qc);
```

其中字符串 `q` 包含了代码中的大部分内容，但除了下一份代码中的 `q` 自己。因为它没办法显式地包括自己，所以这部分只能由 `%s` 替代，后续通过动态填充 `qc` （过程中需要处理转义）来达到输出自己的目的。

```
char q[] = "#include <stdio.h>\n#include <string.h>\n#include <vector>\n#include <algorithm>\n\nint main()\n{\nstd::vector<char> hex;\nchar q[] = \"%s\";\nint i, _0F;\nchar c, qc[4096];\n\nfor(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);\nfor(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);\nstd::srand(55);\nstd::random_shuffle(hex.begin(), hex.end());\n\n_0F = 0;\nfor(i = 0; i < strlen(q); i++)\n{\nif(q[i] == 0xa)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 'n';\n}\nelse if(q[i] == 0x22)\n{\nqc[_0F++] = 0x5c;\nqc[_0F] = 0x22;\n}\nelse if(!strncmp(&q[i], \"0F\", 2) && (q[i-1] == '_' || i == 545))\n{\nchar buf[3];\nbuf[0] = q[i];\nbuf[1] = q[i+1];\nbuf[2] = 0;\nunsigned j = strtoul(buf, NULL, 16);\nqc[_0F++] = q[i++] = hex[j];\nqc[_0F] = q[i] = hex[j+1];\n}\nelse qc[_0F] = q[i];\n_0F++;\n}\nqc[_0F] = 0;\n\nprintf(q, qc);\n\nreturn 0;\n}\n";
```

`qc` 基本上就是 `q` 的一个副本，只是要处理下面的问题：
- 将 `q` 中出现的换行符 `'\n'=0x0a` 替换为两个字符 `'\'=0x5c` 和 `'n'`。之所以代码中要以 `0x5c` 代替 `'\'`（`0x0a` 同理），是因为 `'\'` 会再次引入转义字符 `\`（实际上仍然可行，只是不方便）。

	```cpp
	if(q[i] == 0xa)
	{
	qc[_0F++] = 0x5c;
	qc[_0F] = 'n';
	}
	```

- 将 `q` 中出现的换行符 `'"'=0x22` 替换为两个字符 `'\'=0x5c` 和 `'"'=0x22`。

	```cpp
	else if(q[i] == 0x22)
	{
	qc[_0F++] = 0x5c;
	qc[_0F] = 0x22;
	}
	```

- 这一步是变量名循环的逻辑：找到代码中所有出现当前变量名的位置，并把它换成以它自己在 `hex[]` 中索引后得到的字符串。`545` 应该对应着 `strncmp(&q[i], "0F", 2)` 中出现的变量名。（实际上表达式 `(q[i-1] == '_' || i == 545)` 在前面成立的的情况下应该是恒真的）

	```cpp
	else if(!strncmp(&q[i], "0F", 2) && (q[i-1] == '_' || i == 545))
	{
	char buf[3];
	buf[0] = q[i];
	buf[1] = q[i+1];
	buf[2] = 0;
	unsigned j = strtoul(buf, NULL, 16);
	qc[_0F++] = q[i++] = hex[j];
	qc[_0F] = q[i] = hex[j+1];
	}
	```

#### 编写代码模拟 Cyclic Quine 的行为

了解了这些，我们可以直接编写代码找到变量名循环的规律。

```cpp
/* flag.cc */
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

int main() {
    std::vector<char> hex;
    int i;
    char c;
    for(i = 0; i < 32; i++) for(c = '0'; c <= '9'; c++) hex.push_back(c);
    for(i = 0; i < 32; i++) for(c = 'A'; c <= 'F'; c++) hex.push_back(c);
    std::srand(55);
    std::random_shuffle(hex.begin(), hex.end());

    int n=0x0f;
    i = 0;
    do{
        char buf[3];
        std::stringstream ss;
        ss << std::hex << std::setfill('0') << std::setw(2) << n;
        buf[0] = hex[n];
        buf[1] = hex[n+1];
        buf[2] = 0;
        n = std::stoul(buf, nullptr, 16);
        std::cout << ss.str();
        if(++i > 100)break;
    }while(n!=0x0f);
    std::cout<<'\n';

    return 0;
}
```

因为初始的 `0f` 可能不在循环节里（如果将每一次 n 的值抽象为节点，一次变换就连一条边，则边数与点数相同，构成基环树森林），因此我们直接打印 100 个 n 手动找循环节

```
$ g++ -std=c++11 flag.cc -o flag
$ ./flag
0f25e512a7763eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aeda1f964703eefb7696b3aed
```

循环节是 `3eefb7696b3aeda1f96470`，可惜只有 11 个字节。进入循环之前的字符串是 `0f25e512a776`，有 6 个字节，加上 11 也比 16 大了 1。

也许跟循环节没有关系，我们只需要取前 16 个字节 `0f25e512a7763eefb7696b3aeda1f964` 就好了。

```
$ ./oracle 0f25e512a7763eefb7696b3aeda1f964
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 7 completed, unlocked lvl8         |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

成功通过 Level 7. 到最后也不知道 `tmp` 是何意。

## Level 8

### 完成本关卡后的我的说明

本关卡中涉及的文件很多，因此使用 makefile 管理，最终的 makefile 我直接贴在下面，便于读者理清思路。

```makefile
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

```

### 尝试和分析

`lvl8` 是一个文本文件，包含近万个段落，段落之间由两个换行符分隔，与正常英文文本的区别可能只是其中的单词大部分虽然**可以拼读**出来，但都是陌生的英文单词，或者说像是其他语言中的单词。

```
$ file lvl8
lvl8: ASCII text, with very long lines

$ more lvl8
lOrem iPsuM doLOr SIT AmEt, conseCTETur adipIscing elit. maecenas eget augue sed leo suscipit ultrICiES sed blandit urna
. sed ut risus vitAe Ligula semper scelerisque. fusce et UlTRices telluS, non commodo elit. nullA fACilisi. inteGer phar
etra eu massa et ultrIces. nunc dignISsim nisl eu nulla ultricies venenatis. fusce tincidUnT NibH risuS, IN VulputaTe li
bero congue A. cuRabituR eST diam, lacinia vel placeRat Eget, seMpER nec enim.

proin turpis metus, finibus in porttitor sed, tempor nec ante. nulla ornare volutpat mi, siT AMET VOlUTPAT NUNC. AENEAN
...
```

进一步我们发现其实同一个单词会改变自己的大小写在文本中多次出现。写一段 python 脚本统计单词数量。（这个脚本只是观察文本性质，没有写在 makefile 里面）

```python
# wc.py
# -*- coding: utf-8 -*-
import sys
import re
from collections import Counter

def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <filename>" % sys.argv[0])
        sys.exit(1)
    filename = sys.argv[1]
    try:
        with open(filename, "r") as f:
            text = f.read()
    except Exception as e:
        print("Error reading file: %s" % e)
        sys.exit(1)
        
    # text = text.lower() # 注释此行则大小写不敏感
    
    # 提取单词
    words = re.findall(r"[A-Za-z0-9]+", text)
    counter = Counter(words)
    # 输出：按出现次数从多到少排序
    for word, count in counter.most_common():
        print("%s: %d" % (word, count))


if __name__ == "__main__":
    main()

```

```
$ python wc.py lvl8 > count.txt # 大小写不敏感
$ python wc.py lvl8 > count_sensitive.txt # 大小写敏感
$ wc count.txt count_sensitive.txt
   187    374   2429 count.txt
  9149  18298 109885 count_sensitive.txt
  9336  18672 112314 total
```

python 脚本的处理结果显示，如果大小写敏感地统计，有 9149 个不同单词，但如果大小写不敏感，则只有 187 个不同单词。

```
$ tail -1 lvl8
UT venenatis libero n
# 文末无换行符
$ tail count.txt
inceptos: 159
himenaeos: 159
conubia: 159
taciti: 159
ad: 159
class: 159
potenti: 130
curae: 129
cubilia: 129
n: 1
```

最后这个 `n` 出现很突兀，它只在文章最后出现一次。也许是一个以 `n` 开头的单词被截断了？

### 隐藏在文本中的二进制信息

#### text2bits.cc

可以随意被截断，也许意味着文本内容其实并不重要。换句话说，它只是一种**载波**，真正重要的是大小写，它是载波上的**数据**。我把大小写信息转化为 01 比特流试试。

```cpp
// text2bits.cc
#include <iostream>
#include <cctype>
using namespace std;

/*
标准输入：任意文本
标准输出：看到字母则输出 bit（小写=0，大写=1），非字母忽略
*/

int main() {
    ios::sync_with_stdio(false); // 关闭同步流，加速输出
    cin.tie(nullptr);
    char ch;
    while (cin.get(ch)) {
        if (isalpha(ch)) {
            if (islower(ch)) cout << '0';
            else             cout << '1';
        }
    }
    return 0;
}

```

#### bits2bin.cc

尝试了多种大端/小端，大小写与 01 的对应关系的组合，最终发现**大端**加**小写对应 0，大写对应 1** 可以解码出有意义的二进制文件。

```cpp
#include <iostream>
using namespace std;

/*
标准输入：01 字符串
标准输出：按大端序组装成的字节流
*/

int main() {
    char bit;
    unsigned char byte = 0;
    int count = 0;

    while (cin.get(bit)) {
        if (bit != '0' && bit != '1') continue;

        byte = (byte << 1) | (bit - '0'); // big-endian
        count++;

        if (count == 8) {
            cout.put(byte);
            byte = 0;
            count = 0;
        }
    }

    if (count > 0) {
        byte <<= (8 - count);
        cout.put(byte);
    }

    return 0;
}

```

在 makefile 中构建好编译命令并执行。

```
$ make elf.bmp
g++ -O2 -std=c++11 -Wall -Wextra text2bits.cc -o text2bits
g++ -O2 -std=c++11 -Wall -Wextra bits2bin.cc -o bits2bin
./text2bits < lvl8 | ./bits2bin > elf.bmp
```

提取出来的文件是一个 `PC bitmap`

```
$ file elf.bmp
elf.bmp: PC bitmap, Windows 3.x format, 300 x 300 x 24
```

`elf.bmp` 长这样

![[elf.bmp]]

谷歌搜图后发现这个人物的名字是 *Buddy the Elf*。看来这张图片里面还藏着一个 ELF，我们要设法将其找出。

### 隐藏在图像中的二进制信息

如果让你想个办法，把一个二进制文件藏在图像里，你会怎么做？一个简单的方法是，把这个图像的每个像素的颜色分量对应加上你想隐藏的二进制文件的 0 和 1.

如果是普通的彩色图像，如此操作后很难解码出增加的噪声信息，但对于这张只有几个基本颜色的像素画，解码就不是很困难了。

还有一个细节也许可以支撑我们的猜想。`file` 命令的输出显示这是一张 `300 x 300` 的图像，但是看上去分辨率只有 `25 x 25`。也许是为了放下一个 `ELF` 文件的信息，把图像扩大了 12 倍。

接下来我们看看这个文件的颜色分布。

#### bmp2rgb.cc

这份代码读入一个 `bmp` 图像，输出每一个像素的 rgb 值，格式是每行一个 `#RRGGBB`。注意在 `bmp` 格式中三颜色分量的数据是 B 在前，R 在后。

```cpp
//bmp2rgb.cc
#include <iostream>
#include <vector>
#include <cstdio>
using namespace std;

/*
标准输入：完整 24 位 BMP 文件
标准输出：每行一个 #RRGGBB
*/

uint32_t read_le(const vector<unsigned char>& buf, int& pos, int size) {
    uint32_t v = 0;
    for (int i = 0; i < size; i++) {
        v |= (buf[pos++] << (8 * i));
    }
    return v;
}

int main() {
    // ---- 读入所有 stdin 数据到内存 ----
    vector<unsigned char> buf(
        (istreambuf_iterator<char>(cin)),
        istreambuf_iterator<char>()
    );
    int pos = 0;

    if (buf.size() < 54) {
        cerr << "输入太小，不是 BMP\n";
        return 1;
    }

    // ---- BMP header ----
    if (buf[0] != 'B' || buf[1] != 'M') {
        cerr << "不是 BMP 文件\n";
        return 1;
    }
    pos = 10;
    uint32_t pixel_offset = read_le(buf, pos, 4);
    pos = 14;

    uint32_t dib_size = read_le(buf, pos, 4);
    if (dib_size < 40) {
        cerr << "DIB header 太小\n";
        return 1;
    }

    int32_t width  = read_le(buf, pos, 4);
    int32_t height = read_le(buf, pos, 4);

    pos += 2; // planes
    uint16_t bpp = read_le(buf, pos, 2);
    if (bpp != 24) {
        cerr << "仅支持 24-bit BMP\n";
        return 1;
    }

    uint32_t compression = read_le(buf, pos, 4);
    if (compression != 0) {
        cerr << "不支持压缩 BMP\n";
        return 1;
    }

    // ---- 跳到像素数据 ----
    pos = pixel_offset;

    int row_bytes = width * 3;
    int padding = (4 - (row_bytes % 4)) % 4;
    int h = height > 0 ? height : -height;

    for (int y = 0; y < h; y++) {
        for (int x = 0; x < width; x++) {
            unsigned char b = buf[pos++];
            unsigned char g = buf[pos++];
            unsigned char r = buf[pos++];
            printf("#%02X%02X%02X\n", r, g, b);
        }
        pos += padding;
    }

    return 0;
}
```

#### rgb2json.cc

然后我们统计一下各颜色的分布情况。

```cpp
#include <iostream>
#include <map>
#include <string>
using namespace std;

/*
标准输入：每行一个 #RRGGBB
程序功能：统计颜色个数
标准输出：按 key 排序的 JSON
*/

int main() {
    map<string, int> cnt;
    string line;

    while (cin >> line) {
        cnt[line]++;
    }

    cout << "{\n";
    bool first = true;
    for (auto &p : cnt) {
        if (!first) cout << ",\n";
        first = false;
        cout << "  \"" << p.first << "\": " << p.second;
    }
    cout << "\n}\n";

    return 0;
}

```

使用 makefile 编译运行。

```
$ make rgb.json
g++ -O2 -std=c++11 -Wall -Wextra bmp2rgb.cc -o bmp2rgb
g++ -O2 -std=c++11 -Wall -Wextra rgb2json.cc -o rgb2json
./bmp2rgb < elf.bmp | ./rgb2json > rgb.json
```

`rgb.json` 的结果如下

```json
{
  "#000000": 17643,
  "#000001": 389,
  "#000100": 341,
  "#000101": 269,
  "#010000": 379,
  "#010001": 227,
  "#010100": 259,
  "#010101": 365,
  "#3A3A3A": 535,
  "#3A3A3B": 12,
  "#3A3B3A": 10,
  "#3A3B3B": 4,
  "#3B3A3A": 15,
  "#3B3A3B": 1,
  "#3B3B3A": 6,
  "#3B3B3B": 1433,
  "#54AA00": 720,
  "#54AA01": 27,
  "#54AB00": 19,
  "#54AB01": 20,
  "#55AA00": 8662,
  "#55AA01": 22,
  "#55AB00": 20,
  "#55AB01": 14,
  "#5E4106": 1440,
  "#FEFE00": 3093,
  "#FEFE01": 169,
  "#FEFEFE": 7157,
  "#FEFEFF": 381,
  "#FEFF00": 147,
  "#FEFF01": 143,
  "#FEFFFE": 357,
  "#FEFFFF": 287,
  "#FFD5B0": 6336,
  "#FFFE00": 199,
  "#FFFE01": 138,
  "#FFFEFE": 441,
  "#FFFEFF": 286,
  "#FFFF00": 1023,
  "#FFFF01": 128,
  "#FFFFFE": 281,
  "#FFFFFF": 36602
}
```

### 对颜色分布的分析

我们发现一些相近的颜色一起出现，比如伴随着大量出现的黑色 `#000000`，同时有少量的 `#000001` 或者 `#010101` 等的出现，变体包括自己一共有 8 个，刚好对应着三位二进制数。其他的还有 `#3A3A3A`  `#54AA00` `#FEFEFE`，都有对应三位二进制数的 8 个变体。

但同时还有两种颜色，`#5E4106` 和 `#FFD5B0`，没有变体，且出现次数都刚好是 144 的倍数，说明这两种颜色的像素没有加 01 噪声，处理的时候不应该算这两种颜色。

#### rgb2bits.cc

接下来我们尝试着编写代码，提取 Elf 图像中的 ELF。

具体的映射规则、小端大端等顺序，需要多次尝试，最后得到这个正确版本。

```cpp
// rgb2bits.cc
#include <iostream>
#include <string>
#include <map>
using namespace std;

/*
标准输入：每行一个 #RRGGBB
标准输出：对每行输出 3 个 bit，规则见 bit 内容
*/
map<string, char> bit{
    {"00", '0'},
    {"01", '1'},
    {"3A", '0'},
    {"3B", '1'},
    {"FE", '0'},
    {"FF", '1'},
    {"54", '0'},
    {"55", '1'},
    {"AA", '0'},
    {"AB", '1'},
};
int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    string s;
    while (cin >> s) {
        if(s.substr(1, 6) == "5E4106" || s.substr(1, 6) == "FFD5B0")
            continue;
        cout << bit[s.substr(5,2)] << bit[s.substr(3,2)] << bit[s.substr(1,2)];
    }
    return 0;
}
```

运行得到的 ELF 文件大概率是有大量无效信息在文件末尾的，我们需要使用 ELF 头中的信息计算有效大小并精确截取 ELF 文件对应的部分。

```
$ make elf_untruncated 
g++ -O2 -std=c++11 -Wall -Wextra rgb2bits.cc -o rgb2bits
./rgb2bits < rgb.txt | ./bits2bin > elf_untruncated

$ file elf_untruncated
elf_untruncated: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=3f43c1bc1bc2d1dccc12d2fbb1cb83347e8cb3b4, not stripped
```

计算一下 ELF 文件大小

```
$ readelf -h elf
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4004e0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          6912 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         31
  Section header string table index: 28
```

$$
\text{elf\_size}=6912+31\times 64+4=8896
$$

而当前的文件大小是 `30834`。的确需要截断。

```
$ ls -l elf_untruncated
-rw-rw-r-- 1 binary binary 30834 nov 21 13:38 elf_untruncated
```

使用 `dd` 截取文件。

```
$ dd count=8896 if=elf_untruncated of=elf bs=1
8896+0 records in
8896+0 records out
8896 bytes (8,9 kB, 8,7 KiB) copied, 0,0206838 s, 430 kB/s
```

### 对 elf 文件的分析

直接运行没有任何输出。`.data` 段有 `0x53=83` 个不知何意的字节。

```
$ readelf -x .data -x .rodata elf

Hex dump of section '.rodata':
  0x00400730 01000200                            ....


Hex dump of section '.data':
  0x00601040 00000000 00000000 00000000 00000000 ................
  0x00601050 00000000 00000000 00000000 00000000 ................
  0x00601060 9c9d9e9a 9b74cdcc cccc73cd cccccc84 .....t....s.....
  0x00601070 41f9d4cc cccc8447 d9fecccc ccc3c993 A......G........
  0x00601080 92969594 74f0cccc cc84fd33 c3c9fefe ....t......3....
  0x00601090 fff9adfa aefefdfe fff8fcf8 f8faf5aa ................
  0x006010a0 f8adaeaf a9fbfdae fda8a8fe f5aaccec ................
  0x006010b0 cccccc00 53000000                   ....S...
```

因为该文件没有被 stripped，我们直接看一下汇编代码。

```
00000000004005d6 <main>:
  4005d6:	55                   	push   rbp
  4005d7:	48 89 e5             	mov    rbp,rsp
  4005da:	48 83 ec 30          	sub    rsp,0x30
  4005de:	89 7d dc             	mov    DWORD PTR [rbp-0x24],edi
  4005e1:	48 89 75 d0          	mov    QWORD PTR [rbp-0x30],rsi
  
// 后续没有使用 [rbp-0x30] 和 [rbp-0x24]，应该没用上参数

  4005e5:	be 00 10 00 00       	mov    esi,0x1000
  4005ea:	bf 00 10 00 00       	mov    edi,0x1000
  4005ef:	e8 bc fe ff ff       	call   4004b0 <memalign@plt>
  
// memalign(4096, 4096) = 0x9bc000
//  *(rbp-0x10) = 0x9bc000
// char flag_bin[] = 0x9bc000

  4005f4:	48 89 45 f0          	mov    QWORD PTR [rbp-0x10],rax
  4005f8:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  4005fc:	ba 03 00 00 00       	mov    edx,0x3
  400601:	be 00 10 00 00       	mov    esi,0x1000
  400606:	48 89 c7             	mov    rdi,rax
  400609:	e8 b2 fe ff ff       	call   4004c0 <mprotect@plt>

// mprotect(0x9bc000, 4096, PROT_READ | PROT_WRITE = 3) = 0
// flag_bin_len = 83

  40060e:	8b 05 a0 0a 20 00    	mov    eax,DWORD PTR [rip+0x200aa0]        # 6010b4 <flag_bin_len>
  400614:	89 c2                	mov    edx,eax
  400616:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  40061a:	be 60 10 60 00       	mov    esi,0x601060
  40061f:	48 89 c7             	mov    rdi,rax
  400622:	e8 79 fe ff ff       	call   4004a0 <memcpy@plt>

// memcpy(0x9bc000, 0x601060, 83) = 0x9bc000
// flag_bin[0~82] = 9c9d9e9a...

  400627:	8b 05 87 0a 20 00    	mov    eax,DWORD PTR [rip+0x200a87]        # 6010b4 <flag_bin_len>
  40062d:	89 c2                	mov    edx,eax
  40062f:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  400633:	48 01 d0             	add    rax,rdx
  400636:	c6 00 c3             	mov    BYTE PTR [rax],0xc3

// flag_bin[83] = 0xc3 = ret 指令

  400639:	c7 45 ec 00 00 00 00 	mov    DWORD PTR [rbp-0x14],0x0
  400640:	eb 26                	jmp    400668 <main+0x92>
  400642:	8b 45 ec             	mov    eax,DWORD PTR [rbp-0x14]
  400645:	48 63 d0             	movsxd rdx,eax
  400648:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  40064c:	48 01 d0             	add    rax,rdx
  40064f:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
  400652:	48 63 ca             	movsxd rcx,edx
  400655:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
  400659:	48 01 ca             	add    rdx,rcx
  40065c:	0f b6 12             	movzx  edx,BYTE PTR [rdx]
  40065f:	83 f2 cc             	xor    edx,0xffffffcc
  400662:	88 10                	mov    BYTE PTR [rax],dl
  400664:	83 45 ec 01          	add    DWORD PTR [rbp-0x14],0x1
  400668:	8b 55 ec             	mov    edx,DWORD PTR [rbp-0x14]
  40066b:	8b 05 43 0a 20 00    	mov    eax,DWORD PTR [rip+0x200a43]        # 6010b4 <flag_bin_len>
  400671:	39 c2                	cmp    edx,eax
  400673:	72 cd                	jb     400642 <main+0x6c>
/*
for(i = 0; i < flag_bin_len; i++) {
  a[i] = a[i] ^ 0xcc
}
*/
  400675:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  400679:	ba 04 00 00 00       	mov    edx,0x4
  40067e:	be 00 10 00 00       	mov    esi,0x1000
  400683:	48 89 c7             	mov    rdi,rax
  400686:	e8 35 fe ff ff       	call   4004c0 <mprotect@plt>
  
// mprotect(0x9bc000, 4096, PROT_EXEC = 4) = 0

  40068b:	48 8b 45 f0          	mov    rax,QWORD PTR [rbp-0x10]
  40068f:	8b 15 1f 0a 20 00    	mov    edx,DWORD PTR [rip+0x200a1f]        # 6010b4 <flag_bin_len>
  400695:	89 d2                	mov    edx,edx
  400697:	48 01 d0             	add    rax,rdx
  40069a:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  40069e:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  4006a2:	b8 00 00 00 00       	mov    eax,0x0
  4006a7:	ff d2                	call   rdx
// call flag_bin[83] <- 应该是要改这里
  4006a9:	b8 00 00 00 00       	mov    eax,0x0
  4006ae:	c9                   	leave  
  4006af:	c3                   	ret    
```

总结一下，这份代码
- 使用 `memalign` + `mprotect` 申请了一块对齐的可读写内存，把 `.data` 段中从 `0x601060` 开始的 83 个字节拷贝到申请内存中。
	- 由遗留下来的符号 `flag_bin_len` 可以猜测出，这 83 个字节应该就是 `flag_bin`，运行后可以生成我们想要的 flag。
- 对遍历 `flag_bin[0~82]` 异或 `0xcc` 后，得到解码后的可执行代码段
- 为了执行这一部分代码，需要使用 `mprotect` 将这段内存的权限改为 `PROT_EXEC`
- 但是最后执行的是 `call flag_bin[83]`，而偏移 83 处是先前写入的 `ret` 指令。也就是说，程序会在 `call` 之后立马 `ret` 回来。这显然不是我们想要的。

因此，我们需要让程序执行 `call flag_bin`。只需要把 `40069e` 处的 `mov rdx,QWORD PTR [rbp-0x8]` 改成 `mov rdx,QWORD PTR [rbp-0x10]` 即可。

正愁要学命令格式呢，刚好，这句话就在 `400655` 出现过。

```
  400655:	48 8b 55 f0          	mov    rdx,QWORD PTR [rbp-0x10]
```

所以我们需要把 elf 文件 `0x6a1` 处的 `f8` 改为 `f0`。在 makefile 中写好命令后，运行

```
$ make elf_repaired 
cp elf elf_repaired
printf "\360" | dd of=elf_repaired bs=1 seek=$((0x6a1)) conv=notrunc
1+0 records in
1+0 records out
1 byte copied, 0,000584963 s, 1,7 kB/s
chmod 777 elf_repaired
```

使用 `printf "\360"` 而非 `printf "\xf0"` 是因为 `\xf0` 会被 makefile 解释为 UTF-8 的 4 字节字符，具体原因未知。

```
$ ./elf_repaired
2235a6b2123404469f4abce71b1dd29f �A�
```

虽然最后有个莫名其妙的 `�A�`，但我们不管它。

```
$ ./oracle 2235a6b2123404469f4abce71b1dd29f
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
| Level 8 completed, unlocked reward.tar.gz |
+~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~+
Run oracle with -h to show a hint
```

## Reward

迫不及待地用 `tar` 打开我们来之不易的 `reward.tar.gz`

```
$ tar xvzf reward.tar.gz
runme.sh
wall_1024x768.jpg
wall_1920x1080.jpg
wall_1920x1200.jpg
$ ./runme.sh
Setting wallpaper... Done!
```

![[wall_1920x1200.jpg]]

感谢观看
