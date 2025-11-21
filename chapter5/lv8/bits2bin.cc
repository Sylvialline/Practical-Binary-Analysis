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

        byte = (byte << 1) | (bit - '0');
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
