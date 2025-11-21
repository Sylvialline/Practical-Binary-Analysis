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
