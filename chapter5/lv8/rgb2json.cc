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
