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
