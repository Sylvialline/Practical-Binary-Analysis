#include <iostream>
#include <cctype>
using namespace std;

/*
标准输入：任意文本
标准输出：看到字母则输出 bit（小写=0，大写=1）
非字母忽略
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
