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
    i=0;
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
