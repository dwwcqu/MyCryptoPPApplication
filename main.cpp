#include<cryptopp/files.h>
#include<cryptopp/aes.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<iostream>
#include<string>
using namespace CryptoPP;
using std::cout;
using std::cin;
using std::endl;
using std::string;
int main(){
    AutoSeededRandomPool prng;
    string str ="First Test";
    string des;
    StringSource(str,new HexDecoder(new StringSink(des)));
    cout << "des = " << des;
    return 0;
}