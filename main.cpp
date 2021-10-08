#include<iostream>
#include<string>
#include<cryptopp/dll.h>
#include<cryptopp/files.h>
#include<cryptopp/aes.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
using namespace CryptoPP;
using std::cout;
using std::cin;
using std::endl;
using std::string;
int main(){
    AutoSeededRandomPool prng;
    string str ="First Test";
    string des;
    StringSource(str,true,new HexEncoder(new StringSink(des)));
    cout << "des = " << des << '\n';
    return 0;
}