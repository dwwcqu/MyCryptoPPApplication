#ifndef ENCODEANDDECODE_H
#define ENCODEANDDECODE_H
#include<iostream>
#include<string>
#include<cryptopp/rsa.h>
#include<cryptopp/dsa.h>
#include<cryptopp/files.h>
#include<cryptopp/aes.h>
#include<cryptopp/osrng.h>
#include<cryptopp/hex.h>
#include<cryptopp/xed25519.h>
#include<cryptopp/base64.h>
#include<exception>
using namespace CryptoPP;
using std::cout;
using std::cin; 
using std::endl;
using std::string;
using std::cerr;
using std::runtime_error;

//PKCS#8 对私钥进行 Encode 和 Decode ,X.509对公钥进行 Encode 和 Decode
//即实现对公私钥的 Save 和 Load(保存和加载)
void Save(const string& filename, const BufferedTransformation& bt);
void SavePublicKey(const string& filename, const PublicKey& key);

void Load(const string& filename, BufferedTransformation& bt);
void LoadPublicKey(const string& filename, PublicKey& key);



//使用 DEREncodePublicKey 和 DEREncodePrivateKey 实现对公私钥的 Encode (编码)
void Encode(const string& filename, const BufferedTransformation& bt);
void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key);
void EncodePublicKey(const string& filename, const RSA::PublicKey& key);



//使用 EBRDecodePublicKey 和 EBRDecodePrivateKey 实现对公私钥的 Decode (编码)
void Decode(const string& filename, BufferedTransformation& bt);
void DecodePrivateKey(const string& filename, RSA::PrivateKey& key);
void DecodePublicKey(const string& filename, RSA::PublicKey& key);



//使用 HexEncoder 和 HexDecoder 对公私钥进行编码(Encode/Decode)
void SaveHexPrivateKey(const string& filename, const PrivateKey& key);
void SaveHexPublicKey(const string& filename, const PublicKey& key);
void SaveHex(const string& filename, const BufferedTransformation& bt);

void LoadHexPrivateKey(const string& filename,const PrivateKey& key);
void LoadHexPublicKey(const string& filename,const PublicKey& key);
void LoadHex(const string& filename,const BufferedTransformation& bt);

//使用 Base64Encoder 和 Base64Decoder 对公私钥进行编码(Encode/Decode)
void SaveBase64PrivateKey(const string& filename, const PrivateKey& key);
void SaveBase64PublicKey(const string& filename, const PublicKey& key);
void SaveBase64(const string& filename, const BufferedTransformation& bt);

void LoadBase64PrivateKey(const string& filename,const PrivateKey& key);
void LoadBase64PublicKey(const string& filename,const PublicKey& key);
void LoadBase64(const string& filename,const BufferedTransformation& bt);

#endif