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
#include<exception>
using namespace CryptoPP;
using std::cout;
using std::cin; 
using std::endl;
using std::string;
using std::cerr;
using std::runtime_error;
/*
//PKCS#8 对私钥进行 Encode 和 Decode ,X.509对公钥进行 Encode 和 Decode
//即实现对公私钥的 Save 和 Load(保存和加载)
void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
    //HexEncoder encoder(new FileSink(filename.c_str()));
    ByteQueue queue;
    //HexEncoder encoder;
    key.Save(queue);
    Save(filename, queue);
}
*/
/*
void Load(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true );//pumpAll/

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}
*/
//使用 DEREncodePublicKey 和 DEREncodePrivateKey 实现对公私钥的 Encode (编码)
void Encode(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void EncodePrivateKey(const string& filename, const RSA::PrivateKey& key)
{
    ByteQueue queue;
    key.DEREncodePrivateKey(queue);

    Encode(filename, queue);
}

void EncodePublicKey(const string& filename, const RSA::PublicKey& key)
{
    ByteQueue queue;
    key.DEREncodePublicKey(queue);

    Encode(filename, queue);
}

//使用 EBRDecodePublicKey 和 EBRDecodePrivateKey 实现对公私钥的 Decode (编码)
void Decode(const string& filename, BufferedTransformation& bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}
void DecodePrivateKey(const string& filename, RSA::PrivateKey& key)
{
    ByteQueue queue;

    Decode(filename, queue);
    key.BERDecodePrivateKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
}

void DecodePublicKey(const string& filename, RSA::PublicKey& key)
{
    ByteQueue queue;

    Decode(filename, queue);
    key.BERDecodePublicKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());
}

#endif