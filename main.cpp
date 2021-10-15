#include"include/main.h"
int test1(){
    AutoSeededRandomPool rnd;
    RSA::PrivateKey pri_key;
    pri_key.GenerateRandomWithKeySize(rnd,2048);
    RSA::PublicKey pub_key(pri_key);
    SaveHexPrivateKey("keys/rsa-private.key", pri_key);
    SaveHexPublicKey("keys/rsa-public.key", pub_key);
    //SaveBase64PrivateKey("keys/rsa-private.key", pri_key);
    //SaveBase64PublicKey("keys/rsa-public.key", pub_key);
    try
    {
        RSA::PrivateKey k1;
        //LoadBase64PrivateKey("keys/rsa-private.key", k1);
        LoadHexPrivateKey("keys/rsa-private.key",k1);


        RSA::PublicKey k2;
        //LoadBase64PublicKey("keys/rsa-public.key", k2);
        LoadHexPublicKey("keys/rsa-public.key",k2);
        cout << "Successfully loaded RSA keys" << endl;

        ////////////////////////////////////////////////////////////////////////////////////

        if(!k1.Validate(rnd, 3))
            throw runtime_error("Rsa private key validation failed");

        if(!k2.Validate(rnd, 3))
            throw runtime_error("Rsa public key validation failed");

        cout << "Successfully validated RSA keys" << endl;

        ////////////////////////////////////////////////////////////////////////////////////

        if(k1.GetModulus() != k2.GetModulus() ||
           k1.GetPublicExponent() != k2.GetPublicExponent())
        {
            throw runtime_error("key data did not round trip");
        }

        cout << "Successfully round-tripped RSA keys" << endl;
    }
    catch(CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        return -1;
    }
    return 0;
}

//把 PEM 编码格式的密钥通过 Base64Encoder 解编码为可以使用 BEREncode 编码成 Cryptopp 使用密钥形式
void test2(){
    string RSA_PRIV_KEY =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAK8Q+ToR4tWGshaKYRHKJ3ZmMUF6jjwCS/u1A8v1tFbQiVpBlxYB\n"
    "paNcT2ENEXBGdmWqr8VwSl0NBIKyq4p0rhsCAQMCQHS1+3wL7I5ZzA8G62Exb6RE\n"
    "INZRtCgBh/0jV91OeDnfQUc07SE6vs31J8m7qw/rxeB3E9h6oGi9IVRebVO+9zsC\n"
    "IQDWb//KAzrSOo0P0yktnY57UF9Q3Y26rulWI6LqpsxZDwIhAND/cmlg7rUz34Pf\n"
    "SmM61lJEmMEjKp8RB/xgghzmCeI1AiEAjvVVMVd8jCcItTdwyRO0UjWU4JOz0cnw\n"
    "5BfB8cSIO18CIQCLVPbw60nOIpUClNxCJzmMLbsrbMcUtgVS6wFomVvsIwIhAK+A\n"
    "YqT6WwsMW2On5l9di+RPzhDT1QdGyTI5eFNS+GxY\n"
    "-----END RSA PRIVATE KEY-----";

    static string HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    static string FOOTER = "-----END RSA PRIVATE KEY-----";
        
    size_t pos1, pos2;
    pos1 = RSA_PRIV_KEY.find(HEADER);
    if(pos1 == string::npos)
        throw runtime_error("PEM header not found");
        
    pos2 = RSA_PRIV_KEY.find(FOOTER, pos1+1);
    if(pos2 == string::npos)
        throw runtime_error("PEM footer not found");
        
    // Start position and length
    pos1 = pos1 + HEADER.length();
    pos2 = pos2 - pos1;
    string keystr = RSA_PRIV_KEY.substr(pos1, pos2);

    // Base64 decode, place in a ByteQueue    
    ByteQueue queue;
    Base64Decoder decoder;

    decoder.Attach(new Redirector(queue));
    decoder.Put((const byte*)keystr.data(), keystr.length());
    decoder.MessageEnd();

    // Write to file for inspection
    FileSink fs("keys/decoded-key.der");
    queue.CopyTo(fs);
    fs.MessageEnd();

    try
    {
        CryptoPP::RSA::PrivateKey rsaPrivate;
        rsaPrivate.BERDecodePrivateKey(queue, false /*paramsPresent*/, queue.MaxRetrievable());

        // BERDecodePrivateKey is a void function. Here's the only check
        // we have regarding the DER bytes consumed.
        assert(queue.IsEmpty());
        
        AutoSeededRandomPool prng;
        bool valid = rsaPrivate.Validate(prng, 3);
        if(!valid)
            cerr << "RSA private key is not valid" << endl;
        
        cout << "N:" << rsaPrivate.GetModulus() << endl;
        cout << "E:" << rsaPrivate.GetPublicExponent() << endl;
        cout << "D:" << rsaPrivate.GetPrivateExponent() << endl;
        
    }
    catch (const Exception& ex)
    {
        cerr << ex.what() << endl;
        exit (1);
    }
}


int main(){
    AutoSeededRandomPool rnd;
    test2();
    return 0;
}