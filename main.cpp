#include"include/main.h"

int main(){
    AutoSeededRandomPool rnd;
    try
    {
        RSA::PrivateKey k1;
        DecodePrivateKey("keys/rsa-private.key", k1);

        RSA::PublicKey k2;
        DecodePublicKey("keys/rsa-public.key", k2);

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