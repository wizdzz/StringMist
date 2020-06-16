//blowfish.h
//This code is in the public domain.
//Created by Taylor Hornby 
//May 8, 2010.
//Ported from my C# blowfish code which was ported from the JavaScript crypto library found here:
//  http://etherhack.co.uk/symmetric/blowfish/blowfish.html
//Complies with the test vectors:  http://www.schneier.com/code/vectors.txt
//Description:
//  Blowfish is a keyed, symmetric block cipher, designed in 1993 by Bruce Schneier and
//  included in a large number of cipher suites and encryption products. Blowfish provides
//  a good encryption rate in software and no effective cryptanalysis of it has been found to date.
//Key Size: 32 to 448 bits
//Block Size: 64 bits
//Rounds: 16 (up to 256 rounds can be used with this class, change the '#define ROUNDS' line)
//More Information: http://www.schneier.com/paper-blowfish-fse.html and http://en.wikipedia.org/wiki/Blowfish_cipher

/*  Cryptography 101 - How to implement properly

This class provides two modes of encryption, CBC and ECB. With ECB, the same data encrypted with the same key will
produce the same result. Patterns will also be visible in the ciphertext. ECB mode should not be used unless it is
specifically needed. CBC mode ensures that no patterns are present in the ciphertext, and that the same data
encrypted with the same key, yeilds a different ciphertext.

Whenever encrypting data, ALWAYS verify the authenticity of the data BEFORE decrypting. To do this, use a HMAC:
token = HMAC(ciphertext, key)
Include this token with the data, and verify it by computing the HMAC again. This ensures that without the key,
an attacker cannot modify the ciphertext. This is especially important with CBC mode, without verification, the
attacker can control the value of the first block of plaintext by modifying the IV.

-   When using CBC mode, always use a random and unique IV. SetRandomIV() will do this for you.
-   Blowfish is only as secure as the encryption key you provide. To create a key from a password,
    run it through a hash algorithm such as SHA-256
*/

/* Use

#include <iostream>
#include <string.h>
#include "blowfish.h"
using namespace std;
typedef unsigned char byte;
int main()
{
    BLOWFISH bf("FEDCBA9876543210");
    string asdf = "BlowwFIshhhhhhhhhhh!";
    asdf = bf.Encrypt_CBC(asdf);
    cout << "Encrypted: " << asdf << endl;
    asdf = bf.Decrypt_CBC(asdf);
    cout << "Decrypted: " << asdf;
    return 0;
}


*/

#ifndef BLOWFISH_INCLUDED
#define BLOWFISH_INCLUDED

#include <string>

//headers needed for the CSPRNG
#ifdef _WIN32
    #include <Windows.h>
    #include <Wincrypt.h>
#else
    #include <fstream> //for reading from /dev/urandom on *nix systems
#include <cstring>
#include <dlfcn.h>

#endif

typedef unsigned char byte;

class BLOWFISH{

    //Although there is no successful cryptanalysis of the 16 round version, a higher number of rounds generally means more security.
    //STANDARD: 16
    //MAXIMUM: 256
    //**MUST be an EVEN number**
    #define ROUNDS 16
    public:
        BLOWFISH(std::string hexKey);
        BLOWFISH(byte* cipherKey, int keylength);

        //TODO: string encryption functions -> base64
        std::string Encrypt_CBC(std::string data);
        byte* Encrypt_CBC(byte* data, int length, int* newlength);
        byte* Encrypt_ECB(byte* data, int length, int* newlength);
        void Encrypt_Block(byte* block, int offset = 0);

        std::string Decrypt_CBC(std::string data);
        byte* Decrypt_CBC(byte* data, int length, int* newlength);
        byte* Decrypt_ECB(byte* data, int length, int* newlength);
        void Decrypt_Block(byte* block, int offset = 0);

        void SetRandomIV();
        void SetIV(byte* newIV);
        byte* GetIV();
        bool IvSet;

    protected:
        void initBox();
        void SetupKey(byte* cipherKey, int length);
        void encipher();
        void decipher();
        unsigned int round(unsigned int a, unsigned int b, unsigned int n);
        void setblock(byte* block, int offset);
        void getblock(byte* block, int offset);
        unsigned int p[268];
        unsigned int s0[256];
        unsigned int s1[256];
        unsigned int s2[256];
        unsigned int s3[256];

        static unsigned int g_p[];
        static unsigned int g_s0[];
        static unsigned int g_s1[];
        static unsigned int g_s2[];
        static unsigned int g_s3[];

        unsigned int xl_par;
        unsigned int xr_par;

        byte IV[8];

        byte* Crypt_ECB(byte* data, int length, int* newlength, void (BLOWFISH::*CryptBlock)(byte*, int offset), bool decrypt);
        byte* Crypt_CBC(byte* data, int length, int* newlength, void (BLOWFISH::*CryptBlock)(byte*, int offset), bool decrypt);
        byte* padData(byte* data, int length, int* paddedLength, bool decrypt, bool IvSpace);
        int findPaddingEnd(byte* data, int length);
        int hex2dec(char hex);
        std::string byteToHex(unsigned char x);
};

    BLOWFISH::BLOWFISH(std::string hexKey)
    {
        initBox();

        IvSet = false;
        if(hexKey.length() % 2 != 0)
            throw 2;
        byte key[hexKey.length() / 2];
        for(int i = 0; i < hexKey.length() / 2; i++)
        {
            key[i] = hex2dec(hexKey[i * 2]) * 16 + hex2dec(hexKey[i * 2 + 1]);
        }
        SetupKey(key, hexKey.length() / 2);
    }

    int BLOWFISH::hex2dec(char hex)
    {
        if('a' <= hex && hex <= 'f')
            return 10 + (hex - 'a');
        if('A' <= hex && hex <= 'F')
            return 10 + (hex - 'A');
        return hex - '0';
    }

    BLOWFISH::BLOWFISH(byte* cipherKey, int keyLength)
    {
        initBox();

        IvSet = false;
        SetupKey(cipherKey, keyLength);
    }

    byte* BLOWFISH::Encrypt_ECB(byte* data, int length, int* newlength)
    {
        return Crypt_ECB(data,length, newlength, &BLOWFISH::Encrypt_Block, false);
    }

    byte* BLOWFISH::Decrypt_ECB(byte* data, int length, int* newlength)
    {
        return Crypt_ECB(data,length, newlength, &BLOWFISH::Decrypt_Block, true);
    }

    byte* BLOWFISH::Encrypt_CBC(byte* data, int length, int* newlength)
    {
        return Crypt_CBC(data,length, newlength, &BLOWFISH::Encrypt_Block, false);
    }

    byte* BLOWFISH::Decrypt_CBC(byte* data, int length, int* newlength)
    {
        return Crypt_CBC(data,length, newlength, &BLOWFISH::Decrypt_Block, true);
    }

    std::string BLOWFISH::Encrypt_CBC(std::string data)
    {
        byte* binaryData = new byte[data.length()];
        for(int i = 0; i < data.length(); i++)
            binaryData[i] = data[i];
        int newlen = 0;
        byte* result = Encrypt_CBC(binaryData,data.length(), &newlen);
        std::string encoded = "";
        for(int i = 0; i < newlen; i++)
            encoded += byteToHex(result[i]);
        delete [] result;
        delete [] binaryData;
        return encoded;
    }

    std::string BLOWFISH::Decrypt_CBC(std::string data)
    {
        if(data.length() % 2 != 0)
            throw 2;
        byte binaryData[data.length() / 2];
        for(int i = 0; i < data.length() / 2; i++)
        {
            binaryData[i] = hex2dec(data[i * 2]) * 16 + hex2dec(data[i * 2 + 1]);
        }
        int len = 0;
        byte* cryptresult = Decrypt_CBC(binaryData, data.length() / 2, &len);
        std::string result = "";
        for(int i = 0; i < len; i++)
            result += cryptresult[i];
        delete [] cryptresult;
        return result;
    }

    std::string BLOWFISH::byteToHex(unsigned char x)
    {
        char hex[17] = "0123456789ABCDEF";
        std::string result = "";
        result += hex[x / 16];
        result += hex[x % 16];
        return result;
    }

    byte* BLOWFISH::padData(byte* data, int length, int* paddedLength, bool decrypt, bool IvSpace = false)
    {
        int offset = 0;
        int dataoffset = 0;
        if(decrypt)
        {
            if(length % 8 != 0) throw 8;
            *paddedLength = length;
        }
        else
        {
            //if IvSpace, leave a blank block at the front
            *paddedLength = 8 + (length % 8 == 0 ? length : length + 8 - (length % 8)) + (IvSpace ? 8 : 0); //pad the data to a multiple of 8 plus one block
            if(IvSpace)
                offset = 8;
        }

        //fill the new array with the data
        byte* pData = new byte[*paddedLength];
        for(int i = 0; i < length; i++)
            pData[offset + i] = data[i + dataoffset];

        //add the padding character to the end
        for(int i = length + offset; i < *paddedLength; i++)
            pData[i] = (pData[length - 1 + offset] ^ 0xCC); //fill the padding with a character that is different from the last character in the plaintext, so we can find the end later

        return pData;
    }

    int BLOWFISH::findPaddingEnd(byte* data, int length)
    {
        int i = length;
        while(data[i - 1] == data[length - 1]) //find the first character from the back that isnt the same as the last character
        {
            i--;
        }
        return i; //retun the length without the padding
    }

    byte* BLOWFISH::Crypt_ECB(byte* data, int length, int* newlength, void (BLOWFISH::*CryptBlock)(byte*, int ), bool decrypt)
    {
        byte* pData;
        pData = padData(data,length,newlength, decrypt); //this loads the IV from the front of the ciphertext

        for(int i = 0; i < *newlength; i+=8) //run the encryption
        {
            (this->*CryptBlock)(pData,i);
        }

        if(decrypt) //if we are decrypting, we have to find where the data ends.
        {
            *newlength = findPaddingEnd(pData,*newlength);
        }
        return pData;
    }

    byte* BLOWFISH::Crypt_CBC(byte* data, int length, int* newlength, void (BLOWFISH::*CryptBlock)(byte*, int ), bool decrypt)
    {
        byte* pData;
        if(!decrypt && !IvSet)
            SetRandomIV();
        IvSet = false; // don't re-use an IV
        pData = padData(data,length,newlength, decrypt, true);

        if(!decrypt)
        {
            //padData leaves an 8 byte block at the beggining so we can save the IV
            for(int i = 0; i < 8; i++)
                pData[i] = IV[i];
        }
        else
        {
            for(int i = 0; i < 8; i++)
                IV[i] = pData[i];
        }
        byte nextIV[8];
        for(int i = 8; i < *newlength; i+=8) //run the encryption
        {
            if(!decrypt)
            {
                for(int k = 0; k < 8; k++)
                    pData[k + i] ^= pData[k + i - 8]; //the previous block contains the initialization vector
            }
            else
            {
                for(int k = 0; k < 8; k++)
                    nextIV[k] = pData[k + i];
            }
            (this->*CryptBlock)(pData,i);

            if(decrypt)
            {
                for(int k = 0; k < 8; k++)
                {
                    pData[i + k] ^= IV[k];
                    IV[k] = nextIV[k];
                }
            }
        }

        if(decrypt) //if we are decrypting, we have to find where the data ends, and remove the IV
        {
            *newlength = findPaddingEnd(pData,*newlength) - 8;
            byte* noIV = new byte[*newlength];
            for(int i = 0; i < *newlength; i++)
                noIV[i] = pData[i + 8];
            delete [] pData;
            pData = noIV;
        }
        return pData;
    }

    void BLOWFISH::SetRandomIV()
    {
        #ifdef _WIN32
        //WIN32 CSPRNG thanks to: http://www.tomhandal.com/DevBlog/2010/03/17/cryptographically-random-bytes-in-microsoft-windows/
        HCRYPTPROV hCryptCtx = NULL;
        CryptAcquireContext(&hCryptCtx, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        CryptGenRandom(hCryptCtx, 8, IV);
        CryptReleaseContext(hCryptCtx, 0);
        #else
        std::ifstream devRand ("/dev/urandom", std::ios::in | std::ios::binary);
        if(!devRand.read((char*)&IV,8))
        {
            throw 1;
        }
        #endif
        IvSet = true;
    }

    void BLOWFISH::SetIV(byte* newIV)
    {
        IvSet = true;
        for(int i = 0; i < 8; i++)
            IV[i] = newIV[i];
    }

    byte* BLOWFISH::GetIV()
    {
        byte* returnIV = new byte[8];
        for(int i = 0; i < 8; i++)
            returnIV[i] = IV[i];
        return returnIV;
    }

    void BLOWFISH::Encrypt_Block(byte* block, int offset)
    {
        setblock(block,offset);
        encipher();
        getblock(block,offset);
    }

    void BLOWFISH::Decrypt_Block(byte* block, int offset)
    {
        setblock(block,offset);
        decipher();
        getblock(block,offset);
    }

    void BLOWFISH::setblock(byte* block, int offset)
    {
        //TODO: CHECK ENDIANNESS
        xr_par = 0; xl_par = 0;
        for(int i = 0; i < 4; i++)
        {
            xl_par = (xl_par << 8) + block[offset + i];
            xr_par = (xr_par << 8) + block[4 + offset + i];
        }
    }

    void BLOWFISH::getblock(byte* block, int offset)
    {
        //TODO: CHECK ENDIANNESS
        unsigned int xl = xl_par;
        unsigned int xr = xr_par;
        for(int i = 3; i >= 0; i--)
        {
            block[i + offset] = xl % 256;
            block[i + 4 + offset] = xr % 256;
            xr = xr >> 8;
            xl = xl >> 8;
        }
    }

    void BLOWFISH::SetupKey(byte* cipherKey, int length)
    {
        if(length > 56)
        {
            throw 56;
        }
        byte key[length];
        for(int i = 0; i < length; i++)
            key[i] = cipherKey[i];

        int j = 0;
        unsigned int d;
        for(int i = 0; i < 18; i++)
        {
            d = (((key[j % length] * 256 + key[(j + 1) % length]) * 256 + key[(j + 2) % length]) * 256 + key[(j + 3) % length]);
            p[i] ^= d;
            j = (j + 4) % length;
        }

        xl_par = 0;
        xr_par = 0;

        for(int i = 0; i < 18; i+=2)
        {
            encipher();
            p[i] = xl_par;
            p[i + 1] = xr_par;
        }

        for(int i = 0; i < 256; i+=2)
        {
            encipher();
            s0[i] = xl_par;
            s0[i + 1] = xr_par;
        }

        for(int i = 0; i < 256; i+=2)
        {
            encipher();
            s1[i] = xl_par;
            s1[i+ 1] = xr_par;
        }

        for(int i = 0; i < 256; i+=2)
        {
            encipher();
            s2[i] = xl_par;
            s2[i + 1] = xr_par;
        }

        for(int i = 0; i < 256; i+=2)
        {
            encipher();
            s3[i] = xl_par;
            s3[i + 1] = xr_par;
        }

    }

    void BLOWFISH::encipher()
    {
        xl_par ^= p[0];
        for(int i = 0; i < ROUNDS; i+=2)
        {
            xr_par = round(xr_par, xl_par, i + 1);
            xl_par = round(xl_par, xr_par, i + 2);
        }
        xr_par ^= p[ROUNDS + 1];

        std::swap(xl_par, xr_par);
    }

    void BLOWFISH::decipher()
    {
        xl_par ^= p[ROUNDS + 1];
        for(int i = ROUNDS; i > 0; i -= 2)
        {
            xr_par = round(xr_par, xl_par, i);
            xl_par = round(xl_par, xr_par, i - 1);
        }
        xr_par ^= p[0];

        std::swap(xl_par, xr_par);
    }

    unsigned int BLOWFISH::round(unsigned int a, unsigned int b, unsigned int n)
    {
        //TODO: CHECK ENDIANNESS
        unsigned int x1 = (s0[(b >> 24) % 256] + s1[(b >> 16) % 256]) ^ s2[(b >> 8) % 256];
        unsigned int x2 = x1 + s3[b % 256];
        unsigned int x3 = x2 ^ p[n];
        return x3 ^ a;
    }

    unsigned int BLOWFISH::g_s0[] = {
        0xd1310bc3, 0x94dfb5cc, 0x4ffd74db, 0xd01cdfb7,
        0xb4e1cfed, 0x3c437e93, 0xbc7c9045, 0xf14c7f99,
        0x44c19947, 0xb3913cf7, 0x401f4e4, 0x454efc13,
        0x333940d4, 0x71574e39, 0xc454fec3, 0xf4933d7e,
        0xd95744f, 0x744eb354, 0x714bcd54, 0x44154cee,
        0x7b54c41d, 0xc45c59b5, 0x9c30d539, 0x4cf43013,
        0xc5d1b043, 0x443045f0, 0xcc417914, 0xb4db34ef,
        0x4e79dcb0, 0x303c140e, 0x3c9e0e4b, 0xb01e4c3e,
        0xd71577c1, 0xbd314b47, 0x74cf4fdc, 0x55305c30,
        0xe35545f3, 0xcc55cb94, 0x57449434, 0x33e41440,
        0x55cc393c, 0x4ccb10b3, 0xb4cc5c34, 0x1141e4ce,
        0xc15443cf, 0x7c74e993, 0xb3ee1411, 0x333fbc4c,
        0x4bc9c55d, 0x741431f3, 0xce5c3e13, 0x9b47931e,
        0xcfd3bc33, 0x3c44cf5c, 0x7c345341, 0x44954377,
        0x3b4f4494, 0x3b4bb9cf, 0xc4bfe41b, 0x33444193,
        0x31d409cc, 0xfb41c991, 0x447ccc30, 0x5dec4034,
        0xef445d5d, 0xe94575b1, 0xdc434304, 0xeb351b44,
        0x43493e41, 0xd393ccc5, 0xf3d3ff3, 0x43f44439,
        0x4e0b4444, 0xc4444004, 0x39c4f04c, 0x9e1f9b5e,
        0x41c33444, 0xf3e93c9c, 0x370c9c31, 0xcbd344f0,
        0x3c51c0d4, 0xd4544f34, 0x930fc744, 0xcb5133c3,
        0x3eef0b3c, 0x137c3be4, 0xbc3bf050, 0x7efb4c94,
        0xc1f1351d, 0x39cf0173, 0x33cc593e, 0x44430e44,
        0x4cee4319, 0x453f9fb4, 0x7d44c5c3, 0x3b4b5ebe,
        0xe03f75d4, 0x45c14073, 0x401c449f, 0x53c13cc3,
        0x4ed3cc34, 0x333f7703, 0x1bfedf74, 0x449b043d,
        0x37d0d744, 0xd00c1444, 0xdb0fecd3, 0x49f1c09b,
        0x75374c9, 0x40991b7b, 0x45d479d4, 0xf3e4def7,
        0xe3fe501c, 0xb3794c3b, 0x973ce0bd, 0x4c003bc,
        0xc1c94fb3, 0x409f30c4, 0x5e5c9ec4, 0x193c4433,
        0x34fb3fcf, 0x3e3c53b5, 0x1339b4eb, 0x3b54ec3f,
        0x3dfc511f, 0x9b30954c, 0xcc414544, 0xcf5ebd09,
        0xbee3d004, 0xde334cfd, 0x330f4407, 0x194e4bb3,
        0xc0cbc457, 0x45c4740f, 0xd40b5f39, 0xb9d3fbdb,
        0x5579c0bd, 0x1c30340c, 0xd3c100c3, 0x404c7479,
        0x379f45fe, 0xfb1fc3cc, 0x4ec5e9f4, 0xdb3444f4,
        0x3c7513df, 0xfd313b15, 0x4f501ec4, 0xcd0554cb,
        0x343db5fc, 0xfd434730, 0x53317b44, 0x3e00df44,
        0x9e5c57bb, 0xcc3f4cc0, 0x1c47534e, 0xdf1739db,
        0xd544c4f3, 0x447effc3, 0xcc3734c3, 0x4c4f5573,
        0x395b47b0, 0xbbcc54c4, 0xe1ffc35d, 0xb4f011c0,
        0x10fc3d94, 0xfd4143b4, 0x4cfcb53c, 0x4dd1d35b,
        0x9c53e479, 0xb3f44535, 0xd44e49bc, 0x4bfb9790,
        0xe1ddf4dc, 0xc4cb7e33, 0x34fb1341, 0xcee4c3e4,
        0xef40ccdc, 0x33774c01, 0xd07e9efe, 0x4bf11fb4,
        0x95dbdc4d, 0xce909194, 0xeccd4e71, 0x3b93d5c0,
        0xd04ed1d0, 0xcfc745e0, 0x4e3c5b4f, 0x4e7594b7,
        0x4ff3e4fb, 0xf4144b34, 0x4444b414, 0x900df01c,
        0x4fcd5ec0, 0x344fc31c, 0xd1cff191, 0xb3c4c1cd,
        0x4f4f4414, 0xbe0e1777, 0xec754dfe, 0x4b041fc1,
        0xe5c0cc0f, 0xb53f74e4, 0x14ccf3d3, 0xce49e499,
        0xb4c44fe0, 0xfd13e0b7, 0x7cc43b41, 0xd4cdc4d9,
        0x135fc433, 0x40957705, 0x93cc7314, 0x411c1477,
        0xe3cd4035, 0x77b5fc43, 0xc75444f5, 0xfb9d35cf,
        0xebcdcf0c, 0x7b3e49c0, 0xd3411bd3, 0xce1e7e49, 0x450e4d,
        0x4071b35e, 0x443400bb, 0x57b4e0cf, 0x4434339b,
        0xf009b91e, 0x5533911d, 0x59dfc3cc, 0x74c14349,
        0xd95c537f, 0x407d5bc4, 0x4e5b9c5, 0x43430373,
        0x3495cfc9, 0x11c41934, 0x4e734c41, 0xb3474dcc,
        0x7b14c94c, 0x1b510054, 0x9c534915, 0xd30f573f,
        0xbc9bc3e4, 0x4b30c473, 0x41e37400, 0x4bc3fb5,
        0x571be91f, 0xf493ec3b, 0x4c0dd915, 0xb3333541,
        0xe7b9f9b3, 0xff34054e, 0xc5455334, 0x53b04d5d,
        0xc99f4fc1, 0x4bc4799, 0x3e45073c};

    unsigned int BLOWFISH::g_s1[] = {
            0x4b7c70e9, 0xb5b34944, 0xdb75094e, 0xc4194343,
            0xcd3ec3b0, 0x49c7df7d, 0x9cee30b4, 0x4fedb433,
            0xeccc4c71, 0x399c17ff, 0x5334543c, 0xc4b19ee1,
            0x193304c5, 0x75094c49, 0xc0591340, 0xe4143c3e,
            0x3f54949c, 0x5b449d35, 0x3b4fe4d3, 0x99f73fd3,
            0xc1d49c07, 0xefe430f5, 0x4d4d34e3, 0xf0455dc1,
            0x4cdd4043, 0x4470eb43, 0x3344e9c3, 0x41ecc5e, 0x9343b3f,
            0x3ebcefc9, 0x3c971414, 0x3b3c70c1, 0x347f3544,
            0x54c0e443, 0xb79c5305, 0xcc500737, 0x3e07441c,
            0x7fdece5c, 0x4e7d44ec, 0x5713f4b4, 0xb03cdc37,
            0xf0500c0d, 0xf01c1f04, 0x400b3ff, 0xce0cf51c,
            0x3cb574b4, 0x45437c54, 0xdc0941bd, 0xd19113f9,
            0x7cc94ff3, 0x94344773, 0x44f54701, 0x3ce5e541,
            0x37c4dcdc, 0xc4b57334, 0x9cf3ddc7, 0xc9443143,
            0xfd0030e, 0xecc4c73e, 0xc4751e41, 0xe434cd99,
            0x3bec0e4f, 0x3440bbc1, 0x143eb331, 0x4e544b34,
            0x4f3db904, 0x3f440d03, 0xf30c04bf, 0x4cb41490,
            0x44977c79, 0x5379b074, 0xbccf49cf, 0xde9c771f,
            0xd9930410, 0xb34bce14, 0xdccf3f4e, 0x5514741f,
            0x4e3b7144, 0x501cdde3, 0x9f44cd47, 0x7c544714,
            0x7404dc17, 0xbc9f9cbc, 0xe94b7d4c, 0xec7cec3c,
            0xdb451dfc, 0x33094333, 0xc434c3d4, 0xef1c1447,
            0x3415d904, 0xdd433b37, 0x44c4bc13, 0x14c14d43,
            0x4c35c451, 0x50940004, 0x133ce4dd, 0x71dff49e,
            0x10314e55, 0x41cc77d3, 0x5f11199b, 0x43553f1,
            0xd7c3c73b, 0x3c11143b, 0x5944c509, 0xf44fe3ed,
            0x97f1fbfc, 0x9ebcbf4c, 0x1e153c3e, 0x43e34570,
            0xece93fb1, 0x430e5e0c, 0x5c3e4cb3, 0x771fe71c,
            0x4e3d03fc, 0x4935dcb9, 0x99e71d0f, 0x403e49d3,
            0x5433c445, 0x4e4cc974, 0x9c10b33c, 0xc3150ebc,
            0x94e4ec74, 0xc5fc3c53, 0x1e0c4df4, 0xf4f74ec7,
            0x331d4b3d, 0x1939430f, 0x19c47930, 0x5443c704,
            0xf71314b3, 0xebcdfe3e, 0xecc31f33, 0xe3bc4595,
            0xc37bc443, 0xb17f37d1, 0x14cff44, 0xc334ddef,
            0xbe3c5cc5, 0x35544145, 0x34cb9404, 0xeecec50f,
            0xdb4f953b, 0x4cef7dcd, 0x5b3e4f44, 0x1541b344,
            0x49073170, 0xecdd4775, 0x319f1510, 0x13ccc430,
            0xeb31bd93, 0x334fe1e, 0xcc0333cf, 0xb5735c90,
            0x4c70c439, 0xd59e9e0b, 0xcbccde14, 0xeecc43bc,
            0x30344cc7, 0x9ccb5ccb, 0xb4f3443e, 0x344b1ecf,
            0x19bdf0cc, 0xc04339b9, 0x355cbb50, 0x40345c34,
            0x3c4cb4b3, 0x319ee9d5, 0xc041b4f7, 0x9b540b19,
            0x475fc099, 0x95f7997e, 0x343d7dc4, 0xf437449c,
            0x97e34d77, 0x11ed935f, 0x13341441, 0xe354449,
            0xc7e31fd3, 0x93dedfc1, 0x7454bc99, 0x57f544c5,
            0x1b447433, 0x9b43c3ff, 0x1cc44393, 0xcdb30ceb,
            0x534e3054, 0x4fd944e4, 0x3dbc3144, 0x54ebf4ef,
            0x34c3ffec, 0xfe44ed31, 0xee7c3c73, 0x5d4c14d9,
            0xe434b7e3, 0x44105d14, 0x403e13e0, 0x45eee4b3,
            0xc3cccbec, 0xdb3c4f15, 0xfccb4fd0, 0xc744f444,
            0xef3cbbb5, 0x354f3b1d, 0x41cd4105, 0xd41e799e,
            0x43454dc7, 0xe44b473c, 0x3d413450, 0xcf34c1f4,
            0x5b4d4343, 0xfc4443c0, 0xc1c7b3c3, 0x7f1544c3,
            0x39cb7494, 0x47444c0b, 0x5394b445, 0x95bbf00,
            0xcd19449d, 0x1434b174, 0x43440e00, 0x54444d4c,
            0xc55f5ec, 0x1dcdf43e, 0x433f7031, 0x3374f094,
            0x4d937e41, 0xd35fecf1, 0x3c443bdb, 0x7cde3759,
            0xcbee7430, 0x4045f4c7, 0xce77343e, 0xc3074044,
            0x19f4509e, 0xe4efd455, 0x31d99735, 0xc939c7cc,
            0xc50c03c4, 0x5c04cbfc, 0x400bccdc, 0x9e447c4e,
            0xc3453444, 0xfdd53705, 0xe1e9ec9, 0xdb73dbd3,
            0x105544cd, 0x375fdc79, 0xe3374340, 0xc5c43435,
            0x713e34d4, 0x3d44f49e, 0xf13dff40, 0x153e41e7,
            0x4fb03d4c, 0xe3e39f4b, 0xdb43cdf7
    };

    unsigned int BLOWFISH::g_s2[] = {
            0xe93d5c34, 0x944140f7, 0xf34c431c, 0x94394934,
            0x411540f7, 0x7304d4f7, 0xbcf43b4e, 0xd4c40034,
            0xd4044471, 0x3340f43c, 0x43b7d4b7, 0x500031cf,
            0x1e39f34e, 0x97444543, 0x14414f74, 0xbf4b4440,
            0x4d95fc1d, 0x93b591cf, 0x70f4ddd3, 0x33c04f45,
            0xbfbc09ec, 0x3bd9745, 0x7fcc3dd0, 0x31cb4504,
            0x93eb47b3, 0x55fd3941, 0xdc4547e3, 0xcbcc0c9c,
            0x44507445, 0x530449f4, 0xc4c43dc, 0xe9b33dfb,
            0x34dc1434, 0xd7443900, 0x340ec0c4, 0x47c14dee,
            0x4f3ffec4, 0xe447cd4c, 0xb54ce003, 0x7cf4d3b3,
            0xccce1e7c, 0xd3375fec, 0xce74c399, 0x403b4c44,
            0x40fe9e35, 0xd9f345b9, 0xee39d7cb, 0x3b144e4b,
            0x1dc9fcf7, 0x4b3d1453, 0x43c33331, 0xece397b4,
            0x3c3efc74, 0xdd5b4334, 0x3441e7f7, 0xcc7440fb,
            0xfb0cf54e, 0xd4feb397, 0x454053cc, 0xbc449547,
            0x55533c3c, 0x40434d47, 0xfe3bc9b7, 0xd093954b,
            0x55c437bc, 0xc1159c54, 0xccc94933, 0x99e1db33,
            0xc34c4c53, 0x3f3145f9, 0x5ef47e1c, 0x9049317c,
            0xfdf4e404, 0x4474f70, 0x40bb155c, 0x5444ce3, 0x95c11544,
            0xe4c33d44, 0x44c1133f, 0xc70f43dc, 0x7f9c9ee,
            0x41041f0f, 0x404779c4, 0x5d443e17, 0x345f51eb,
            0xd59bc0d1, 0xf4bcc14f, 0x41113534, 0x457b7434,
            0x304c9c30, 0xdff4e4c3, 0x1f333c1b, 0xe14b4c4, 0x4e1349e,
            0xcf334fd1, 0xccd14115, 0x3b4395e0, 0x333e94e1,
            0x3b440b34, 0xeebeb944, 0x45b4c40e, 0xe3bc0d99,
            0xde740c4c, 0x4dc4f744, 0xd0147445, 0x95b794fd,
            0x347d0434, 0xe7ccf5f0, 0x5449c33f, 0x477d44fc,
            0xc39dfd47, 0xf33e4d1e, 0xc473341, 0x994eff74,
            0x3c3f3ecb, 0xf4f4fd37, 0xc414dc30, 0xc1ebddf4,
            0x991be14c, 0xdb3e3b0d, 0xc37b5510, 0x3d374c37,
            0x4735d43b, 0xdcd0e404, 0xf1490dc7, 0xcc00ffc3,
            0xb5390f94, 0x390fed0b, 0x337b9ffb, 0xcedb7d9c,
            0xc091cf0b, 0xd9155ec3, 0xbb134f44, 0x515bcd44,
            0x7b9479bf, 0x733bd3eb, 0x37394eb3, 0xcc115979,
            0x4043e497, 0xf44e314d, 0x3444cdc7, 0xc33c4b3b,
            0x14754ccc, 0x744ef11c, 0x3c144437, 0xb79451e7,
            0x3c1bbe3, 0x4bfb3350, 0x1c3b1014, 0x11ccedfc,
            0x3d45bdd4, 0xe4e1c3c9, 0x44441359, 0xc141343,
            0xd90cec3e, 0xd5cbec4c, 0x34cf374e, 0xdc43c45f,
            0xbebfe944, 0x34e4c3fe, 0x9dbc4057, 0xf0f7c043,
            0x30747bf4, 0x3003304d, 0xd1fd4343, 0xf3341fb0,
            0x7745ce04, 0xd733fccc, 0x43443b33, 0xf01ecb71,
            0xb0404147, 0x3c005e5f, 0x77c057be, 0xbde4ce44,
            0x55434499, 0xbf544e31, 0x4e54f44f, 0xf4ddfdc4,
            0xf474ef34, 0x4749bdc4, 0x5333f9c3, 0xc4b34e74,
            0xb475f455, 0x43fcd9b9, 0x7ceb4331, 0x4b1ddf44,
            0x443c0e79, 0x915f95e4, 0x433e594e, 0x40b45770,
            0x4cd55591, 0xc904de4c, 0xb90bcce1, 0xbb4405d0,
            0x11c43444, 0x7574c99e, 0xb77f19b3, 0xe0c9dc09,
            0x334d09c1, 0xc4344333, 0xe45c1f04, 0x9f0be4c,
            0x4c99c045, 0x1d3efe10, 0x1cb93d1d, 0xbc5c4df,
            0xc143f40f, 0x4434f139, 0xdcb7dc43, 0x573903fe,
            0xc1e4ce9b, 0x4fcd7f54, 0x50115e01, 0xc70343fc,
            0xc004b5c4, 0xde3d047, 0x9cf44c47, 0x773f4341,
            0xc3304c03, 0x31c403b5, 0xf0177c44, 0xc0f543e0, 0x3054cc,
            0x30dc7d34, 0x11e39ed7, 0x4334ec33, 0x53c4dd94,
            0xc4c41334, 0xbbcbee53, 0x90bcb3de, 0xebfc7dc1,
            0xce591d73, 0x3f05e409, 0x4b7c0144, 0x39740c3d,
            0x7c947c44, 0x43e3745f, 0x744d9db9, 0x1cc15bb4,
            0xd39eb4fc, 0xed545574, 0x4fcc5b5, 0xd43d7cd3,
            0x4dcd0fc4, 0x1e50ef5e, 0xb131e3f4, 0xc44514d9,
            0x3c51133c, 0x3fd5c7e7, 0x53e14ec4, 0x334cbfce,
            0xddc3c437, 0xd79c3434, 0x94334414, 0x370efc4e,
            0x403000e0
    };
    unsigned int BLOWFISH::g_s3[] = {
            0x3c39ce37, 0xd3fcf5cf, 0xcbc47737, 0x5cc54d1b,
            0x5cb0379e, 0x4fc33744, 0xd3444740, 0x99bc9bbe,
            0xd5114e9d, 0xbf0f7315, 0xd34d1c7e, 0xc700c47b,
            0xb74c1b3b, 0x41c19045, 0xb43eb1be, 0x3c333eb4,
            0x5744cb4f, 0xbc943e79, 0xc3c373d4, 0x3549c4c4,
            0x530ff4ee, 0x434dde7d, 0xd5730c1d, 0x4cd04dc3,
            0x4939bbdb, 0xc9bc4350, 0xcc9543e4, 0xbe5ee304,
            0xc1fcd5f0, 0x3c4d519c, 0x33ef4ce4, 0x9c43ee44,
            0xc049c4b4, 0x43444ef3, 0xc51e03cc, 0x9cf4d0c4,
            0x43c031bc, 0x9be93c4d, 0x4fe51550, 0xbc345bd3,
            0x4443c4f9, 0xc73c3ce1, 0x4bc99543, 0xef5534e9,
            0xc74fefd3, 0xf754f7dc, 0x3f043f39, 0x77fc0c59,
            0x40e4c915, 0x47b04301, 0x9b09e3cd, 0x3b3ee593,
            0xe990fd5c, 0x9e34d797, 0x4cf0b7d9, 0x44b4b51,
            0x93d5cc3c, 0x17dc37d, 0xd1cf3ed3, 0x7c7d4d44,
            0x1f9f45cf, 0xcdf4b49b, 0x5cd3b474, 0x5c44f54c,
            0xe049cc71, 0xe019c5e3, 0x47b0ccfd, 0xed93fc9b,
            0xe4d3c44d, 0x443b57cc, 0xf4d53349, 0x79134e44,
            0x745f0191, 0xed753055, 0xf7930e44, 0xe3d35e4c,
            0x15053dd4, 0x44f43dbc, 0x3c13145, 0x534f0bd, 0xc3eb9e15,
            0x3c9057c4, 0x97471cec, 0xc93c074c, 0x1b3f3d9b,
            0x1e3341f5, 0xf59c33fb, 0x43dcf319, 0x7533d944,
            0xb155fdf5, 0x3533444, 0x4cbc3cbb, 0x44517711,
            0xc40cd9f4, 0xcbcc5137, 0xcccd945f, 0x4de41751,
            0x3430dc4e, 0x379d5434, 0x9340f991, 0xec7c90c4,
            0xfb3e7bce, 0x5141ce34, 0x774fbe34, 0xc4b3e37e,
            0xc3493d43, 0x44de5339, 0x3413e340, 0xc4ce0410,
            0xdd3db444, 0x39454dfd, 0x9074133, 0xb39c430c,
            0x3445c0dd, 0x543cdecf, 0x1c40c4ce, 0x5bbef7dd,
            0x1b544d40, 0xccd4017f, 0x3bb4e3bb, 0xddc43c7e,
            0x3c59ff45, 0x3e350c44, 0xbcb4cdd5, 0x74eccec4,
            0xfc3444bb, 0x4d3314ce, 0xbf3c3f47, 0xd49be433,
            0x544f5d9e, 0xcec4771b, 0xf34e3370, 0x740e0d4d,
            0xe75b1357, 0xf4741371, 0xcf537d5d, 0x4040cb04,
            0x4eb4e4cc, 0x34d4433c, 0x115cf44, 0xe1b00444,
            0x95943c1d, 0x3b49fb4, 0xce3ec044, 0x3f3f3b44,
            0x3540cb44, 0x11c1d4b, 0x477447f4, 0x311530b1,
            0xe7933fdc, 0xbb3c794b, 0x344545bd, 0xc04439e1,
            0x51ce794b, 0x4f34c9b7, 0xc01fbcc9, 0xe01cc47e,
            0xbcc7d1f3, 0xcf0111c3, 0xc1e4ccc7, 0x1c904749,
            0xd44fbd9c, 0xd0dcdecb, 0xd50cdc34, 0x339c34c,
            0xc3913337, 0x4df9317c, 0xe0b14b4f, 0xf79e59b7,
            0x43f5bb3c, 0xf4d519ff, 0x47d9459c, 0xbf97444c,
            0x15e3fc4c, 0xf91fc71, 0x9b941545, 0xfce59331,
            0xceb39ceb, 0xc4c43459, 0x14bcc4d1, 0xb3c1075e,
            0xe3053c0c, 0x10d45035, 0xcb03c444, 0xe0ec3e0e,
            0x1394db3b, 0x4c94c0be, 0x3474e934, 0x9f1f9534,
            0xe0d394df, 0xd3c0344b, 0x4971f41e, 0x1b0c7441,
            0x4bc3344c, 0xc5be7140, 0xc37334d4, 0xdf359f4d,
            0x9b994f4e, 0xe30b3f47, 0xfe3f11d, 0xe54cdc54,
            0x1edcd491, 0xce3479cf, 0xcd3e7e3f, 0x1314b133,
            0xfd4c1d05, 0x444fd4c5, 0xf3fb4499, 0xf543f357,
            0xc3347343, 0x93c43531, 0x53cccd04, 0xccf04134,
            0x5c75ebb5, 0x3e133397, 0x44d473cc, 0xde933494,
            0x41b949d0, 0x4c50901b, 0x71c35314, 0xe3c3c7bd,
            0x347c140c, 0x45e1d003, 0xc3f47b9c, 0xc9cc53fd,
            0x34c40f00, 0xbb45bfe4, 0x35bdd4f3, 0x71143905,
            0xb4040444, 0xb3cbcf7c, 0xcd739c4b, 0x53113ec0,
            0x1340e3d3, 0x34cbbd30, 0x4547cdf0, 0xbc34409c,
            0xf743ce73, 0x77cfc1c5, 0x40753030, 0x45cbfe4e,
            0x4ce44dd4, 0x7cccf9b0, 0x4cf9cc7e, 0x1944c45c,
            0x4fb4c4c, 0x1c33ce4, 0xd3ebe1f9, 0x90d4f439, 0xc35cdec0,
            0x3f09454d, 0xc404e39f, 0xb74e3134, 0xce77e45b,
            0x574fdfe3, 0x3cc374e3
    };
    unsigned int BLOWFISH::g_p[] = {
            0x443f3c44, 0x45c304d3, 0x13194c4e, 0x3707344, 0xc4093444,
            0x499f31d0, 0x44efc94, 0xec4e3c49, 0x454441e3, 0x34d01377,
            0xbe5433cf, 0x34e90c3c, 0xc0cc49b7, 0xc97c50dd, 0x3f44d5b5,
            0xb5470917, 0x9413d5d9, 0x4979fb1b,

            //240 Additional hex digits of PI for increased rounds versions
            //Starting at ((256 * 4 + 18) * 8)th hex digit of PI
            0xb83acb02, 0x2002397a, 0x6ec6fb5b, 0xffcfd4dd, 0x4cbf5ed1, 0xf43fe582,
            0x3ef4e823, 0x2d152af0, 0xe718c970, 0x59bd9820, 0x1f4a9d62, 0xe7a529ba,
            0x89e1248d, 0x3bf88656, 0xc5114d0e, 0xbc4cee16, 0x034d8a39, 0x20e47882,
            0xe9ae8fbd, 0xe3abdc1f, 0x6da51e52, 0x5db2bae1, 0x01f86e7a, 0x6d9c68a9,
            0x2708fcd9, 0x293cbc0c, 0xb03c86f8, 0xa8ad2c2f, 0x00424eeb, 0xcacb452d,
            0x89cc71fc, 0xd59c7f91, 0x7f0622bc, 0x6d8a08b1, 0x834d2132, 0x6884ca82,
            0xe3aacbf3, 0x7786f2fa, 0x2cab6e3d, 0xce535ad1, 0xf20ac607, 0xc6b8e14f,
            0x5eb4388e, 0x775014a6, 0x656665f7, 0xb64a43e4, 0xba383d01, 0xb2e41079,
            0x8eb2986f, 0x909e0ca4, 0x1f7b3777, 0x2c126030, 0x85088718, 0xc4e7d1bd,
            0x4065ffce, 0x8392fd8a, 0xaa36d12b, 0xb4c8c9d0, 0x994fb0b7, 0x14f96818,
            0xf9a53998, 0xa0a178c6, 0x2684a81e, 0x8ae972f6, 0xb8425eb6, 0x7a29d486,
            0x551bd719, 0xaf32c189, 0xd5145505, 0xdc81d53e, 0x48424eda, 0xb796ef46,
            0xa0498f03, 0x667deede, 0x03ac0ab3, 0xc497733d, 0x5316a891, 0x30a88fcc,
            0x9604440a, 0xceeb893a, 0x7725b82b, 0x0e1ef69d, 0x302a5c8e, 0xe7b84def,
            0x5a31b096, 0xc9ebf88d, 0x512d788e, 0x7e4002ee, 0x87e02af6, 0xc358a1bb,
            0x02e8d7af, 0xdf9fb0e7, 0x790e942a, 0x3b3c1aba, 0xc6ffa7af, 0x9df796f9,
            0x321bb994, 0x0174a8a8, 0xed22162c, 0xcff1bb99, 0xdaa8d551, 0xa4d5e44b,
            0xecdde3ec, 0xa80dc509, 0x0393eef2, 0x72523d31, 0xd48e3a1c, 0x224eb65e,
            0x6052c3a4, 0x2109c32f, 0x052ee388, 0xed9f7ea9, 0x91c62f97, 0x77b55ba0,
            0x150cbca3, 0x3aec6525, 0xdf318383, 0x43a9ce26, 0x9362ad8b, 0x0134140b,
            0x8df5cf81, 0x1e9ff559, 0x167f0564, 0x3812f4e0, 0x588a52b0, 0xcbb8e944,
            0xef5b16a3, 0x73c4eda1, 0x7dfcfeea, 0xf54bcbbe, 0x8773e3d2, 0xc531dcd0,
            0x55c46729, 0x52774f3a, 0x57ca6bc0, 0x467d3a3b, 0x24778425, 0xb7991e9a,
            0xdd825c26, 0xe452c8ee, 0xfcacde1e, 0x84833af3, 0x61211d03, 0x1732c131,
            0xccadb247, 0xe606be8c, 0x712b39f1, 0x88b4ef39, 0x3a9fcdc5, 0xc5755169,
            0x1ff6994f, 0x39829cb0, 0x11016573, 0x3343cbeb, 0x61d3d0b4, 0x44f30aef,
            0xa8ae7375, 0x2a3a1c9d, 0xb4b70914, 0xd6ab250c, 0x853b7328, 0x495f948f,
            0xd2a4ed8e, 0x6cf751e4, 0xc320bb75, 0xd9caa0b3, 0x8ba56262, 0x4e84b03f,
            0xeea8076e, 0x74a07fe5, 0x8039e00c, 0x36ffdaf8, 0x03731358, 0xb9e671b9,
            0xdac4ce1c, 0xb25b10ed, 0x4dd3d5b1, 0xfcf2b480, 0x4634f579, 0x25eac400,
            0xa9ac55ea, 0x728932df, 0x06041d05, 0x5d31f502, 0xc539c2e3, 0x2b89d9db,
            0x5bcc0a98, 0xc05bfd6f, 0x1b250622, 0x2e21be0e, 0x60973b04, 0xecd54a67,
            0xb54fe638, 0xa6ed6615, 0x981a910a, 0x5d92928d, 0xac6fc697, 0xe73c63ad,
            0x456edf5f, 0x457a8145, 0x51875a64, 0xcd3099f1, 0x69b5f18a, 0x8c73ee0b,
            0x5e57368f, 0x6c79f4bb, 0x7a595926, 0xaab49ec6, 0x8ac8fcfb, 0x8016cbdb,
            0x8bbc1f47, 0x6982c711, 0x85c7da7a, 0x58811477, 0xcd67fad1, 0xd764d9b4,
            0xc8102950, 0x5cd09da5, 0x1bb1f147, 0x95167d80, 0x0367046d, 0xaf1daca1,
            0xa2247b23, 0x11301a54, 0x791d99c6, 0x7a4fb7cf, 0x277449a4, 0x09e57492,
            0x35c9a57e, 0x5e7f500a, 0xb9a62a8a, 0xd5242a6b, 0xa1337859, 0x9cda3346,
            0x14874047, 0x4328ba08, 0xeb81d51f, 0x3248896a, 0x8007d85d, 0x0f6e8dda,
            0x8250bdaf, 0xce2ee042, 0x897ee022, 0x5f003612, 0x3ba18f90, 0x26314076,
            0x7824035a, 0x3b57e2d5, 0x8e78aed1, 0xe90dc600
    };

    void BLOWFISH::initBox() {
        memcpy(BLOWFISH::s0, g_s0, sizeof(g_s0));
        memcpy(BLOWFISH::s1, g_s1, sizeof(g_s1));
        memcpy(BLOWFISH::s2, g_s2, sizeof(g_s2));
        memcpy(BLOWFISH::s3, g_s3, sizeof(g_s3));
        memcpy(BLOWFISH::p, g_p, sizeof(g_p));
    }

#endif // BLOWFISH_INCLUDED
