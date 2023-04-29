//
//  img1tool.cpp
//  img1tool
//
//  Created by tihmstar on 28.03.23.
//

#include <img1tool/img1tool.hpp>
#include <libgeneral/macros.h>
#include <stdint.h>
#include <string.h>

extern "C"{
#include "crc32.h"
};

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

#ifdef HAVE_OPENSSL
#   include <openssl/aes.h>
#   include <openssl/sha.h>
#warning TODO adjust this for HAVE_COMMCRYPTO
#   include <openssl/x509.h> //not replaced by CommCrypto
#   include <openssl/evp.h> //not replaced by CommCrypto
#else
#   ifdef HAVE_COMMCRYPTO
#       include <CommonCrypto/CommonCrypto.h>
#       include <CommonCrypto/CommonDigest.h>
#       define SHA1(d, n, md) CC_SHA1(d, n, md)
#       define SHA384(d, n, md) CC_SHA384(d, n, md)
#       define SHA_DIGEST_LENGTH CC_SHA1_DIGEST_LENGTH
#       define SHA384_DIGEST_LENGTH CC_SHA384_DIGEST_LENGTH
#   endif //HAVE_COMMCRYPTO
#endif // HAVE_OPENSSL

using namespace tihmstar;

enum Img1Enc : uint8_t {
    kImg1EncBootUIDKey  = 0x00,
    kImg1EncBootPlain   = 0x02,
    kImg1EncKey0x837    = 0x03,
    kImg1EncPlain       = 0x04
    //other values are unknown!
};

struct Img1{
    uint32_t    magic;                 // string "8900"
    char        version[3];            // string "1.0"
    Img1Enc     format;                // plaintext format is 0x4, encrypted with Key 0x837 format is 0x3, boot plaintext is 0x2, boot encrypted with UID-key is 0x1.
    uint32_t    unknown1;
    uint32_t    sizeOfData;            // size of data (i.e: file size - header(0x800) - footerSig(0x80) - footerCert(0xC0A))
    uint32_t    footerSignatureOffset; // offset to footer signature (relative to end of header)
    uint32_t    footerCertOffset;      // offset to footer certificate, (relative to end of header)
    uint32_t    footerCertLen;
    uint8_t     salt[0x20];            // a seemingly random salt for the signature
    uint16_t    unknown2;
    uint16_t    epoch;                 // the security epoch of the file
    uint8_t     headerSignature[0x10]; // encrypt(sha1(header[0:0x40])[0:0x10], key_0x837, zero_iv)
    uint8_t     padding[0x7B0];        // pad to 0x800 (i.e: 2 KiB)};
};

const uint8_t key0x837[0x10] = {0x18, 0x84, 0x58, 0xA6, 0xD1, 0x50, 0x34, 0xDF, 0xE3, 0x86, 0xF2, 0x3B, 0x61, 0xD4, 0x37, 0x74};

#pragma mark private
static void DumpHex(const void* data, size_t size, uint32_t offset) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        if ((i%0x10) == 0) printf("%08x  ",offset+(uint32_t)i);
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

const Img1 *verifyIMG1Header(const void *buf, size_t size){
    retassure(size >= sizeof(Img1), "buf too small for header");
    const Img1 *header = (const Img1*)buf;
    
    retassure(size >= sizeof(Img1), "Failed: size >= sizeof(Img1)");
    retassure(header->magic == htonl('8900'), "Bad magic! Got 0x%08x but expected 0x%08x",header->magic, htonl('8900'));
    retassure(!strncmp(header->version, "1.0", 3), "Unkown version '%.3s'",header->version);
    retassure(header->sizeOfData + sizeof(Img1) <= size, "Failed: header->sizeOfData + sizeof(Img1) <= size");
    retassure(header->footerSignatureOffset >= header->sizeOfData, "Failed: header->footerSignatureOffset >= header->sizeOfData");
    retassure(header->footerSignatureOffset + sizeof(Img1) <= size, "Failed: header->footerSignatureOffset + sizeof(Img1) <= size");
    retassure(header->footerCertOffset >= header->footerSignatureOffset, "Failed: header->footerCertOffset >= header->footerSignatureOffset");
    retassure(header->footerCertOffset + sizeof(Img1) <= size, "Failed: header->footerCertOffset + sizeof(Img1) <= size");
    retassure(header->footerCertOffset + sizeof(Img1) + header->footerCertLen <= size, "Failed: header->footerCertOffset + sizeof(Img1) + header->footerCertLen <= size");
    return header;
}

#pragma mark public
const char *img1tool::version(){
    return VERSION_STRING;
}

void img1tool::printIMG1(const void *buf, size_t size){
    const Img1 *header = verifyIMG1Header(buf, size);

    printf("IMG1:\n");
    printf("magic       : %.4s\n",(char*)&header->magic);
    printf("version     : %.3s\n",(char*)&header->version);
    {
        const char *format = "UNKNOWN";
        switch (header->format) {
            case kImg1EncBootUIDKey:
                format = "BootEncryptUID";
                break;
            case kImg1EncBootPlain:
                format = "BootPlain";
                break;
            case kImg1EncKey0x837:
                format = "Encrypt0x837";
                break;
            case kImg1EncPlain:
                format = "Plain";
                break;
            default:
                break;
        }
        
        printf("format      : %s (%d)\n",format,header->format);
    }
    printf("data offset : 0x%x\n",(uint32_t)sizeof(Img1));
    printf("data size   : 0x%x\n",header->sizeOfData);
    printf("sig  offset : 0x%x\n",header->footerSignatureOffset+(uint32_t)sizeof(Img1));
    printf("cert offset : 0x%x\n",header->footerCertOffset+(uint32_t)sizeof(Img1));
    printf("cert size   : 0x%x\n",header->footerCertLen);
    printf("salt        : "); for (int i=0; i<sizeof(header->salt); i++) printf("%02x",header->salt[i]); printf("\n");
    printf("epoch       : 0x%x\n",header->epoch);
    printf("header sig  : "); for (int i=0; i<sizeof(header->headerSignature); i++) printf("%02x",header->headerSignature[i]); printf("\n");
    printf("-------------------------\n");
    
    printf("Padding: \n");
    uint8_t emptyline[0x10] = {};
    bool lastLineWasEmpty = false;
    bool didPrintStar = false;
    for (int i=0; i<=sizeof(header->padding)-0x10; i+=0x10) {
        const uint8_t *curptr = &header->padding[i];
        bool curLineIsEmpty = (memcmp(emptyline, curptr, sizeof(emptyline)) == 0);
        if (!curLineIsEmpty || !lastLineWasEmpty){
            DumpHex(curptr, 0x10, i+sizeof(Img1)-sizeof(header->padding));
            didPrintStar = false;
        }else{
            if (!didPrintStar) {
                printf("*\n");
                didPrintStar = true;
            }
        }
        lastLineWasEmpty = curLineIsEmpty;
    }
    if (didPrintStar) {
        DumpHex(&header->padding[sizeof(header->padding)-0x10], 0x10, sizeof(header->padding)-0x10+(sizeof(Img1)-sizeof(header->padding)));
    }
    printf("-------------------------\n");
    {
        const uint8_t *p = (const uint8_t*)(header+1);
        printf("sig:");
        for (size_t i = 0; i<header->footerCertOffset-header->footerSignatureOffset; i++){
            if ((i%0x20) == 0) printf("\n\t");
            printf("%02x",p[i+header->footerSignatureOffset]);
        }
        printf("\n");
    }
}

std::vector<uint8_t> img1tool::getPayloadFromIMG1(const void *buf, size_t size){
    const Img1 *header = verifyIMG1Header(buf, size);
    const uint8_t *data = (const uint8_t*)(header+1);
    std::vector<uint8_t> ret{data,data+header->sizeOfData};
    switch (header->format) {
        case kImg1EncBootUIDKey:
            reterror("Decrypting with UID key is not supported!");
            
        case kImg1EncBootPlain:
            reterror("todo");

        case kImg1EncKey0x837:
        {
#ifdef HAVE_OPENSSL
        uint8_t iv[0x10] = {};
        AES_KEY k = {};
        AES_set_decrypt_key(key0x837, 128, &k);
        AES_cbc_encrypt(ret.data(), ret.data(), ret.size(), &k, iv, 0);
#elif defined(HAVE_COMMCRYPTO)
            size_t dataOut = ret.size();
        CCCryptorStatus err = 0;
        retassure((err = CCCrypt(kCCDecrypt, kCCAlgorithmAES, 0, key0x837, kCCKeySizeAES128, NULL, ret.data(), dataOut, ret.data(), dataOut, &dataOut)) == kCCSuccess,"Failed to decrypt payload");
#endif
        }
            break;

        case kImg1EncPlain:
            break;
            
        default:
            reterror("Unknown format %d",header->format);
            break;
    }
    return ret;
}

std::vector<uint8_t> img1tool::getCertFromIMG1(const void *buf, size_t size){
    const Img1 *header = verifyIMG1Header(buf, size);
    const uint8_t *certdata = (const uint8_t*)(header+1) + header->footerCertOffset;
    return {certdata,certdata+header->footerCertLen};
}


std::vector<uint8_t> img1tool::createIMG1FromPayloadAndCert(const std::vector<uint8_t> &payload, const std::vector<uint8_t> &salt, const std::vector<uint8_t> &cert, const std::vector<uint8_t> &sig){
    Img1 header = {
        .magic = htonl('8900'),
        .version = {'1','.','0'},
        .format = kImg1EncPlain,
        .unknown1 = 0,
        .sizeOfData = static_cast<uint32_t>(payload.size()),
        .footerSignatureOffset = static_cast<uint32_t>(payload.size()),
        .footerCertOffset = static_cast<uint32_t>(payload.size()+sig.size()),
        .footerCertLen = static_cast<uint32_t>(cert.size()),
        .salt = {},
        .unknown2 = 0,
        .epoch = 3,
        .headerSignature = {},
        .padding = {}
    };
    strncpy((char*)&header.padding[0x30], "This space left intentionally blank.", sizeof(header.padding)-0x30);
    {
        size_t realSaltSize = salt.size();
        if (realSaltSize > sizeof(header.salt)) realSaltSize = sizeof(header.salt);
        memcpy(header.salt, salt.data(), realSaltSize);
    }
    {
#if defined(HAVE_COMMCRYPTO) || defined(HAVE_OPENSSL)
        uint8_t shabuf[SHA_DIGEST_LENGTH];
        SHA1((const uint8_t*)&header, offsetof(Img1, headerSignature), shabuf);
#endif
#ifdef HAVE_OPENSSL
        uint8_t iv[0x10] = {};
        AES_KEY k = {};
        AES_set_encrypt_key(key0x837, 128, &k);
        AES_cbc_encrypt(shabuf, header.headerSignature, sizeof(header.headerSignature), &k, iv, 1);
#elif defined(HAVE_COMMCRYPTO)
        size_t dataOut = sizeof(header.headerSignature);
        CCCryptorStatus err = 0;
        retassure((err = CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0, key0x837, kCCKeySizeAES128, NULL, shabuf, sizeof(header.headerSignature), header.headerSignature, dataOut, &dataOut)) == kCCSuccess,"Failed to encrypt header sig");
#endif
    }
    
    std::vector<uint8_t> ret{(uint8_t*)&header,((uint8_t*)&header)+sizeof(header)};
    ret.insert(ret.end(), payload.begin(),payload.end());
    ret.insert(ret.end(), sig.begin(),sig.end());
    ret.insert(ret.end(), cert.begin(),cert.end());
    return ret;
}

std::vector<uint8_t> img1tool::createIMG1FromPayloadWithPwnage2(const std::vector<uint8_t> &payload){
#include "pwnage2.crt.h" //exposes /* const unsigned char pwnage2[]; */ variable
    std::vector<uint8_t> cert{pwnage2,pwnage2+sizeof(pwnage2)};
    
    Img1 header = {
        .magic = htonl('8900'),
        .version = {'1','.','0'},
        .format = kImg1EncPlain,
        .unknown1 = 0,
        .sizeOfData = static_cast<uint32_t>(payload.size()),
        .footerSignatureOffset = static_cast<uint32_t>(payload.size()),
        .footerCertOffset = static_cast<uint32_t>(payload.size()+0x80),
        .footerCertLen = static_cast<uint32_t>(cert.size() - 0x80),
        .salt = {},
        .unknown2 = 0,
        .epoch = 4,
        .headerSignature = {},
        .padding = {}
    };
    strncpy((char*)&header.padding[0x30], "This image contains Pwnage 2.0", sizeof(header.padding)-0x30);

    {
#if defined(HAVE_COMMCRYPTO) || defined(HAVE_OPENSSL)
        uint8_t shabuf[SHA_DIGEST_LENGTH];
        SHA1((const uint8_t*)&header, offsetof(Img1, headerSignature), shabuf);
#endif
#ifdef HAVE_OPENSSL
        uint8_t iv[0x10] = {};
        AES_KEY k = {};
        AES_set_encrypt_key(key0x837, 128, &k);
        AES_cbc_encrypt(shabuf, header.headerSignature, sizeof(header.headerSignature), &k, iv, 1);
#elif defined(HAVE_COMMCRYPTO)
        size_t dataOut = sizeof(header.headerSignature);
        CCCryptorStatus err = 0;
        retassure((err = CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0, key0x837, kCCKeySizeAES128, NULL, shabuf, sizeof(header.headerSignature), header.headerSignature, dataOut, &dataOut)) == kCCSuccess,"Failed to encrypt header sig");
#endif
    }
    
    std::vector<uint8_t> ret{(uint8_t*)&header,((uint8_t*)&header)+sizeof(header)};
    ret.insert(ret.end(), payload.begin(),payload.end());
    ret.insert(ret.end(), cert.begin(),cert.end());
    return ret;
}

std::vector<uint8_t> img1tool::appendDFUFooter(const void *buf, size_t size){
    uint32_t crc=0xFFFFFFFF;
    const uint8_t header[]={0xff,0xff,0xff,0xff,0xac,0x05,0x00,0x01,0x55,0x46,0x44,0x10};
    
    std::vector<uint8_t> ret{(uint8_t*)buf,(uint8_t*)buf+size};
    
    ret.insert(ret.end(), header,header+sizeof(header));
    crc = update_crc(crc, ret.data(), (uint32_t)ret.size());
    for(int a=0;a<4;a++) {
        ret.push_back(crc&0xFF);
        crc=crc>>8;
    }
    return ret;
}
