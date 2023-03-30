//
//  main.cpp
//  img2tool
//
//  Created by tihmstar on 28.03.23.
//

#include <libgeneral/macros.h>
#include <img2tool/img2tool.hpp>

#include <iostream>
#include <getopt.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace tihmstar::img2tool;

#define FLAG_CREATE         (1 << 0)
#define FLAG_EXTRACT        (1 << 1)
#define FLAG_VERIFY         (1 << 2)
#define FLAG_DFU_FOOTER     (1 << 3)

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "create",         required_argument,  NULL, 'c' },
    { "cert",           no_argument,        NULL, 'C' },
    { "extract",        no_argument,        NULL, 'e' },
    { "dfu-footer",     no_argument,        NULL, 'f' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "salt",           required_argument,  NULL, 's' },
    { "sig",            required_argument,  NULL, 'S' },
    { "verify",         no_argument,        NULL, 'v' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img2tool [OPTIONS] FILE\n");
    printf("Parses img2 files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -c, --create\t<PATH>\t\tcreates img2 with raw file (last argument)\n");
    printf("  -C, --cert\t\t\tselect cert for extraction, or give cert for creation\n");
    printf("  -e, --extract\t\t\textracts payload\n");
    printf("  -f, --dfu-footer\t\tappend DFU footer\n");
    printf("  -o, --outfile\t\t\toutput path for extracting payload\n");
    printf("  -s, --salt\t\t\tspecify salt (in 0x20 hex bytes)\n");
    printf("  -S, --sig\t\t\tspecify signature (in hex bytes)\n");
    printf("  -v, --verify\t\t\tverify img2\n");
    printf("\n");
}

std::vector<uint8_t> readFromFile(const char *filePath){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    struct stat st{};
    std::vector<uint8_t> ret;
    
    retassure((fd = open(filePath, O_RDONLY))>0, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    ret.resize(st.st_size);
    retassure(read(fd, ret.data(), ret.size()) == ret.size(), "Failed to read file");
    return ret;
}

void saveToFile(const char *filePath, std::vector<uint8_t>data){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    retassure((fd = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, 0644))>0, "failed to create file '%s'",filePath);
    retassure(write(fd, data.data(), data.size()) == data.size(), "failed to write to file");
}

std::vector<uint8_t> parseHexbytes(const char *bytes){
    std::vector<uint8_t> ret;
    for (;*bytes;bytes+=2) {
        unsigned int t;
        retassure(bytes[1],"odd hex string");
        retassure(sscanf(bytes,"%02x",&t) == 1,"Failed paring hexstring");
        ret.push_back(t);
    }
    return ret;
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    printf("%s\n",version());
    int optindex = 0;
    int opt = 0;
    long flags = 0;
    
    std::vector<uint8_t> sig(0x80);
    std::vector<uint8_t> salt;

    const char *outFile = NULL;
    const char *lastArg = NULL;
    
    const char *putCertPath = NULL;
    bool certSelector = false;
    
    while ((opt = getopt_long(argc, (char* const *)argv, "hc:C::efo:s:S:v", longopts, &optindex)) >= 0) {
        switch (opt) {
            case 'h':
                cmd_help();
                return 0;

            case 'e': //extract
                retassure(!(flags & FLAG_CREATE), "Invalid command line arguments. can't do multiple actions at the same time!");
                flags |= FLAG_EXTRACT;
                break;
                
            case 'f': //dfu-footer
                flags |= FLAG_DFU_FOOTER;
                break;
                
            case 'c': //create
                retassure(!(flags & FLAG_EXTRACT), "Invalid command line arguments. can't do multiple actions at the same time!");
                flags |= FLAG_CREATE;
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
                
            case 'C': //cert
                certSelector = true;
                if (optarg) putCertPath = optarg;
                break;
                
            case 'o': //output
                retassure(!outFile, "Invalid command line arguments. outFile already set!");
                outFile = optarg;
                break;
                
            case 's': //salt
                salt = parseHexbytes(optarg);
                break;

            case 'S': //sig
                sig = parseHexbytes(optarg);
                break;

            case 'v':
                flags |= FLAG_VERIFY;
                break;

            default:
                cmd_help();
                return -1;
        }
    }

    if (argc-optind == 1) {
        argc -= optind;
        argv += optind;
        lastArg = argv[0];
    }else{
        if (!(flags & FLAG_CREATE)) {
            cmd_help();
            return -2;
        }
    }
    
    std::vector<uint8_t> workingBuf;

    if (lastArg) {
        workingBuf = readFromFile(lastArg);
    }

    if (flags & FLAG_EXTRACT) {
        retassure(outFile, "Outfile required for operation");
        std::vector<uint8_t> outdata;
        if (certSelector) {
            outdata = getCertFromIMG2(workingBuf.data(),workingBuf.size());
        }else{
            outdata = getPayloadFromIMG2(workingBuf.data(),workingBuf.size());
        }
        saveToFile(outFile, outdata);
        info("Extracted IMG2 payload to %s",outFile);
    }else if (flags & FLAG_CREATE) {
        retassure(outFile, "Outfile required for operation");
        retassure(workingBuf.size(), "Need lastarg for this operation");
        std::vector<uint8_t> img2;
        std::vector<uint8_t> cert;
        if (putCertPath) {
            cert = readFromFile(putCertPath);
        }else{
            info("No cert specified, using pwnage cert");
        }
        
        info("Creating IMG2 file");
        img2 = createIMG2FromPayloadAndCert(workingBuf,salt,cert,sig);
        
        if (flags & FLAG_DFU_FOOTER) {
            info("Appending DFU footer");
            img2 = appendDFUFooter(img2.data(), img2.size());
        }
        
        saveToFile(outFile, img2);
        info("Created IMG2 file at %s",outFile);
    }else if (flags & FLAG_VERIFY){
        info("Verifying IMG2 file");
        bool isSigned = false;

        reterror("not implemented");
        return isSigned ? 0 : 1;
    }else if (flags & FLAG_DFU_FOOTER){
        retassure(outFile, "Outfile required for operation");
        retassure(workingBuf.size(), "Need lastarg for this operation");
        info("Appending DFU footer");
        auto buf = appendDFUFooter(workingBuf.data(), workingBuf.size());
        saveToFile(outFile, buf);
        info("Wrote file to %s",outFile);
    }else{
        //print
        printIMG2(workingBuf.data(), workingBuf.size());
    }

    
    
    return 0;
}
