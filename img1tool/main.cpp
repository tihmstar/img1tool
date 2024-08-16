//
//  main.cpp
//  img1tool
//
//  Created by tihmstar on 28.03.23.
//

#include <libgeneral/macros.h>
#include <libgeneral/Utils.hpp>
#include <img1tool/img1tool.hpp>

#include <iostream>
#include <getopt.h>
#include <vector>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

using namespace tihmstar::img1tool;

#define FLAG_CREATE         (1 << 0)
#define FLAG_EXTRACT        (1 << 1)
#define FLAG_VERIFY         (1 << 2)
#define FLAG_DFU_FOOTER     (1 << 3)

static struct option longopts[] = {
    { "help",           no_argument,        NULL, 'h' },
    { "create",         required_argument,  NULL, 'c' },
    { "cert",           optional_argument,  NULL, 'C' },
    { "extract",        no_argument,        NULL, 'e' },
    { "dfu-footer",     no_argument,        NULL, 'f' },
    { "outfile",        required_argument,  NULL, 'o' },
    { "salt",           required_argument,  NULL, 's' },
    { "sig",            required_argument,  NULL, 'S' },
    { "verify",         no_argument,        NULL, 'v' },
    { NULL, 0, NULL, 0 }
};

void cmd_help(){
    printf("Usage: img1tool [OPTIONS] FILE\n");
    printf("Parses img1 files\n\n");
    printf("  -h, --help\t\t\tprints usage information\n");
    printf("  -c, --create\t<PATH>\t\tcreates img1 with raw file (last argument)\n");
    printf("  -C, --cert\t\t\tselect cert for extraction, or give cert for creation\n");
    printf("  -e, --extract\t\t\textracts payload\n");
    printf("  -o, --outfile\t\t\toutput path for extracting payload\n");
    printf("  -s, --salt\t\t\tspecify salt (in 0x20 hex bytes)\n");
    printf("  -S, --sig\t\t\tspecify signature (in hex bytes)\n");
    printf("  -v, --verify\t\t\tverify img1\n");
    printf("\n");
}

tihmstar::Mem readFromFile(const char *filePath){
    int fd = -1;
    cleanup([&]{
        safeClose(fd);
    });
    struct stat st{};
    tihmstar::Mem ret;
    
    retassure((fd = open(filePath, O_RDONLY))>0, "Failed to open '%s'",filePath);
    retassure(!fstat(fd, &st), "Failed to stat file");
    ret.resize(st.st_size);
    retassure(read(fd, ret.data(), ret.size()) == ret.size(), "Failed to read file");
    return ret;
}

tihmstar::Mem parseHexbytes(const char *bytes){
    size_t len = strlen(bytes);
    tihmstar::Mem ret(len/2);
    for (int i=0; i<len; i+=2) {
        unsigned int t;
        retassure(sscanf(&bytes[i],"%02x",&t) == 1,"Failed paring hexstring");
        ret.data()[i/2] = (uint8_t)t;
    }
    return ret;
}

void saveToFile(const char *filePath, const void *buf, size_t bufSize){
    FILE *f = NULL;
    cleanup([&]{
        if (f) {
            fclose(f);
        }
    });
    
    if (strcmp(filePath, "-") == 0) {
        write(STDERR_FILENO, buf, bufSize);
    }else{
        retassure(f = fopen(filePath, "wb"), "failed to create file");
        retassure(fwrite(buf, 1, bufSize, f) == bufSize, "failed to write to file");
    }
}

MAINFUNCTION
int main_r(int argc, const char * argv[]) {
    printf("%s\n",version());
    int optindex = 0;
    int opt = 0;
    long flags = 0;
    
    tihmstar::Mem sig;
    tihmstar::Mem salt;

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
    
    if (outFile && strcmp(outFile, "-") == 0) {
        int s_out = -1;
        int s_err = -1;
        cleanup([&]{
            safeClose(s_out);
            safeClose(s_err);
        });
        s_out = dup(STDOUT_FILENO);
        s_err = dup(STDERR_FILENO);
        dup2(s_out, STDERR_FILENO);
        dup2(s_err, STDOUT_FILENO);
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
    
    tihmstar::Mem workingBuf;

    if (lastArg) {
        if (strcmp(lastArg, "-") == 0){
            char cbuf[0x1000] = {};
            ssize_t didRead = 0;
            
            while ((didRead = read(STDIN_FILENO, cbuf, sizeof(cbuf))) > 0) {
                workingBuf.append(cbuf, didRead);
            }
            
        }else{
            workingBuf = tihmstar::readFile(lastArg);
        }
    }

    if (flags & FLAG_EXTRACT) {
        retassure(outFile, "Outfile required for operation");
        tihmstar::Mem outdata;
        if (certSelector) {
            outdata = getCertFromIMG1(workingBuf.data(),workingBuf.size());
        }else{
            outdata = getPayloadFromIMG1(workingBuf.data(),workingBuf.size());
        }
        saveToFile(outFile, outdata.data(), outdata.size());
        info("Extracted IMG1 payload to %s",outFile);
    }else if (flags & FLAG_CREATE) {
        retassure(outFile, "Outfile required for operation");
        retassure(workingBuf.size(), "Need lastarg for this operation");
        tihmstar::Mem img1;
        tihmstar::Mem cert;
        if (putCertPath) {
            cert = readFromFile(putCertPath);
        }else{
            info("No cert specified, using pwnage cert");
        }
        
        if (!salt.size() && !cert.size() && !sig.size()) {
            info("Creating IMG1 file with PWNage2.0 exploit");
            img1 = createIMG1FromPayloadWithPwnage2(workingBuf);
        }else{
            info("Creating IMG1 file");
            if (!sig.size()) sig.resize(0x80);
            img1 = createIMG1FromPayloadAndCert(workingBuf,salt,cert,sig);
        }
        
        saveToFile(outFile, img1.data(), img1.size());
        info("Created IMG1 file at %s",outFile);
    }else if (flags & FLAG_VERIFY){
        info("Verifying IMG1 file");
        bool isSigned = false;

        reterror("not implemented");
        return isSigned ? 0 : 1;
    }else{
        //print
        printIMG1(workingBuf.data(), workingBuf.size());
    }

    
    
    return 0;
}
