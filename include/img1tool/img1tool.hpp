//
//  img1tool.hpp
//  img1tool
//
//  Created by tihmstar on 28.03.23.
//

#ifndef img1tool_hpp
#define img1tool_hpp

#include <stdlib.h>
#include <vector>
#include <stdint.h>
#include <iostream>


namespace tihmstar {
    namespace img1tool {
        const char *version();

        void printIMG1(const void *buf, size_t size);
    
        std::vector<uint8_t> getPayloadFromIMG1(const void *buf, size_t size);
        std::vector<uint8_t> getCertFromIMG1(const void *buf, size_t size);
        std::vector<uint8_t> createIMG1FromPayloadAndCert(const std::vector<uint8_t> &payload, const std::vector<uint8_t> &salt = {}, const std::vector<uint8_t> &cert = {}, const std::vector<uint8_t> &sig = {});
        std::vector<uint8_t> appendDFUFooter(const void *buf, size_t size);
    };
};
#endif /* img1tool_hpp */
