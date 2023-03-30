//
//  img2tool.hpp
//  img2tool
//
//  Created by tihmstar on 28.03.23.
//

#ifndef img2tool_hpp
#define img2tool_hpp

#include <stdlib.h>
#include <vector>
#include <stdint.h>
#include <iostream>


namespace tihmstar {
    namespace img2tool {
        const char *version();

        void printIMG2(const void *buf, size_t size);
    
        std::vector<uint8_t> getPayloadFromIMG2(const void *buf, size_t size);
        std::vector<uint8_t> getCertFromIMG2(const void *buf, size_t size);
        std::vector<uint8_t> createIMG2FromPayloadAndCert(const std::vector<uint8_t> &payload, const std::vector<uint8_t> &salt = {}, const std::vector<uint8_t> &cert = {}, const std::vector<uint8_t> &sig = {});
        std::vector<uint8_t> appendDFUFooter(const void *buf, size_t size);
    };
};
#endif /* img2tool_hpp */
