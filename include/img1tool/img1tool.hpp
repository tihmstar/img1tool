//
//  img1tool.hpp
//  img1tool
//
//  Created by tihmstar on 28.03.23.
//

#ifndef img1tool_hpp
#define img1tool_hpp

#include <libgeneral/Mem.hpp>
#include <stdlib.h>
#include <vector>
#include <stdint.h>

namespace tihmstar {
    namespace img1tool {
        const char *version();

        void printIMG1(const void *buf, size_t size);
    
        tihmstar::Mem getPayloadFromIMG1(const void *buf, size_t size);
        tihmstar::Mem getCertFromIMG1(const void *buf, size_t size);
        tihmstar::Mem createIMG1FromPayloadAndCert(const tihmstar::Mem &payload, const tihmstar::Mem &salt = {}, const tihmstar::Mem &cert = {}, const tihmstar::Mem &sig = {});
        tihmstar::Mem createIMG1FromPayloadWithPwnage2(const tihmstar::Mem &payload);
    };
};
#endif /* img1tool_hpp */
