#ifndef OVERRIDES_H
#define OVERRIDES_H

#include "rtObject.h"

namespace RDK
{

bool overridesEnabled();
void loadOverrides(std::string url, rtObjectRef browser);

}

#endif /* OVERRIDES_H */
