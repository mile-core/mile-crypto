#include <stdarg.h>
#include <cstring>
#include <math.h>

#include "mile_crypto.h"

const std::string StringFormat(const char* format, ...)
{
    char buffer[1024] = {};
    va_list ap = {};

    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);

    return std::string(buffer);
}

const std::string ErrorFormat(const char* format, ...)
{
    char buffer[1024] = {};
    va_list ap = {};

    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);

    return "MileCsa error: " + std::string(buffer);
}

static inline void reverse(char *str, int len)
{
    int i=0, j=len-1, temp;
    while (i<j)
    {
        temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++; j--;
    }
}

static inline int intToStr(int x, char str[], int d)
{
    int i = 0;
    while (x)
    {
        str[i++] = (x%10) + '0';
        x = x/10;
    }

    while (i < d)
        str[i++] = '0';

    reverse(str, i);
    str[i] = '\0';
    return i;
}

void float2FixedPoint(float value, int precision, std::string &output)
{
    output.clear();

#if __USE_MILECSA_FIXED_POINT_IMP__
    char *res = (char *)malloc((sizeof(n)+afterpoint) * 16);
    if (!res)
        return;
#else
    char res[(sizeof(value)+precision) * 16];
#endif

    int ipart = (int)value;

    float fpart = value - (float)ipart;

    int i = intToStr(ipart, res, 0);

    if (abs(value) < 1.0) {
        output = "0";
    }

    if (precision != 0)
    {
        res[i] = '.';

        fpart = fpart * pow(10, precision);

        intToStr((int)fpart, res + i + 1, precision);
    }

    output += res;

#if __USE_MILECSA_FIXED_POINT_IMP__
    free(res);
#endif
}