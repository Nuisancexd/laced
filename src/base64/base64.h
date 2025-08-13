#ifndef _BASE_64_H_
#define _BASE_64_H_


enum class BASE_E
{
    ENCODE = 1,
    DECODE = 2
};


namespace base64
{
    void init_table_base64_decode();
    int base64_encode(const unsigned char* src, unsigned len, char* dst);
    int base64_decode(const unsigned char* src, unsigned len, char* dst);
    bool base64(BASE_E e, const unsigned char* src, unsigned len, char* dst, int* bsize);
}


#endif

