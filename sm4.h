#ifndef SM4_H
#define SM4_H

#ifdef _WIN32
  #ifdef SM4_EXPORTS
    #define SM4_API __declspec(dllexport)
  #else
    #define SM4_API __declspec(dllimport)
  #endif
#else
  #define SM4_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

SM4_API int SM4_ECB_Encrypt(unsigned char* pKey,
                            unsigned int KeyLen,
                            unsigned char* pInData,
                            unsigned int inDataLen,
                            unsigned char* pOutData,
                            unsigned int* pOutDataLen);

SM4_API int SM4_ECB_Decrypt(unsigned char* pKey,
                            unsigned int KeyLen,
                            unsigned char* pInData,
                            unsigned int inDataLen,
                            unsigned char* pOutData,
                            unsigned int* pOutDataLen);

#ifdef __cplusplus
}
#endif

#endif // SM4_H
