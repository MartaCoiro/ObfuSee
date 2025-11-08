#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* OBFUSEE_FN */
static unsigned char* _obf_b64dec(const char* b64, int* outlen){
    BIO *b = BIO_new_mem_buf(b64, -1);
    BIO *d = BIO_new(BIO_f_base64());
    b = BIO_push(d, b); BIO_set_flags(b, BIO_FLAGS_BASE64_NO_NL);
    unsigned char* buf = malloc(strlen(b64));
    *outlen = BIO_read(b, buf, strlen(b64));
    BIO_free_all(b); return buf;
}
static int get_runtime_key(const char* id, unsigned char** key_out){
    const char* k = getenv("AEAD_KEY_B64");
    if(!k) return 0;
    int L=0; unsigned char* kb = _obf_b64dec(k, &L);
    if(L != 32){ free(kb); return 0; }
    *key_out = kb; return 1;
}
char* dec_aead(const char* b64_blob, const char* id){
    int rawlen=0; unsigned char* raw = _obf_b64dec(b64_blob, &rawlen);
    if(!raw || rawlen<12+16){ free(raw); return NULL; }
    unsigned char *nonce = raw, *ct_tag = raw+12;
    int ctlen = rawlen - 12 - 16;
    unsigned char* key = NULL;
    if(!get_runtime_key(id, &key)){ free(raw); return NULL; }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    unsigned char* pt = malloc(ctlen+1);
    int outl=0; EVP_DecryptUpdate(ctx, pt, &outl, ct_tag, ctlen);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct_tag+ctlen);
    int ok = EVP_DecryptFinal_ex(ctx, pt+outl, &outl);
    EVP_CIPHER_CTX_free(ctx); free(raw); free(key);
    if(!ok){ free(pt); return NULL; }
    pt[ctlen] = '\0'; return (char*)pt;
}

/* OBFUSEE_FN */
void anti_debug_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        raise(SIGKILL);
    }
}











int main() {
    anti_debug_check();
    char c8;

if ((z * z + 1) > 0) { /* sempre vero */ }


    double bd, bl, xi;

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }



    printf(dec_aead("udTtD00wu2SOz9srGc27FJWXcZkU+gHZyaY+0qU84L9Z0X79z3GrDAzsKEWXaAcsYzGW", "480ce0fea63405c0"));

if ((z * z + 1) > 0) { /* sempre vero */ }


    scanf(dec_aead("AkCkbq0G1U8ohfd8yN3iCSWDr1xowrVBnh26B+ru8No=", "ca6cec8e0933996b"), &c8);

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }



    printf(dec_aead("X0lKfMhlhHjTHuiDEPRApyvLXiZDO3SqSTFvabghQXSFlz5yDQg=", "09e523ec1459a1fb"));

if ((z * z + 1) > 0) { /* sempre vero */ }


    scanf(dec_aead("OPJ3j3DqfvRRQGm5ivhNuELNDgqNl3JbQ2Om3OtQv3TS1zE=", "fda868a9849b21f5"), &bd, &bl);

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }



    switch (c8) {
        case '+':
            xi = ((bd == bd) ? bd : bl) + ((bl == bl) ? bl : bd);
<opaque>
if ((z * z + 1) > 0) { /* sempre vero */ }

</opaque>
            printf(dec_aead("m3PN+hbTAVDcdV3tDtS3AB7FxShaV4k6HiUMi/mLrzkzQzqH1XHZwQ==", "ebe30c418a6b5403"), xi);

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


            break;

if ((z * z + 1) > 0) { /* sempre vero */ }


        case '-':
            xi = ((bd == bd) ? bd : bl) + ((bl == bl) ? -bl : -bd);
<opaque>
if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }

</opaque>
            printf(dec_aead("p8CqHfq6E9D5+VN27gAZv3HAD4+rUzpvLYywhhnd3c3vL/ee76p/UQ==", "5f1ef4be31617b51"), xi);

if ((z * z + 1) > 0) { /* sempre vero */ }


            break;

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


        case '*':
            xi = bd * bl;

if ((z * z + 1) > 0) { /* sempre vero */ }


            printf(dec_aead("PaNwnnY6UtxxxEIHiksJA4dZOB4BdqmF+K6LVWKUlyi2i1V5oGh7NA==", "6a836c2eb53c6e0a"), xi);

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


            break;

if ((z * z + 1) > 0) { /* sempre vero */ }


        case '/':
            if ((bl == bl && bl != '\0')) {
                xi = bd / bl;

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


                printf(dec_aead("Hz3mzQ5oI1YQsrOuEfIsX1C2BcvfV2h8s35LA9E0I/bGfBF6tg4dvA==", "a321bea0a98810e4"), xi);

if ((z * z + 1) > 0) { /* sempre vero */ }


            } else {
                printf(dec_aead("pDemtcRCySoaZkpc+JEqHplqAlRfRJ3awbSBRPOpUM2/SyOy21AJ/bmH9g==", "da27f10b78a9602b"));

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


            }
            break;

if ((z * z + 1) > 0) { /* sempre vero */ }


        r8:
            printf(dec_aead("y7yVQ+LTmfb8fivbHjJ7pLMus73jBa3eF6Mg5mPOwzM7qG62KKLT", "cb1459b7d7cdc5f4"));

if ((int)z % 2 == 0 || 1) { /* condizione inutile */ }


    }

    return 0;

if ((z * z + 1) > 0) { /* sempre vero */ }


}