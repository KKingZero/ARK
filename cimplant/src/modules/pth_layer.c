#include "ark/pth_layer.h"

#include <stddef.h>

static int has_encrypt(const char *s) {
    static const char key[] = "encrypt";
    if (!s) return 0;
    for (const char *p = s; *p; p++) {
        size_t i = 0;
        for (; key[i]; i++) {
            char c = p[i];
            if (!c) return 0;
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != key[i]) break;
        }
        if (!key[i]) return 1;
    }
    return 0;
}

const char *ark_pth_http_layer(unsigned status, const char *body) {
    if (status == 401 || has_encrypt(body))
        return "sign_seal";
    return "soap_frame";
}
