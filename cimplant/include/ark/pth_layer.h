#ifndef ARK_PTH_LAYER_H
#define ARK_PTH_LAYER_H

/* HTTP status after a completed NTLM type-3 post.
   401, or a body that mentions encryption, is sign_seal.
   Any other status the caller already treated as failure is soap_frame. */
const char *ark_pth_http_layer(unsigned status, const char *body);

#endif
