/* Host tests for the WinRM PTH HTTP failure tag. No sockets. */
#include <stdio.h>
#include <string.h>

#include "ark/pth_layer.h"

static int fails;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        fails++;
    }
}

int main(void) {
    expect(strcmp(ark_pth_http_layer(401, NULL), "sign_seal") == 0, "401 is sign_seal");
    expect(strcmp(ark_pth_http_layer(401, "bad hash"), "sign_seal") == 0, "401 wins over body text");
    expect(strcmp(ark_pth_http_layer(500, "Unencrypted traffic is currently disabled"), "sign_seal") == 0,
        "unencrypted fault is sign_seal");
    expect(strcmp(ark_pth_http_layer(500, "SOAP schema error"), "soap_frame") == 0, "other 500 is soap_frame");
    expect(strcmp(ark_pth_http_layer(0, NULL), "soap_frame") == 0, "no status is soap_frame");

    if (fails) {
        fprintf(stderr, "%d pth_layer tests failed\n", fails);
        return 1;
    }
    printf("pth_layer_host_test: ok\n");
    return 0;
}
