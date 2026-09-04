#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ark/linux_cloud.h"

static int fail = 0;
static void expect(int c, const char *m) {
    if (!c) { fprintf(stderr, "FAIL %s\n", m); fail = 1; }
}

static void write_file(const char *p, const char *b) {
    FILE *f = fopen(p, "w");
    if (!f) exit(1);
    fputs(b, f);
    fclose(f);
}

int main(void) {
    char tmpl[] = "/tmp/ark-cloud-XXXXXX";
    char *home = mkdtemp(tmpl);
    if (!home) return 1;
    char aws[512], az[512];
    snprintf(aws, sizeof(aws), "%s/.aws", home);
    mkdir(aws, 0700);
    char cred[512];
    snprintf(cred, sizeof(cred), "%s/.aws/credentials", home);
    write_file(cred, "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secretline\n");
    snprintf(az, sizeof(az), "%s/.azure", home);
    mkdir(az, 0700);
    char tok[512];
    snprintf(tok, sizeof(tok), "%s/.azure/accessTokens.json", home);
    write_file(tok, "[{\"accessToken\":\"eyJhbGciOi\",\"refreshToken\":\"0.AXo\"}]\n");

    ark_cloud_credential creds[8];
    size_t n = 0;
    expect(ark_cloud_harvest_aws_files(home, creds, &n, 8) == 1, "aws files");
    expect(n == 1, "one profile");
    expect(strcmp(creds[0].identity, "AKIAEXAMPLE") == 0, "akid");
    expect(strcmp(creds[0].secret, "secretline") == 0, "secret parsed");

    ark_cloud_token toks[8];
    size_t tn = 0;
    expect(ark_cloud_harvest_azure_cli(home, toks, &tn, 8) == 1, "azure cli");
    expect(tn == 1, "one token");
    expect(strcmp(toks[0].access_token, "eyJhbGciOi") == 0, "access token");
    expect(strcmp(toks[0].refresh_token, "0.AXo") == 0, "refresh token");

    /* AWS SigV4 GET iam ListUsers example (20150830). */
    char auth[512];
    int ok = ark_aws_sigv4("GET", "iam.amazonaws.com", "/",
        "Action=ListUsers&Version=2010-05-08", "",
        "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1", "iam", "20150830T123600Z", "20150830",
        auth, sizeof(auth));
    expect(ok == 1, "sigv4 ok");
    expect(strstr(auth, "Signature=") != NULL, "has signature");
    expect(strstr(auth, "AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request") != NULL, "cred scope");

    if (fail) return 1;
    printf("linux_cloud host tests ok\n");
    return 0;
}
