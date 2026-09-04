#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ark/linux_postex.h"

static int fail = 0;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", msg);
        fail = 1;
    }
}

static void write_file(const char *path, const char *body) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(1);
    }
    fputs(body, f);
    fclose(f);
}

int main(void) {
    char tmpl[] = "/tmp/ark-postex-XXXXXX";
    char *home = mkdtemp(tmpl);
    if (!home) {
        perror("mkdtemp");
        return 1;
    }
    char ssh[512], hist[512], awsdir[512];
    snprintf(ssh, sizeof(ssh), "%s/.ssh", home);
    mkdir(ssh, 0700);
    char key[512];
    snprintf(key, sizeof(key), "%s/.ssh/id_ed25519", home);
    write_file(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END OPENSSH PRIVATE KEY-----\n");
    snprintf(hist, sizeof(hist), "%s/.bash_history", home);
    write_file(hist, "ls\nexport password=s3cret\nwhoami\n");
    snprintf(awsdir, sizeof(awsdir), "%s/.aws", home);
    mkdir(awsdir, 0700);
    char aws[512];
    snprintf(aws, sizeof(aws), "%s/.aws/credentials", home);
    write_file(aws, "[default]\naws_secret_access_key=abc\n");

    ark_credential creds[16];
    size_t n = 0;
    expect(ark_linux_creds_collect("ssh_keys", home, creds, 16, &n) == 1, "ssh_keys collect");
    expect(n == 1, "one ssh key");
    expect(strstr(creds[0].source, "id_ed25519") != NULL, "ssh source path");
    expect(strstr(creds[0].value, "SECRETKEYMATERIAL") == NULL, "no private key bytes");
    expect(strstr(creds[0].value, "OPENSSH") != NULL, "key type ref");

    n = 0;
    expect(ark_linux_creds_collect("history", home, creds, 16, &n) == 1, "history collect");
    expect(n == 1, "one history");
    expect(strstr(creds[0].source, ".bash_history") != NULL, "history path");

    n = 0;
    expect(ark_linux_creds_collect("files", home, creds, 16, &n) == 1, "files collect");
    expect(n >= 1, "aws credentials listed");
    expect(strstr(creds[0].value, "abc") == NULL, "no file secret bytes");

    expect(ark_linux_creds_collect("nope", home, creds, 16, &n) == 0, "unknown method");

    char line[128] = "export password=s3cret rest";
    ark_linux_redact_secrets(line);
    expect(strstr(line, "s3cret") == NULL, "redact password");
    expect(strncmp(line, "export password=", 16) == 0, "keep key name");

    expect(!ark_linux_payload_allowed("/etc/cron.d/x"), "refuse /etc");
    expect(!ark_linux_payload_allowed("../evil"), "refuse dotdot");
    expect(ark_linux_payload_allowed("/tmp/implant_c_linux"), "allow /tmp");

    ark_persist_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.method, sizeof(cfg.method), "bashrc");
    snprintf(cfg.name, sizeof(cfg.name), "qa");
    snprintf(cfg.payload_path, sizeof(cfg.payload_path), "/tmp/implant_c_linux");
    char details[256];
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "bashrc add");
    char bashrc[512];
    snprintf(bashrc, sizeof(bashrc), "%s/.bashrc", home);
    FILE *bf = fopen(bashrc, "r");
    expect(bf != NULL, "bashrc exists");
    char body[1024] = {0};
    if (bf) {
        fread(body, 1, sizeof(body) - 1, bf);
        fclose(bf);
    }
    expect(strstr(body, "/tmp/implant_c_linux") != NULL, "bashrc payload");
    expect(strstr(body, "ark-persist-begin qa") != NULL, "bashrc marker");
    snprintf(cfg.trigger, sizeof(cfg.trigger), "remove");
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "bashrc remove");
    bf = fopen(bashrc, "r");
    body[0] = '\0';
    if (bf) {
        fread(body, 1, sizeof(body) - 1, bf);
        fclose(bf);
    }
    expect(strstr(body, "ark-persist-begin qa") == NULL, "bashrc marker gone");

    char cronf[512];
    snprintf(cronf, sizeof(cronf), "%s/cron", home);
    setenv("ARK_CRON_FILE", cronf, 1);
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.method, sizeof(cfg.method), "cron");
    snprintf(cfg.name, sizeof(cfg.name), "qa");
    snprintf(cfg.payload_path, sizeof(cfg.payload_path), "/tmp/implant_c_linux");
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "cron add");
    FILE *cf = fopen(cronf, "r");
    body[0] = '\0';
    if (cf) {
        fread(body, 1, sizeof(body) - 1, cf);
        fclose(cf);
    }
    expect(strstr(body, "@reboot /tmp/implant_c_linux") != NULL, "cron line");
    snprintf(cfg.trigger, sizeof(cfg.trigger), "remove");
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "cron remove");
    cf = fopen(cronf, "r");
    body[0] = '\0';
    if (cf) {
        fread(body, 1, sizeof(body) - 1, cf);
        fclose(cf);
    }
    expect(strstr(body, "@reboot") == NULL, "cron line gone");

    char sysd[512];
    snprintf(sysd, sizeof(sysd), "%s/systemd", home);
    mkdir(sysd, 0700);
    setenv("ARK_SYSTEMD_USER_DIR", sysd, 1);
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.method, sizeof(cfg.method), "systemd_user");
    snprintf(cfg.name, sizeof(cfg.name), "qa");
    snprintf(cfg.payload_path, sizeof(cfg.payload_path), "/tmp/implant_c_linux");
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "systemd add");
    char unit[512];
    expect(snprintf(unit, sizeof(unit), "%s/qa.service", sysd) < (int)sizeof(unit), "unit path fits");
    expect(access(unit, R_OK) == 0, "unit written");
    snprintf(cfg.trigger, sizeof(cfg.trigger), "remove");
    expect(ark_linux_persist_apply(&cfg, home, details, sizeof(details)) == 1, "systemd remove");
    expect(access(unit, F_OK) != 0, "unit removed");

    char suidroot[512];
    snprintf(suidroot, sizeof(suidroot), "%s/bin", home);
    mkdir(suidroot, 0755);
    char suidbin[512];
    snprintf(suidbin, sizeof(suidbin), "%s/bin/suidhelper", home);
    write_file(suidbin, "#!/bin/sh\n");
    chmod(suidbin, 04755);
    setenv("ARK_PRIVESC_ROOTS", suidroot, 1);
    char dump[2048];
    expect(ark_linux_privesc_enum(dump, sizeof(dump)) == 1, "enum");
    expect(strstr(dump, "suid") != NULL, "enum lists suid");
    expect(strstr(dump, "suidhelper") != NULL, "enum path");

    if (fail) {
        fprintf(stderr, "linux_postex host tests failed\n");
        return 1;
    }
    printf("linux_postex host tests ok\n");
    return 0;
}
