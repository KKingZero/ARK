/* Host unit tests for path jail pure validators (no Windows APIs). */
#include <stdio.h>
#include <string.h>

#include "ark/pathjail.h"

/* Compile pathjail.c with -DARK_PATHJAIL_HOST_TEST and link pure helpers. */

static int fails;

static void expect_true(const char *name, int cond) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", name);
        fails++;
    }
}

static void expect_false(const char *name, int cond) {
    expect_true(name, !cond);
}

int main(void) {
    expect_false("rel notes", ark_path_is_absolute("notes.txt"));
    expect_false("rel nested", ark_path_is_absolute("data\\file.bin"));
    expect_true("unix abs", ark_path_is_absolute("/etc/passwd"));
    expect_true("win drive", ark_path_is_absolute("C:\\Windows\\system32"));
    expect_true("win root slash", ark_path_is_absolute("\\Windows"));
    expect_true("unc", ark_path_is_absolute("\\\\server\\share"));

    expect_false("no escape rel", ark_path_has_dotdot_escape("notes.txt"));
    expect_false("no escape nested", ark_path_has_dotdot_escape("data\\file.bin"));
    expect_false("dot segment ok", ark_path_has_dotdot_escape("foo\\.\\bar"));
    expect_true("parent alone", ark_path_has_dotdot_escape(".."));
    expect_true("parent prefix", ark_path_has_dotdot_escape("..\\secret"));
    expect_true("nested escape", ark_path_has_dotdot_escape("sub\\..\\..\\etc\\passwd"));
    expect_false("up then down stays", ark_path_has_dotdot_escape("a\\..\\b"));

    if (fails) {
        fprintf(stderr, "%d pathjail host tests failed\n", fails);
        return 1;
    }
    printf("pathjail host tests ok\n");
    return 0;
}
