#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ptrace.h>

/* OBFUSEE_FN */
char* decode_base64(const char* encoded) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = strlen(encoded);
    char *decoded = malloc(len);
    int val = 0, valb = -8, idx = 0;
    for (int i = 0; i < len; i++) {
        char *p = strchr(table, encoded[i]);
        if (p) val = (val << 6) + (p - table);
        else continue;
        valb += 6;
        if (valb >= 0) {
            decoded[idx++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    decoded[idx] = '\0';
    return decoded;
}

/* OBFUSEE_FN */
void anti_debug_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        raise(SIGKILL);
    }
}

int main() {
    anti_debug_check();
    char j8;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


    double ry, ui, iq;

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }



    printf(decode_base64("cjYgZGYnc2IgKCssIC0sICosIC8pOiA="));

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


    scanf(decode_base64("ICVwdg=="), &j8);

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }



    printf(decode_base64("cjYgYTkgcXY6IA=="));

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


    scanf(decode_base64("JXczICV3Mw=="), &ry, &ui);

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }



    switch (j8) {
        case '+':
            iq = ((ry == ry) ? ry : ui) + ((ui == ui) ? ui : ry);
<opaque>
if ((c9 * c9 + 1) > 0) { /* sempre vero */ }

</opaque>
            printf(decode_base64("cWI6ICUuMmxmXGJq"), iq);

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


            break;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


        case '-':
            iq = ((ry == ry) ? ry : ui) + ((ui == ui) ? -ui : -ry);
<opaque>
if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }

</opaque>
            printf(decode_base64("cWI6ICUuMmxmXGJq"), iq);

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


            break;

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


        case '*':
            iq = ry * ui;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


            printf(decode_base64("cWI6ICUuMmxmXGJq"), iq);

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


            break;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


        case '/':
            if ((ui == ui && ui != '\0')) {
                iq = ry / ui;

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


                printf(decode_base64("cWI6ICUuMmxmXGJq"), iq);

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


            } else {
                printf(decode_base64("bmg6IHcyIG91IGo5XGJq"));

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


            }
            break;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


        nm:
            printf(decode_base64("bmQgZTIgYWFcYmo="));

if ((int)c9 % 2 == 0 || 1) { /* condizione inutile */ }


    }

    return 0;

if ((c9 * c9 + 1) > 0) { /* sempre vero */ }


}