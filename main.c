#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define _MIN(a, b) ((a) < (b) ? (a) : (b))

#define INPUT_LEN 50

// This will make veritesting take a very very long time. INPUT_LEN needs to be quite low for reasonable completeion times.
// #define ANTI_VERITESTING

#ifdef ANTI_VERITESTING
#define INCR(A) collatzStep(&A)
#else
#define INCR(A) A++
#endif

int evaluateRun(char* input, char* flag) {
    for (int i = 0; i < INPUT_LEN; i++) {
        if (flag[i] != input[i]) {
            return 0;
        }
    }
    return 1;
}

int evaluateRun1(char* input) {
    char flag[] = "BBBAAABAAAAAAAAAAABBBAAABBAABBABAAABBAABBBAAABAAAAAAAABABABBAAAABBAAAAABABBAABBBBAAABAABBABBAAAABABABBBABBAABBBBAAAABAABBAABAAABAABBBAAABABAABABAAABAAAAAAAAAABBBBBAABAAAABAAABABBBBBABAABBAABBBAAAABABB";
    return evaluateRun(input, flag);
}

int evaluateRun2(char* input) {
    char flag[] = "BAABAAABBBAAABBAABBABAAABBAABBBAAABAAAAAAAABABABBAAAABBAAAAABABBAABBBBAAABAABBABBAAAABABABBBABBAABBBBAAAABAABBAABAAABAABBBAAABABAABABAAABAAAAAAAAAABBBBBAABAAAABAAABABBBBBABAABBAABBBAAAABABBAABABAABABB";
    return evaluateRun(input, flag);
}

void collatzStep(int* val) {
    if (*val % 2) {
        *val = *val * 3 + 1;
    }
    else {
        *val = *val / 2;
    }
    *val++;
}

int doRun(char* buf) {
    read(0, buf, INPUT_LEN);
    int counter1 = 0;
    int counter2 = 0;
    for (int i = 0; i < INPUT_LEN; i++) {
        if (buf[i] == 'A') {
            INCR(counter1);
        }
        if (buf[i] == 'B' ) {
            INCR(counter1);
        }
    }
    return counter1 * counter2;
}

int main() {
    char buf[INPUT_LEN+1];
    doRun(buf);

    if (!evaluateRun1(buf)) {
        exit(0);
    }
    memset(buf, 0, INPUT_LEN);
    doRun(buf);
    if (evaluateRun2(buf)) {
        exit(1);
    }
    exit(0);
}
