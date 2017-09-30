#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define _MIN(a, b) ((a) < (b) ? (a) : (b))

#define INPUT_LEN 5

int evaluateRun(char* input, char* flag) {
    for (int i = 0; i < INPUT_LEN; i++) {
        if (flag[i] != input[i]) {
            return 0;
        }
    }
    return 1;
}

int evaluateRun1(char* input) {
    char flag[] = "FAKE_HAHAAAABBBAAABBAABBABAAABBAABBBAAABAAAAAAAABABABBAAAABBAAAAABABBAABBBBAAABAABBABBAAAABABABBBABBAABBBBAAAABAABBAABAAABAABBBAAABABAABABAAABAAAAAAAAAABBBBBAABAAAABAAABABBBBBABAABBAABBBAAAABABBAABABAABABB";
    return evaluateRun(input, flag);
}

int evaluateRun2(char* input) {
    char flag[] = "BAABAAABBBAAABBAABBABAAABBAABBBAAABAAAAAAAABABABBAAAABBAAAAABABBAABBBBAAABAABBABBAAAABABABBBABBAABBBBAAAABAABBAABAAABAABBBAAABABAABABAAABAAAAAAAAAABBBBBAABAAAABAAABABBBBBABAABBAABBBAAAABABBAABABAABABB";
    return evaluateRun(input, flag);
}

int doRun(char* out) {
    char buf[INPUT_LEN+1];
    read(0, buf, INPUT_LEN);
    int counter1 = 0;
    int counter2 = 0;
    for (int i = 0; i < INPUT_LEN; i++) {
        if (buf[i] == 'A') {
            counter1 += 1;
        }
        if (buf[i] == 'B' ) {
            counter2 += 1;
        }
    }
    memcpy(out, buf, INPUT_LEN);
    return counter1 * counter2;
}

int main() {
    char buf[INPUT_LEN+1];
    doRun(buf);
    
    if (evaluateRun1(buf)) {
        buf[INPUT_LEN/2] = '!';
    }
    doRun(buf);
    if (evaluateRun2(buf)) {
        exit(1);
    }
    exit(0);
}
