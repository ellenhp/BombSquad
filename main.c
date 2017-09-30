#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define _MIN(a, b) ((a) < (b) ? (a) : (b))

#define INPUT_LEN 100

int evaluateRun(int counter1, int counter2, char* input) {
    char target[] = "BAABAAABBBAAABBAABBABAAABBAABBBAAABAAAAAAAABABABBAAAABBAAAAABABBAABBBBAAABAABBABBAAAABABABBBABBAABBBBAAAABAABBAABAAABAABBBAAABABAABABAAABAAAAAAAAAABBBBBAABAAAABAAABABBBBBABAABBAABBBAAAABABBAABABAABABB";
    for (int i = 0; i < _MIN(INPUT_LEN, sizeof(target)-1); i++) {
        if (target[i] != input[i]) {
            exit(0);
        }
    }
    exit(1);
}

int main() {
    char input[INPUT_LEN+1];
    input[INPUT_LEN] = 0;
    read(0, input, INPUT_LEN);

    int counter1 = 0;
    int counter2 = 0;
    for (int i = 0; i < INPUT_LEN; i++) {
        if (input[i] == 'A') {
            counter1 += 1;
        }
        if (input[i] == 'B' ) {
            counter2 += 1;
        }
    }

    evaluateRun(counter1, counter2, input);
}
