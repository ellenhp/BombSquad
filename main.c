#include <unistd.h>
#include <stdlib.h>

#define INPUT_LEN 4

int main() {
    char input[INPUT_LEN+1];
    input[INPUT_LEN] = 0;
    read(0, input, INPUT_LEN);

    int counter1 = 0;
    int counter2 = 0;
    for (int i = 0; i < INPUT_LEN; i++) {
        if (input[i] == 'A') {
            counter1++;
        }
        if (input[i] == 'B' ) {
            counter2++;
        }
    }

    if (counter1 == INPUT_LEN/2 && counter2 == (INPUT_LEN+1)/2) {
        exit(1);
    } else {
        exit(0);
    }
}
