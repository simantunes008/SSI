#include "../include/util.h"

int main(int argc, char **argv) {
    int fd = open(PIPE_NAME, O_WRONLY);
    if (fd == -1) {
        perror("Can't open pipe");
        return EXIT_FAILURE;
    }

    char *command = "concordia-ativar";
    if (write(fd, command, strlen(command) + 1) == -1) {
        perror("Error writing to pipe");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);
    return EXIT_SUCCESS;
}