#include "../include/util.h"

int main(int argc, char **argv) {
    int fd = open(PIPE_NAME, O_WRONLY);
    if (fd == -1) {
        perror("Can't open pipe");
        return EXIT_FAILURE;
    }

    char buffer[1024] = "concordia-grupo-listar";
    for (int i = 1; i < argc; i++) {
        strcat(buffer, " ");
        strcat(buffer, argv[i]);
    }

    if (write(fd, buffer, strlen(buffer) + 1) == -1) {
        perror("Error writing to pipe");
        close(fd);
        return EXIT_FAILURE;
    }
    
    close(fd);
    return EXIT_SUCCESS;
}