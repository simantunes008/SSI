#include "../include/util.h"

static int concordia_ativado = 0;
static int concordia_mensagem_ativado = 0;


static int file_counter = 1;

void process_enviar(const char* folder_name, const char* content){
    char path[100];
    sprintf(path, "%s/msg%d.txt", folder_name, file_counter++);

    int file = open(path, O_WRONLY | O_CREAT, S_IRWXU);
    if (file != -1) {
        write(file, content, strlen(content));
        close(file);
    } else {
        printf("Não foi possível abrir o ficheiro %s\n", path);
    }
}

void process_ler(int numero, const char* folder_name){
    char command[30];
    sprintf(command, "cat %s/msg%d.txt; echo", folder_name, numero);
    system(command);
}

void process_remover(int numero, const char* folder_name){
    char command[30];
    sprintf(command, "rm %s/msg%d.txt; echo", folder_name, numero);
    system(command);
}

void process_listar(const char* folder_name){
    char command[30];
    sprintf(command, "ls -la %s; echo", folder_name);
    system(command);
}


static void process_command(const char *command) {
    if (strcmp(command, "concordia-ativar") == 0 && !concordia_ativado) {
        const char *username = getlogin();
        if (username == NULL) {
            perror("Erro ao obter o nome do utilizador");
            return;
        }

        char dir_path[256];
        snprintf(dir_path, sizeof(dir_path), "%s/%s", ".", username);
        if (mkdir(dir_path, S_IRWXU) == -1) {
            perror("Erro ao criar o diretório");
            return;
        }

        printf("\nDiretório criado com sucesso para o utilizador %s\n", username);
        concordia_ativado = 1;

    } else if (concordia_ativado) {

        char commandType[50];

        char* token = strtok(command, " "); 

        if (token != NULL) {
            strcpy(commandType, token);
            token = strtok(NULL, " ");
        }

        if(strcmp(command, "concordia-desativar") == 0){
            const char *username = getlogin();

            char dir_path[128];
            snprintf(dir_path, sizeof(dir_path), "%s/%s", ".", username);

            if (remove(dir_path) == 0){
                printf("\nDiretório e mensagens eliminadas com sucesso para o utilizador %s\n", username);
            }   

            concordia_ativado = 0; 
        }

        if(strcmp(command, "concordia-mensagem") == 0 && !concordia_mensagem_ativado){
            concordia_mensagem_ativado = 1;

        } else if (concordia_mensagem_ativado) {


            if(strcmp(commandType, "concordia-enviar") == 0) {
                char dest[20];
                char msg[512];

                if (token != NULL) {
                    strcpy(dest, token); 
                    token = strtok(NULL, " ");
                }

                if (token != NULL) {
                    strcpy(msg, token); 
                    token = strtok(NULL, " ");
                }

                process_enviar(dest, msg);
            }
            
            
            if(strcmp(command, "concordia-ler") == 0){
                const char *username = getlogin();

                char num[2];
                if (token != NULL) {
                    strcpy(num, token); 
                    token = strtok(NULL, " ");
                }

                int num_int = atoi(num);

                
                process_ler(num_int, username);

            }

            if(strcmp(command, "concordia-remover") == 0){
                const char *username = getlogin();

                char num[2];
                if (token != NULL) {
                    strcpy(num, token); 
                    token = strtok(NULL, " ");
                }

                int num_int = atoi(num);
                process_remover(num_int, username);

            }

            if(strcmp(command, "concordia-listar") == 0){
                const char *username = getlogin();

                char flag[5];
                if (token != NULL) {
                    strcpy(flag, token); 
                    token = strtok(NULL, " ");
                
                }

                process_listar(username);

            }
               
        } if(strcmp(command, "concordia-grupo-criar") == 0){
            char groupname[50];
            if (token != NULL) {
                strcpy(groupname, token); 
                token = strtok(NULL, " "); 
            }

            sprintf(command, "sudo groupadd %s; echo", groupname);
            system(command);


        
        } if(strcmp(command, "concordia-grupo-remover") == 0){
            char groupname[50];
            if (token != NULL) {
                strcpy(groupname, token); 
                token = strtok(NULL, " "); 
            }

            sprintf(command, "sudo groupdel %s; echo", groupname);
            system(command);
        
        
        } if(strcmp(command, "concordia-grupo-listar") == 0){
            char groupname[50];
            if (token != NULL) {
                strcpy(groupname, token); 
                token = strtok(NULL, " "); 
            }

            sprintf(command, "getent group %s; echo", groupname);
            system(command);
        
        
        } if(strcmp(command, "concordia-grupo-destinatario-adicionar") == 0){
            char groupname[50];
            char user[50];
            if (token != NULL) {
                strcpy(groupname, token); 
                token = strtok(NULL, " "); 
            }

            if (token != NULL) {
                strcpy(user, token); 
                token = strtok(NULL, " "); 
            }

            sprintf(command, "sudo usermod -a -G %s %s; echo", groupname, user);
            system(command);

        } if(strcmp(command, "concordia-grupo-destinatario-remover") == 0){
            char groupname[50];
            char user[50];
            if (token != NULL) {
                strcpy(groupname, token); 
                token = strtok(NULL, " "); 
            }

            if (token != NULL) {
                strcpy(user, token); 
                token = strtok(NULL, " "); 
            }

            sprintf(command, "sudo deluser %s %s; echo", user, groupname);
            system(command);

        }


    } else {
        printf("Comando inválido: %s\n", command);
    }
}

static void run_main_loop(void) {
    int fd1 = open(PIPE_NAME, O_RDONLY);
    if (fd1 == -1) {
        perror("Can't open stats pipe!");
        return;
    }

    int fd2 = open(PIPE_NAME, O_WRONLY);
    if (fd2 == -1) {
        perror("Can't open stats pipe!");
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytes;

    while ((bytes = read(fd1, buffer, BUFFER_SIZE)) > 0) {
        process_command(buffer);
    }
}

int main(int argc, char **argv) {
    if (mkfifo(PIPE_NAME, 0777) == -1) {
        if (errno != EEXIST) {
            perror("Can't create pipe");
            return EXIT_FAILURE;
        }
    }

    chmod(PIPE_NAME, S_IRUSR | S_IWUSR);

    pid_t pid = fork();

    if (pid == -1) {
        perror("Can't fork daemon process");
        return EXIT_FAILURE;
    } else if (pid == 0) {
        // Código processo filho
        run_main_loop();
    }

    return EXIT_SUCCESS;
}
