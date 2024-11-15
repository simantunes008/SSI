CC = gcc
CFLAGS = -Wall -g -Iinclude
LDFLAGS =

all: folders concordia-demonio concordia-ativar concordia-mensagem concordia-enviar concordia-desativar concordia-ler concordia-listar concordia-remover concordia-grupo-criar concordia-grupo-remover concordia-grupo-listar concordia-grupo-dest-add concordia-grupo-dest-rem

concordia-demonio: bin/concordia-demonio

concordia-ativar: bin/concordia-ativar

concordia-mensagem: bin/concordia-mensagem

concordia-enviar: bin/concordia-enviar

concordia-desativar: bin/concordia-desativar

concordia-ler: bin/concordia-ler

concordia-listar: bin/concordia-listar

concordia-remover: bin/concordia-remover

concordia-grupo-criar: bin/concordia-grupo-criar

concordia-grupo-remover: bin/concordia-grupo-remover

concordia-grupo-listar: bin/concordia-grupo-listar

concordia-grupo-dest-add: bin/concordia-grupo-dest-add

concordia-grupo-dest-rem: bin/concordia-grupo-dest-rem


folders:
	@mkdir -p src include obj bin tmp
	
bin/concordia-demonio: obj/concordia-demonio.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-ativar: obj/concordia-ativar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-mensagem: obj/concordia-mensagem.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-enviar: obj/concordia-enviar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-desativar: obj/concordia-desativar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-ler: obj/concordia-ler.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-listar: obj/concordia-listar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-remover: obj/concordia-remover.o
	$(CC) $(LDFLAGS) $^ -o $@	

bin/concordia-grupo-criar: obj/concordia-grupo-criar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-grupo-remover: obj/concordia-grupo-remover.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-grupo-listar: obj/concordia-grupo-listar.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-grupo-dest-add: obj/concordia-grupo-dest-add.o
	$(CC) $(LDFLAGS) $^ -o $@

bin/concordia-grupo-dest-rem: obj/concordia-grupo-dest-rem.o
	$(CC) $(LDFLAGS) $^ -o $@				


obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f obj/* tmp/* bin/*