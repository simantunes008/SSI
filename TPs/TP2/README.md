# Concordia

## Descrição

O seguinte programa faz a gestão de utilizadores e grupos em ambientes bem como a troca de mensagens entre os utilizadores.

## Inicialização

Começamos por fazer a compilação de todos os ficheiros com auxílio da makefile e através do comando:
```bash
make
```

De seguida deve-se dar início ao concordia-demonio que é o servidor do nosso serviço.

```bash
./bin/concordia-demonio
```

Após isso os utilizadores devem ligar-se ao servidor

```bash
./bin/concordia-ativar
```

A pasta com o nome do utilizador foi criada

Depois do utilizador estar ligado podemos passar à troca de mensagens, no início temos de correr o comando
```bash
./bin/concordia-mensagem
```

E depois poderemos escolher entre uma das opções disponíveis para a mensagem:

Enviar uma mensagem a um destinatário:
```bash
./bin/concordia-enviar dest msg
```

Ler uma mensagem através do seu número:
```bash
./bin/concordia-ler [num_msg]
```

Listar todas as mensagens de um utilizador:
```bash
./bin/concordia-listar
```

Remover todas as mensagens de um utilizador:
```bash
./bin/concordia-remover
```



Relativamente à gestão de grupos podemos fazer a criação de um grupo:

```bash
./bin/concordia-grupo-criar [nome do grupo]
```

Remover um grupo:
```bash
./bin/concordia-grupo-remover [nome do grupo]
```

Listar os membros de um grupo:
```bash
./bin/concordia-grupo-listar [nome do grupo]
```

Adicionar um utilizador a um grupo:
```bash
./bin/concordia-grupo-destinatario-adicionar [nome do grupo] [utilizador]
```

Remover um utilizador a um grupo:
```bash
./bin/concordia-grupo-destinatario-remover [nome do grupo] [utilizador]
```