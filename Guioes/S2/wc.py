import sys

linhas = 0
palavras = 0
caracteres = 0

if len(sys.argv) < 2:
    for line in sys.stdin.readlines():
        linhas += 1
        palavras += len(line.split())
        caracteres += len(line)
else:
    file = sys.argv[1]
    with open(file, 'r') as f:
        for line in f:
            linhas += 1
            palavras += len(line.split())
            caracteres += len(line)

print(f"{linhas} {palavras} {caracteres}")
