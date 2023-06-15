import hashlib
import time


def brute_force_md5(username, target_hash, charset, max_length):
    if len(target_hash) != 32:
        print(f"A hash MD5 para o usuário {username} precisa ter 32 caracteres.")
        return

    start_time = time.time()
    print(f"Iniciando ataque de força bruta para o usuário {username}...")
    for length in range(1, max_length + 1):
        generate_passwords(username, "", target_hash, charset, length)

    print(f"Ataque concluído para o usuário {username}. A senha não foi encontrada.")
    elapsed_time = time.time() - start_time
    print(f"Tempo de execução: {elapsed_time:.2f} segundos")

def generate_passwords(username, current_password, target_hash, charset, length):
    start_time = time.time()
    if length == 0:
        if hashlib.md5(current_password.encode()).hexdigest() == target_hash:
            print(f"Senha encontrada para o usuário {username}: {current_password}")
            elapsed_time = time.time() - start_time
            print(f"Tempo de execução: {elapsed_time:.2f} segundos")
            exit()
        return

    for char in charset:
        new_password = current_password + char
        generate_passwords(username, new_password, target_hash, charset, length - 1)

def search_hash_in_file(file_path, charset, max_length):
    start_time = time.time()
    with open(file_path, "r") as file:
        for line in file:
            username, target_hash = line.strip().split(",")
            brute_force_md5(username, target_hash, charset, max_length)

    elapsed_time = time.time() - start_time
    print("A senha não foi encontrada no arquivo.")
    print(f"Tempo de execução total: {elapsed_time:.2f} segundos")

# Configurações do ataque
file_path = "C:\\Users\\joao.merlin.GRUPOMARISTA\\SOMATIVA-2-SI\\usuarios.txt"  # Caminho para o arquivo de hashes
charset = "abcdefghijklmnopqrstuvwxyz1234567890"  # Caracteres possíveis
max_length = 5  # Tamanho máximo da senha a ser testada

# Execução do ataque
search_hash_in_file(file_path, charset, max_length)
