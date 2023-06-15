import hashlib
import os
import re

def cadastrar_usuario():
    regex = re.compile(r'^[a-zA-Z]{2}\d{2}$')
    nome = input("Digite o nome do usuário (até 20 caracteres): ")
    senha = input("Digite a senha do usuário (4 caracteres): ")

    if regex.fullmatch(senha):
        senha_hash = hashlib.md5(senha.encode()).hexdigest()
        with open(r"C:\Users\joao.merlin.GRUPOMARISTA\SOMATIVA-2-SI\usuarios.txt", "a") as file:
            file.write(f"{nome},{senha_hash}\n")

        print("Usuário cadastrado com sucesso!")
    else:
        print("Escreva uma senha valida")

    if len(nome) > 20 or len(senha) != 4:
        print("Erro: Nome deve ter até 20 caracteres e senha deve ter 4 caracteres.")
        return

def autenticar_usuario():
    nome = input("Digite o nome do usuário: ")
    senha = input("Digite a senha do usuário: ")

    senha_hash = hashlib.md5(senha.encode()).hexdigest()

    with open(r"C:\Users\joao.merlin.GRUPOMARISTA\SOMATIVA-2-SI\usuarios.txt","r") as file:
        for line in file:
            usuario, senha_armazenada = line.strip().split(",")
            print(line)
            if usuario == nome and senha_armazenada == senha_hash:
                print("Autenticação bem-sucedida!")
                return

    print("Nome de usuário ou senha incorretos.")

def main():
    if not os.path.isfile("usuarios.txt"):
        open("usuarios.txt", "w").close()

def main():
    while True:
        print("\n1 - Cadastrar usuário")
        print("2 - Autenticar usuário")
        print("0 - Sair")
        opcao = input("Digite a opção desejada: ")

        if opcao == "1":
            cadastrar_usuario()
        elif opcao == "2":
            autenticar_usuario()
        elif opcao == "0":
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()