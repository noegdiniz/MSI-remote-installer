import argparse
import ipaddress
import os
import subprocess
import getpass # Usado para esconder a senha ao digitar

def parse_ips(ip_string):
    """Analisa uma string de IPs, que pode ser um range (ex: 192.168.1.1-192.168.1.10) ou uma lista separada por vírgulas."""
    ips = []
    if '-' in ip_string:
        try:
            start_ip_str, end_ip_str = ip_string.split('-')
            start_ip = ipaddress.ip_address(start_ip_str.strip())
            end_ip = ipaddress.ip_address(end_ip_str.strip())
            while start_ip <= end_ip:
                ips.append(str(start_ip))
                start_ip += 1
        except ValueError as e:
            print(f"Erro: Range de IP inválido. {e}")
            exit(1)
    else:
        ips = [ip.strip() for ip in ip_string.split(',')]
    return ips

def run_psexec_command(psexec_path, ip, username, password, command):
    """Executa um comando em uma máquina remota usando psexec.exe e retorna o resultado."""
    psexec_command = [
        psexec_path,
        f"\\\\{ip}",
        "-u", username,
        "-p", password,
        "-s", # Executa o comando com privilégios de sistema
        "-accepteula", # Aceita o EULA do PsExec na primeira execução
        "cmd.exe",
        "/c",
        command
    ]
    
    try:
        # O timeout é importante para evitar que o script fique preso em máquinas offline
        result = subprocess.run(psexec_command, capture_output=True, text=True, encoding='latin-1', timeout=90)
        return result
    except FileNotFoundError:
        print(f"Erro: O executável do PsExec não foi encontrado em '{psexec_path}'. Verifique o caminho.")
        return None
    except subprocess.TimeoutExpired:
        print(f"Erro: A conexão com {ip} excedeu o tempo limite. A máquina pode estar offline ou bloqueada por firewall.")
        return None
    except Exception as e:
        print(f"Ocorreu um erro inesperado ao executar o PsExec: {e}")
        return None

def main():
    # Caminho literal para o PsExec
    psexec_path = r"C:\PROJETOS\PSTools\PSexec.exe"

    parser = argparse.ArgumentParser(
        description='Ferramenta de instalação remota de MSI usando PsExec.exe.',
        formatter_class=argparse.RawTextHelpFormatter # Melhora a formatação da ajuda
    )
    
    parser.add_argument('--msi_file', required=True, help='Caminho local completo para o arquivo MSI.')
    parser.add_argument('--ips', required=True, help='Range de IPs (ex: 192.168.1.1-192.168.1.10) ou IPs separados por vírgula.')
    parser.add_argument('--username', required=True, help='Nome de usuário para acesso remoto (ex: dominio\\usuario).')
    parser.add_argument('--password', help='Senha para acesso remoto. Se não for fornecida, será solicitada.')
    parser.add_argument('--install_command', required=True, help='Comando de instalação do MSI (use "installer.msi" como placeholder).\nExemplo: "msiexec /i C:\\Windows\\Temp\\installer.msi /qn"')
    parser.add_argument('--force', action='store_true', help='Força a reinstalação mesmo se o software já estiver instalado.')
    args = parser.parse_args()

    # Solicita a senha de forma segura se não for passada como argumento
    password = args.password if args.password else getpass.getpass(f"Digite a senha para o usuário {args.username}: ")

    msi_filename = os.path.basename(args.msi_file)
    remote_temp_path = f"C:\\{msi_filename}"

    ip_list = parse_ips(args.ips)

    # Força a reinstalação se a flag --force for usada
    force = args.force
    
    for ip in ip_list:
        print(f"\n--- Processando {ip} ---")
        
        # Faça um teste de ping
        ping_command = ['ping', '-n', '1', '-w', '1000', ip]
        ping_result = subprocess.run(ping_command, capture_output=True, text=True)
        if ping_result.returncode != 0:
            print(f"Erro: {ip} está offline ou inacessível (ping falhou). Pulando...")
            continue
        
        # 1. Verificar se o processo "Netskope Client" está em execução
        if not force:
            print(f"Verificando processo 'Netskope Client' em {ip}...")
            check_command = 'TASKLIST'
            result = run_psexec_command(psexec_path, ip, args.username, password, check_command)

            if result is None:
                # Erro já foi impresso pela função run_psexec_command
                continue
        
            # O PsExec pode retornar código 1 se o processo não for encontrado, o que é esperado.
            # Verificamos a saída de texto para ter certeza.
            if "stAgentUI.exe" in result.stdout or "stAgentSvc.exe" in result.stdout:
                print(f"-> 'Netskope Client' JÁ ESTÁ em execução em {ip}. Instalação ignorada.")
                
                continue
            else:
                print(f"-> 'Netskope Client' NÃO está em execução. Prosseguindo com a instalação.")

        # 2. Copiar o arquivo MSI para o diretório temporário remoto
        # O PsExec pode copiar arquivos automaticamente se o caminho for local
        print(f"Copiando {msi_filename} para \\\\{ip}\\C$")
        copy_command = f'copy "{args.msi_file}" \\\\{ip}\\C$'
        # Usamos subprocess.run localmente para a cópia, pois é mais simples
        copy_result = subprocess.run(copy_command, shell=True, capture_output=True, text=True)
        
        if copy_result.returncode != 0:
            print(f"-> Falha ao copiar o arquivo para {ip}. Erro: {copy_result.stderr}")
            continue
        print("-> Cópia concluída.")

        # 3. Executar o comando de instalação
        # Substitui o placeholder pelo nome real do arquivo MSI
        full_install_command = args.install_command.replace("installer.msi", msi_filename)
        print(f"Executando comando de instalação: '{full_install_command}'...")
        
        install_result = run_psexec_command(psexec_path, ip, args.username, password, full_install_command)

        if install_result and install_result.returncode == 0:
            print(f"-> Instalação concluída com sucesso em {ip}.")
        elif install_result:
            print(f"-> Instalação falhou em {ip} com código de saída {install_result.returncode}.")
            print(f"   STDOUT: {install_result.stdout.strip()}")
            print(f"   STDERR: {install_result.stderr.strip()}")
        
        # 4. (Opcional) Limpar o arquivo de instalação
        print(f"Limpando o instalador em {remote_temp_path}...")
        cleanup_command = f"del {remote_temp_path}"
        run_psexec_command(psexec_path, ip, args.username, password, cleanup_command)
        print("-> Limpeza concluída.")

if __name__ == '__main__':
    main()
