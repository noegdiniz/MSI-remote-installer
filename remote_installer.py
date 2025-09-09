import argparse
import ipaddress
import os
import subprocess
import getpass
from multiprocessing import Pool


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
        "-s",
        "-accepteula",
        "cmd.exe",
        "/c",
        command
    ]
    try:
        result = subprocess.run(
            psexec_command,
            capture_output=True,
            text=True,
            encoding='latin-1',
            timeout=90
        )
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


def process_ip(args_tuple):
    """Função chamada pelos workers do Pool."""
    ip, psexec_path, args, password, msi_filename, remote_temp_path, force = args_tuple

    print(f"\n--- Processando {ip} ---")

    # Testa ping
    ping_command = ['ping', '-n', '1', '-w', '1000', ip]
    ping_result = subprocess.run(ping_command, capture_output=True, text=True)
    if ping_result.returncode != 0:
        print(f"Erro: {ip} está offline ou inacessível (ping falhou). Pulando...")
        return

    # 1. Verificar se o Netskope Client já está rodando
    if not force:
        print(f"Verificando processo 'Netskope Client' em {ip}...")
        result = run_psexec_command(psexec_path, ip, args.username, password, "TASKLIST")

        if result is None:
            return

        if "stAgentUI.exe" in result.stdout or "stAgentSvc.exe" in result.stdout:
            print(f"-> 'Netskope Client' JÁ ESTÁ em execução em {ip}. Instalação ignorada.")
            return
        else:
            print(f"-> 'Netskope Client' NÃO está em execução. Prosseguindo com a instalação.")

    # 2. Copiar MSI
    print(f"Copiando {msi_filename} para \\\\{ip}\\C$")
    copy_command = f'copy "{args.msi_file}" \\\\{ip}\\C$'
    copy_result = subprocess.run(copy_command, shell=True, capture_output=True, text=True)

    if copy_result.returncode != 0:
        print(f"-> Falha ao copiar o arquivo para {ip}. Erro: {copy_result.stderr}")
        return
    print("-> Cópia concluída.")

    # 3. Instalar
    full_install_command = args.install_command.replace("installer.msi", msi_filename)
    print(f"Executando comando de instalação: '{full_install_command}'...")

    install_result = run_psexec_command(psexec_path, ip, args.username, password, full_install_command)

    if install_result and install_result.returncode == 0:
        print(f"-> Instalação concluída com sucesso em {ip}.")
    elif install_result:
        print(f"-> Instalação falhou em {ip} com código {install_result.returncode}.")
        print(f"   STDOUT: {install_result.stdout.strip()}")
        print(f"   STDERR: {install_result.stderr.strip()}")

    # 4. Limpar instalador
    print(f"Limpando o instalador em {remote_temp_path}...")
    cleanup_command = f"del {remote_temp_path}"
    run_psexec_command(psexec_path, ip, args.username, password, cleanup_command)
    print("-> Limpeza concluída.")


def main():
    psexec_path = r"C:\PROJETOS\PSTools\PSexec.exe"

    parser = argparse.ArgumentParser(
        description='Ferramenta de instalação remota de MSI usando PsExec.exe.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--msi_file', required=True)
    parser.add_argument('--ips', required=True)
    parser.add_argument('--username', required=True)
    parser.add_argument('--password')
    parser.add_argument('--install_command', required=True)
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--processes', type=int, default=20, help='Número de processos paralelos (padrão: 20)')
    
    args = parser.parse_args()

    password = args.password if args.password else getpass.getpass(f"Digite a senha para {args.username}: ")

    msi_filename = os.path.basename(args.msi_file)
    remote_temp_path = f"C:\\{msi_filename}"
    processes = args.processes
    
    ip_list = parse_ips(args.ips)

    jobs = [(ip, psexec_path, args, password, msi_filename, remote_temp_path, args.force) for ip in ip_list]

    with Pool(processes=processes) as pool:
        pool.map(process_ip, jobs)


if __name__ == '__main__':
    main()
