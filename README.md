# Ferramenta de Instalação Remota de MSI

Esta ferramenta Python permite a instalação remota de arquivos `.msi` em máquinas Windows usando `PStools` (via `pypsexec`), com uma verificação para garantir que o processo "Netskope Client (32 bits)" não esteja em execução na máquina de destino antes da instalação.

## Requisitos

- Python 3.x
- Biblioteca `pypsexec` (será instalada automaticamente)
- Acesso de administrador às máquinas Windows de destino.
- As máquinas de destino devem ter o serviço "Remote Registry" habilitado (geralmente habilitado por padrão).
- As máquinas de destino devem permitir conexões WMI e SMB (verifique as configurações de firewall).

## Instalação

1. Clone este repositório ou baixe o arquivo `remote_installer.py`.

2. Instale as dependências:

   ```bash
   pip install pypsexec
   ```

## Uso

```bash
python remote_installer.py --msi_file <caminho_do_msi> --ips <ips_ou_range> --username <usuario> --password <senha> --install_command "msiexec /i <nome_do_msi> /qn"
```

### Argumentos:

- `--msi_file`: **Obrigatório**. Caminho completo para o arquivo `.msi` local a ser instalado.
- `--ips`: **Obrigatório**. Pode ser um único IP, uma lista de IPs separados por vírgula (ex: `192.168.1.1,192.168.1.2`) ou um range de IPs (ex: `192.168.1.1-192.168.1.10`).
- `--username`: **Obrigatório**. Nome de usuário com permissões de administrador nas máquinas de destino.
- `--password`: **Obrigatório**. Senha do usuário especificado.
- `--install_command`: **Obrigatório**. O comando `msiexec` completo para a instalação. **Importante**: Substitua o nome do arquivo `.msi` no comando pelo placeholder `installer.msi` (ex: `msiexec /i installer.msi /qn`). A ferramenta substituirá `installer.msi` pelo nome base do seu arquivo `.msi` automaticamente.

### Exemplo:

Para instalar `meu_aplicativo.msi` nas máquinas `192.168.1.5` e `192.168.1.6` usando o usuário `administrador` e a senha `MinhaSenha123`:

```bash
python remote_installer.py \
  --msi_file "C:\Users\SeuUsuario\Downloads\meu_aplicativo.msi" \
  --ips "192.168.1.5,192.168.1.6" \
  --username "administrador" \
  --password "MinhaSenha123" \
  --install_command "msiexec /i installer.msi /qn"
```

Para instalar `outro_app.msi` em um range de IPs de `192.168.1.10` a `192.168.1.20`:

```bash
python remote_installer.py \
  --msi_file "/path/to/outro_app.msi" \
  --ips "192.168.1.10-192.168.1.20" \
  --username "dominio\\usuario_admin" \
  --password "SenhaSegura!" \
  --install_command "msiexec /i installer.msi /quiet /norestart"
```

## Como funciona

1. A ferramenta parseia os IPs fornecidos.
2. Para cada IP, ela tenta conectar à máquina remota usando as credenciais fornecidas.
3. Verifica se o processo "Netskope Client (32 bits)" está em execução. Se estiver, a instalação é ignorada para aquela máquina.
4. Se o processo não estiver em execução, o arquivo `.msi` é copiado para o diretório `C:\Windows\Temp\` na máquina remota.
5. O comando `msiexec` fornecido é executado remotamente para iniciar a instalação.
6. O status da instalação (sucesso ou falha) é reportado.

## Observações

- Certifique-se de que o arquivo `.msi` especificado em `--msi_file` existe e é acessível a partir do local onde você executa o script.
- A ferramenta utiliza `tasklist.exe` para verificar processos e `cmd.exe` para executar o comando `msiexec` remotamente. Certifique-se de que esses executáveis estão disponíveis no PATH das máquinas de destino.
- Em caso de problemas de conexão ou permissão, verifique as credenciais, o firewall do Windows e as configurações de segurança nas máquinas de destino.


