# ReconForge (Linux)

Ferramenta de reconnaissance feita para rodar em Linux. Suporte a Windows foi removido.

## Requisitos (Linux)

- Python 3.11+ (recomendado: virtualenv)
- `nmap` instalado no sistema e acessível via `PATH`

Exemplo (Debian/Kali/Ubuntu):

```bash
sudo apt update
sudo apt install -y nmap
```

## Instalação

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

## Execução

```bash
source venv/bin/activate
python reconforge.py example.com -o reconforge_output --format html
```
