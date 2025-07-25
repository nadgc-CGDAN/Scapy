try:
    from flask import Flask
    print("Flask importado com sucesso!")
except ImportError:
    print("Erro: Flask não está instalado.")
