from datetime import datetime

def log(msg: str, module: str = ""):
    print(f"{datetime.now()} {module}:\t{msg}")
