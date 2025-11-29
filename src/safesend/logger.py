# safesend/logger.py

LOGGER = print  # default prints to terminal

def set_logger(func):
    """
    Set the global logger function.
    func must be a function that accepts (message: str)
    """
    global LOGGER
    LOGGER = func

def log(msg: str):
    """
    Log a message using the current logger function.
    """
    LOGGER(str(msg))
