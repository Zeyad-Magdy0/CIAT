import logging
import sys
import threading
from pathlib import Path
from colorama import init, Fore, Style

init(autoreset=True)
_logger_lock = threading.Lock()


def get_logger(
    name: str,
    level: int = logging.INFO,
    format: str = "%(asctime)s - %(levelname)s - %(message)s",
    log_file: str = "audit.log"   
) -> logging.Logger:   
    logger = logging.getLogger(name)   
    if not logger.handlers:
        with _logger_lock:
            if not logger.handlers: 
                logger.setLevel(level)             
                # Console handler (colored output)
                console_handler = logging.StreamHandler(sys.stdout)
                console_handler.setLevel(level)
                console_handler.setFormatter(_ColorFormatter(format, use_color= True))
                logger.addHandler(console_handler)

                # File handler (plain text)
                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setLevel(level)
                file_handler.setFormatter(_ColorFormatter(format, use_color= False)) 
       
                logger.addHandler(file_handler)   
    return logger


class _ColorFormatter(logging.Formatter):
    # Colorize log level based on severity    
    COLOR_MAP = {
        logging.DEBUG: Fore.GREEN,
        logging.INFO: Fore.BLUE,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    
    def __init__(self, format: str, use_color: bool = True):
        super().__init__(fmt=format, datefmt="%Y-%m-%d %H:%M:%S")
        self.use_color = use_color   
        
    def format(self, record) -> str:
        "Apply color to log level name"
        if self.use_color: 
            level_color = self.COLOR_MAP.get(record.levelno, "")
            record.levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)