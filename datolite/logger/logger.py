LOGGER_LEVEL = 5

class Logger:
    RESET = "\033[0m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"

    @staticmethod
    def info(message):
        if LOGGER_LEVEL >= 3:
            print(f"{Logger.GREEN}[INFO] {Logger.RESET}{message}")

    @staticmethod
    def warn(message):
        if LOGGER_LEVEL >= 2:
            print(f"{Logger.YELLOW}[WARNING] {Logger.RESET}{message}")

    @staticmethod
    def error(message):
        if LOGGER_LEVEL >= 1:
            print(f"{Logger.RED}[ERROR] {Logger.RESET}{message}")

    @staticmethod
    def debug(message):
        if LOGGER_LEVEL >= 4:
            print(f"{Logger.CYAN}[DEBUG] {Logger.RESET}{message}")

    @staticmethod
    def cassert(condition, message):
        if not condition:
            Logger.error(message)
            exit(1)

    @staticmethod
    def set_level(level: int):
        global LOGGER_LEVEL
        LOGGER_LEVEL = level

    @staticmethod
    def get_level() -> int:
        return LOGGER_LEVEL