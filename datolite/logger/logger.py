
LOGGER_LEVEL = 5

class Logger:
  def info(message):
    if LOGGER_LEVEL >= 3:
      print(f"[INFO] {message}")
  
  def warn(message):
    if LOGGER_LEVEL >= 2:
      print(f"[WARNING] {message}")
    
  def error(message):
    if LOGGER_LEVEL >= 1:
      print(f"[ERROR] {message}")
  
  def debug(message):
    if LOGGER_LEVEL >= 4:
      print(f"[DEBUG] {message}")
  
  def set_level(level: int):
    global LOGGER_LEVEL
    LOGGER_LEVEL = level
  
  def get_level() -> int:
    return LOGGER_LEVEL