from log import get_logger
import logging
import threading


def test_basic_logging():
    
    print("==== Test 1: Basic Logging ===")
    
    logger = get_logger("test basic logging")
    
    logger.debug("Debug message should be green")
    logger.info("Info message should be blue")
    logger.warning("Warning message should be yellow")
    logger.error("Error message should be red")
    logger.critical("Critical message should be red and bold")
    
    
def test_log_level():
    
    print("==== Test 2: Log Level ===")
    logger = get_logger("test log level", level=logging.ERROR)
    
    logger.debug("Debug message should not be printed")
    logger.info("Info message should not be printed")
    logger.warning("Warning message should not be printed")
    logger.error("Error message should be printed")
    logger.critical("Critical message should be printed")
   
    
def test_log_format():
    
    print("==== Test 3: Log Format ===")
    logger = get_logger("test log format", format="%(levelname)s|%(message)s")
    
    logger.info("Custom format test")
    logger.error("Should show level message only")
    
    
def test_no_duplicate_handlers():
    print("\n=== Test 4: No Duplicate Handlers ===")
    logger1 = get_logger("test_duplicates")
    handler_count1 = len(logger1.handlers)
    
    logger2 = get_logger("test_duplicates")
    handler_count2 = len(logger2.handlers)
    
    print(f"Handlers before: {handler_count1}, after: {handler_count2}")
    assert handler_count1 == handler_count2, "Duplicate handler detected!"
    
    
def test_thread_safety():

    print("\n=== Test 5: Thread Safety ===")
    
    def worker():
        logger = get_logger("test_threading")
        logger.info(f"Message from thread {threading.get_ident()}")
    
    threads = []
    for _ in range(5):
        t = threading.Thread(target=worker)
        threads.append(t)
        t.start()
    
    for t in threads:
        t.join()
    
    logger = get_logger("test_threading")
    print(f"Final handler count: {len(logger.handlers)} (should be 1)")
    
