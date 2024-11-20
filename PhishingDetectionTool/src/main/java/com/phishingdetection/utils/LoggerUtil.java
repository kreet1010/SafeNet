package com.phishingdetection.utils;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LoggerUtil {
    // Create a logger instance
    private static final Logger logger = Logger.getLogger(LoggerUtil.class.getName());
    
    // Set up a console handler for logging output to the console
    static {
        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);
        logger.addHandler(consoleHandler);
        logger.setLevel(Level.ALL);  
    }

    // Log an INFO level message
    public static void logInfo(String message) {
        logger.info(message);
    }

    // Log a WARNING level message
    public static void logWarning(String message) {
        logger.warning(message);
    }

    // Log a SEVERE level message
    public static void logError(String message) {
        logger.severe(message);
    }

    // Log a FINE level message for debugging
    public static void logDebug(String message) {
        logger.fine(message);
    }
}
