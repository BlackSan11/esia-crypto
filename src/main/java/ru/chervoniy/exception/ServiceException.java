package ru.chervoniy.exception;

public class ServiceException extends Exception {

    public ServiceException(String message, Throwable e) {
        super(message, e);
    }

    public ServiceException(String message) {

    }
}
