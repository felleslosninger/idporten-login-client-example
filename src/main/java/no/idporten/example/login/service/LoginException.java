package no.idporten.example.login.service;

public class LoginException extends RuntimeException {

    public LoginException(String msg) {
        super(msg);
    }

    public LoginException(String msg, Throwable e) {
        super(msg, e);
    }
}
