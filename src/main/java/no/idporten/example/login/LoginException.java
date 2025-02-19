package no.idporten.example.login;

public class LoginException extends RuntimeException {

    public LoginException(String msg) {
        super(msg);
    }

    public LoginException(String msg, Throwable e) {
        super(msg, e);
    }
}
