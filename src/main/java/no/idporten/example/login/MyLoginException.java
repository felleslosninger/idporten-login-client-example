package no.idporten.example.login;

public class MyLoginException extends RuntimeException {

    public MyLoginException(String msg) {
        super(msg);
    }

    public MyLoginException(String msg, Throwable e) {
        super(msg, e);
    }
}
