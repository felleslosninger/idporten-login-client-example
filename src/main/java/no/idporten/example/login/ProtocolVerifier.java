package no.idporten.example.login;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.servlet.http.HttpSession;

public record ProtocolVerifier(
    State state,
    Nonce nonce,
    CodeVerifier codeVerifier) {

    public ProtocolVerifier() {
        this(new State(), new Nonce(), new CodeVerifier());
    }

    public static ProtocolVerifier fromHttpSession(HttpSession session) {
        return (ProtocolVerifier) session.getAttribute("protocol_verifier");
    }
}
