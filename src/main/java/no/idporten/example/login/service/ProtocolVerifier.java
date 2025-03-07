package no.idporten.example.login.service;

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

    public static final String protocolVerifierAttrId = "protocol_verifier";

    public static ProtocolVerifier popFromHttpSession(HttpSession session) {
        ProtocolVerifier protocolVerifier =
            (ProtocolVerifier) session.getAttribute(protocolVerifierAttrId);
        session.removeAttribute(protocolVerifierAttrId); // OK if not exists.
        return protocolVerifier;
    }

    public void pushToHttpSession(HttpSession session) {
        session.setAttribute(protocolVerifierAttrId, this);
    }

}
