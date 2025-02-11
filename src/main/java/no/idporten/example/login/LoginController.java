package no.idporten.example.login;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.net.URI;

@Controller
public class LoginController {
    private final String clientIDStr = "oidc_idporten_example_login";
    private final String callbackURIStr = "http://localhost:7040/callback";
    private final String endpointURIStr = "https://login.idporten.dev/authorize";

    // used to check state in authorization responses.
    private State lastState;

    @GetMapping(path = "/login")
    public String login() {

        ClientID clientID = new ClientID(clientIDStr);

        // can use URI.create() since we know the addresses to be valid.
        URI callbackURI = URI.create(callbackURIStr);
        URI endpointURI = URI.create(endpointURIStr);

        State state = new State();

        AuthenticationRequest request =
            new AuthenticationRequest.Builder(
                ResponseType.CODE,   // use authorization code flow.
                new Scope("openid"), // TODO: +profile?
                clientID,
                callbackURI
            ).endpointURI(endpointURI)
             .state(state)
             .nonce(new Nonce())
             .codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256) // PKCE
             .build();

        // store state for verification in callback.
        lastState = state;

        String requestURIStr = request.toURI().toString();
        return "redirect:" + requestURIStr;
    }
}
