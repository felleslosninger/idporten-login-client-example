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
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.net.URI;

@Controller
public class LoginController {

    // TODO
    // @Value("@{.../callbackURI}")
    // private final String callbackURIStr;

    // used to check state in authorization responses.
    private State lastState;

    @GetMapping(path = "/login")
    public String login(Model model) { // TODO: need model?

        ClientID clientID = new ClientID("oidc_idporten_example_login");

        // can use URI.create() since we know the addresses to be valid.
        // TODO: what happens if callback/endpoint address/port change?
        URI callbackURI = URI.create("http://localhost:7040/callback");
        URI endpointURI = URI.create("https://login.idporten.dev/authorize");

        State state = new State();

        AuthenticationRequest request =
            new AuthenticationRequest.Builder(
                ResponseType.CODE, // authorization code flow
                new Scope("openid"), // TODO: +profile?
                clientID,
                callbackURI
            ).endpointURI(endpointURI)
             .state(state)
             .nonce(new Nonce())
             .codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256) // PKCE
             .build();

        lastState = state;

        String requestURIStr = request.toURI().toString();
        return "redirect:" + requestURIStr;
    }


    @GetMapping(path = "/callback")
    public String loginCallback() {
        // TODO
        return "";
    }
}