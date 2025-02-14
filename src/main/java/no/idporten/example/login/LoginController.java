package no.idporten.example.login;


import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.openid.connect.sdk.Prompt;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.net.URI;
import java.util.Objects;

@Controller
public class LoginController {

    private final static Logger logger = LoggerFactory.getLogger(LoginController.class);

    private final String clientIDStr = "oidc_idporten_example_login";
    private final String callbackURIStr = "http://localhost:7040/callback";
    private final String endpointURIStr = "https://login.idporten.dev/authorize";
    final URI callbackURI = URI.create("http://localhost:7040/callback");

    @GetMapping(path = "/login")
    public String login(HttpSession session) {

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
             .prompt(Prompt.Type.LOGIN)
             .build();

        // store state for verification in callback.
        session.setAttribute("state", state);

        String requestURIStr = request.toURI().toString();
        return "redirect:" + requestURIStr;
    }

    @GetMapping(path = "/callback")
    public String loginCallback(HttpServletRequest req, HttpSession session, Model model) {
        URI authzResponseURI = UriComponentsBuilder.fromUri(callbackURI)
                                                   .query(req.getQueryString())
                                                   .build()
                                                   .toUri();
        return handleCallbackURI(authzResponseURI, session, model);
    }

    private String handleCallbackURI(URI authzResponseURI, HttpSession session, Model model) {
        try {
            AuthorizationResponse resp = AuthorizationResponse.parse(authzResponseURI);

            // authz code flow requires that state received in an authz response
            // should match state sent in authz request.
            // this should be stored in session from the authorization request.
            State lastState = (State) session.getAttribute("state");
            if (lastState == null) {
                throw new MyLoginException("No stored state found");
            }
            if (!Objects.equals(resp.getState(), lastState)) {
                throw new MyLoginException("Bad state");
            }
            if (!resp.indicatesSuccess()) {
                throw new MyLoginException(resp.toErrorResponse().toString());
            }

            model.addAttribute("errmsg_attr", "Success");

            String authzCode = resp.toSuccessResponse()
                                   .getAuthorizationCode()
                                   .getValue();
            model.addAttribute("authz_code_attr", authzCode);

            return "login_success";
        }
        catch (ParseException e) {
            throw new MyLoginException("Authorization response parse error", e);
        }
    }

    @ExceptionHandler
    public String handleMyLoginException(MyLoginException e, Model model) {
        model.addAttribute("errmsg_attr", "Login error: " + e.getMessage());
        logger.error("Login failed with exception: ", e);
        return "login_fail";
    }
}
