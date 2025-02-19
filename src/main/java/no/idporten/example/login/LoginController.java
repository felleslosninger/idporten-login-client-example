package no.idporten.example.login;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import no.idporten.example.login.config.LoginProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;

import com.nimbusds.openid.connect.sdk.AuthenticationRequest;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;

@Controller
public class LoginController {

    private final OIDCProviderMetadata oidcProviderMetadata;

    private final ClientID clientID;
    private final Secret clientSecret;
    private final URI redirectUri;

    public LoginController(LoginProperties loginProperties,
                           OIDCProviderMetadata oidcProviderMetadata) {
        this.oidcProviderMetadata = oidcProviderMetadata;
        this.clientID = loginProperties.client().clientID();
        this.clientSecret = loginProperties.client().clientSecret();
        this.redirectUri = loginProperties.client().redirectUri();
    }

    private final static Logger logger =
        LoggerFactory.getLogger(LoginController.class);

    @GetMapping(path = "/login")
    public String login(HttpSession session) {

        ProtocolVerifier myVerifier = new ProtocolVerifier();

        AuthenticationRequest request =
            new AuthenticationRequest.Builder(
                ResponseType.CODE,   // use authorization code flow.
                new Scope("openid"),
                clientID,
                redirectUri
            ).endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
             .state(myVerifier.state())
             .nonce(myVerifier.nonce())
             .codeChallenge(myVerifier.codeVerifier(), CodeChallengeMethod.S256)
             .build();

        // store state for verification in callback.
        session.setAttribute("protocol_verifier", myVerifier);

        String requestURIStr = request.toURI().toString();
        return "redirect:" + requestURIStr;
    }

    @GetMapping(path = "/callback")
    public String loginCallback(
        HttpServletRequest req,
        HttpSession session,
        Model model) {
        URI authzResponseURI =
            UriComponentsBuilder.fromUri(redirectUri)
                                .query(req.getQueryString())
                                .build()
                                .toUri();

        AuthorizationCode authzCode =
            getAuthzCodeFromAuthzResponse(authzResponseURI, session);

        AccessTokenResponse tokenResp = getAccessTokenResp(authzCode, session);
        Tokens tokens = tokenResp.getTokens();

        // TODO: which tokens do we need to keep around..?
        session.setAttribute("access_token", tokens.getAccessToken().getValue());
        session.setAttribute("refresh_token", tokens.getRefreshToken().getValue());

        if (tokenResp instanceof OIDCTokenResponse oidcTokenResp) {

            JWT oidcToken = oidcTokenResp.getOIDCTokens().getIDToken();
            session.setAttribute("oidc_token", oidcToken.getParsedString());

            ClaimsSet claims = validateIdToken(oidcToken, session);

            String pidStr = (String) claims.getClaim("pid");
            if (pidStr == null) {
                throw new MyLoginException("No pid in claims!");
            }
            // TODO: d- eller f-nr?

            logger.info("Got pid from claims");
            model.addAttribute("pid", pidStr);
        }

        return "login_success";
    }

    private ClaimsSet validateIdToken(JWT token, HttpSession session) {
        try {

            JWSAlgorithm jwsAlgorithm =
                (JWSAlgorithm) token.getHeader().getAlgorithm();
            URL jwkSetUrl = oidcProviderMetadata.getJWKSetURI().toURL();

            IDTokenValidator idTokenValidator =
                new IDTokenValidator(oidcProviderMetadata.getIssuer(),
                                     clientID,
                                     jwsAlgorithm,
                                     jwkSetUrl);

            Nonce expectedNonce =
                ProtocolVerifier.fromHttpSession(session).nonce();

            ClaimsSet claims = idTokenValidator.validate(token, expectedNonce);
            logger.info("Token validation successful");
            return claims;
        }
        catch (Exception e) {
            throw new MyLoginException("ID validation failed", e);
        }
    }

    private AccessTokenResponse getAccessTokenResp(
        AuthorizationCode authzCode,
        HttpSession session) {
        try {
            CodeVerifier codeVerifier =
                ProtocolVerifier.fromHttpSession(session).codeVerifier();

            AuthorizationGrant codeGrant =
                new AuthorizationCodeGrant(
                    authzCode,
                    redirectUri,
                    codeVerifier);

            ClientAuthentication clientAuthn =
                new ClientSecretBasic(clientID, clientSecret);

            Scope scope = new Scope("openid");
            TokenRequest tokenReq =
                new TokenRequest(oidcProviderMetadata.getTokenEndpointURI(),
                                 clientAuthn,
                                 codeGrant,
                                 scope);

            TokenResponse tokenResp =
                OIDCTokenResponse.parse(tokenReq.toHTTPRequest().send());

            if (!tokenResp.indicatesSuccess()) {
                TokenErrorResponse errorResp = tokenResp.toErrorResponse();
                // TODO: how to get a proper error msg here?
                throw new MyLoginException("Token request error: " +
                    errorResp.getErrorObject().toString());
            }

            return tokenResp.toSuccessResponse();
        }
        // TODO: best practice for catching multiple exceptions?
        catch (
            IOException |
            ParseException e) {
            throw new MyLoginException("Error sending token request", e);
        }
    }

    private AuthorizationCode getAuthzCodeFromAuthzResponse(
        URI authzResponseURI,
        HttpSession session) {
        try {
            AuthorizationResponse resp =
                AuthorizationResponse.parse(authzResponseURI);

            // authz code flow requires that state received in an authz response
            // should match state sent in authz request.
            // this should be stored in session from the authorization request.
            State lastState = ProtocolVerifier.fromHttpSession(session).state();
            if (lastState == null) {
                throw new MyLoginException("No stored state found");
            }
            if (!Objects.equals(resp.getState(), lastState)) {
                throw new MyLoginException("Bad state");
            }
            if (!resp.indicatesSuccess()) {
                throw new MyLoginException(resp.toErrorResponse().toString());
            }

            return resp.toSuccessResponse().getAuthorizationCode();
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
