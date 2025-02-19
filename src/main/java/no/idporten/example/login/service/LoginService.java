package no.idporten.example.login.service;

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
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
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

@Component
public class LoginService {

    private final OIDCProviderMetadata oidcProviderMetadata;

    private final ClientID clientID;
    private final Secret clientSecret;
    private final URI redirectUri;

    public LoginService(LoginProperties loginProperties,
                        OIDCProviderMetadata oidcProviderMetadata) {
        this.oidcProviderMetadata = oidcProviderMetadata;
        this.clientID = loginProperties.client().clientID();
        this.clientSecret = loginProperties.client().clientSecret();
        this.redirectUri = loginProperties.client().redirectUri();
    }

    private final static Logger logger =
        LoggerFactory.getLogger(LoginService.class);

    public URI getAuthnRequestUri(HttpSession session) {
        return makeAuthnRequest(session).toURI();
    }

    private AuthenticationRequest makeAuthnRequest(HttpSession session) {
        ProtocolVerifier verifier = new ProtocolVerifier();

        AuthenticationRequest request =
            new AuthenticationRequest.Builder(
                ResponseType.CODE,   // use authorization code flow.
                new Scope("openid"),
                clientID,
                redirectUri
            ).endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
             .state(verifier.state())
             .nonce(verifier.nonce())
             .codeChallenge(verifier.codeVerifier(), CodeChallengeMethod.S256)
             .build();

        // if authn request is successful, add verifier to session.
        session.setAttribute("protocol_verifier", verifier);
        logger.info("Made authn request; added protocol_verifier to session");
        return request;
    }

    // TODO: signature?
    // in particular: what's the return type, and does the method use model?
    public void handleLoginCallback(
        HttpServletRequest request,
        Model model) {
        HttpSession session = request.getSession();

        URI authzResponseUri =
            UriComponentsBuilder.fromUri(redirectUri)
                                .query(request.getQueryString())
                                .build()
                                .toUri();
        AuthorizationCode authzCode =
            getAuthzCodeFromAuthzResponse(authzResponseUri, session);

        makeTokenRequest(authzCode, session, model);
    }

    private void makeTokenRequest(
        AuthorizationCode authzCode,
        HttpSession session,
        Model model) {

        AccessTokenResponse tokenResp = sendAccessTokenRequest(authzCode, session);
        if (tokenResp instanceof OIDCTokenResponse oidcTokenResp) {
            logger.info("Got ID token");

            JWT oidcToken = oidcTokenResp.getOIDCTokens().getIDToken();
            ClaimsSet claims = validateIdToken(oidcToken, session);

            session.setAttribute("oidc_token", oidcToken.getParsedString());

            String pidStr = claims.getStringClaim("pid");
            String acrStr = claims.getStringClaim("acr");
            if (pidStr != null) {
                model.addAttribute("pid", pidStr);
                logger.info("Got pid from claims");
            }
            if (acrStr != null) {
                model.addAttribute("acr", acrStr);
                logger.info("Got acr from claims");
            }
        }

        Tokens tokens = tokenResp.getTokens();
        // TODO: which tokens do we need to keep around..?
        session.setAttribute("access_token", tokens.getAccessToken().getValue());
        session.setAttribute("refresh_token", tokens.getRefreshToken().getValue());

        logger.info("Got access and refresh tokens");
    }

    private AccessTokenResponse sendAccessTokenRequest(
        AuthorizationCode authzCode,
        HttpSession session) {
        // given authorization code: creates and sends a token request; receives
        // an access token response on said request; and verifies and returns
        // this response.
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
                throw new LoginException("Token request error: " +
                                             errorResp.getErrorObject().toString());
            }

            return tokenResp.toSuccessResponse();
        }
        catch (
            IOException |
            ParseException e) {
            throw new LoginException("Error sending token request", e);
        }
    }

    private ClaimsSet validateIdToken(JWT idToken, HttpSession session) {
        // given an JWT ID token: validates the token using stored OIDC provider
        // metadata as well as the nonce from the original authz request; and
        // returns the claims given in the token.
        try {

            JWSAlgorithm jwsAlgorithm =
                (JWSAlgorithm) idToken.getHeader().getAlgorithm();
            URL jwkSetUrl = oidcProviderMetadata.getJWKSetURI().toURL();

            IDTokenValidator idTokenValidator =
                new IDTokenValidator(oidcProviderMetadata.getIssuer(),
                                     clientID,
                                     jwsAlgorithm,
                                     jwkSetUrl);

            Nonce expectedNonce =
                ProtocolVerifier.fromHttpSession(session).nonce();

            ClaimsSet claims = idTokenValidator.validate(idToken, expectedNonce);
            logger.info("ID token validation successful");
            return claims;
        }
        catch (Exception e) {
            throw new LoginException("ID validation failed", e);
        }
    }


    private AuthorizationCode getAuthzCodeFromAuthzResponse(
        URI authzResponseURI,
        HttpSession session) {
        // given authz response URI: parses URI, validates state, checks
        // success, and extracts authz code.
        try {
            AuthorizationResponse resp =
                AuthorizationResponse.parse(authzResponseURI);

            // authz code flow requires that state received in an authz response
            // should match state sent in authz request.
            // this should be stored in session from the authorization request.
            State lastState = ProtocolVerifier.fromHttpSession(session).state();
            if (lastState == null) {
                throw new LoginException("No stored state found");
            }
            if (!Objects.equals(resp.getState(), lastState)) {
                throw new LoginException("Bad state");
            }
            if (!resp.indicatesSuccess()) {
                throw new LoginException(resp.toErrorResponse().toString());
            }

            return resp.toSuccessResponse().getAuthorizationCode();
        }
        catch (ParseException e) {
            throw new LoginException("Authorization response parse error", e);
        }
    }
}
