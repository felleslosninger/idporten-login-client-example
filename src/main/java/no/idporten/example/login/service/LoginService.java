package no.idporten.example.login.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.id.State;

import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import no.idporten.example.login.config.LoginProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

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
    private final LoginProperties.RpProperties.ServiceProperties serviceProperties;

    public LoginService(LoginProperties.RpProperties.ServiceProperties serviceProperties,
                        OIDCProviderMetadata oidcProviderMetadata) {
        this.oidcProviderMetadata = oidcProviderMetadata;
        this.serviceProperties = serviceProperties;
    }

    private final static Logger logger =
        LoggerFactory.getLogger(LoginService.class);

    public AuthenticationRequest makeAuthnRequest(
        ProtocolVerifier verifier,
        URI redirectUri
    ) {
        return
            new AuthenticationRequest.Builder(
                ResponseType.CODE,   // use authorization code flow.
                new Scope("openid"),
                serviceProperties.clientID(),
                redirectUri
            ).endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
             .state(verifier.state())
             .nonce(verifier.nonce())
             .codeChallenge(verifier.codeVerifier(), CodeChallengeMethod.S256)
             .build();
    }


    public ClaimsSet validateTokenResponse(
        AccessTokenResponse tokenResponse,
        Nonce expectedNonce
    ) {
        if (tokenResponse instanceof OIDCTokenResponse oidcTokenResp) {
            JWT oidcToken = oidcTokenResp.getOIDCTokens().getIDToken();
            return validateOidcToken(oidcToken, expectedNonce); // returns null on invalidation
        }
        return null;
    }

    public TokenRequest makeTokenRequest(
        AuthorizationCode authzCode,
        URI redirectUri,
        CodeVerifier codeVerifier
    ) {
        AuthorizationGrant codeGrant =
            new AuthorizationCodeGrant(authzCode, redirectUri, codeVerifier);

        ClientAuthentication clientAuthn =
            new ClientSecretBasic(serviceProperties.clientID(),
                                  serviceProperties.clientSecret());
        return
            new TokenRequest(oidcProviderMetadata.getTokenEndpointURI(),
                             clientAuthn,
                             codeGrant,
                             new Scope("openid"));
    }

    private ClaimsSet validateOidcToken(JWT oidcToken, Nonce expectedNonce) {
        try {
            JWSAlgorithm jwsAlgorithm =
                (JWSAlgorithm) oidcToken.getHeader().getAlgorithm();
            URL jwkSetUrl = oidcProviderMetadata.getJWKSetURI().toURL();

            IDTokenValidator idTokenValidator =
                new IDTokenValidator(oidcProviderMetadata.getIssuer(),
                                     serviceProperties.clientID(),
                                     jwsAlgorithm,
                                     jwkSetUrl);

            return idTokenValidator.validate(oidcToken, expectedNonce);
        } catch (
              Exception e) {
            // TODO: can alternatively throw here.
            return null;
        }
    }

    public AuthorizationCode getAuthzCodeFromAuthzResponse(
        URI authzResponseURI,
        State lastState
    ) {
        try {
            AuthorizationResponse resp =
                AuthorizationResponse.parse(authzResponseURI);

            // authz code flow requires that state received in an authz response
            // should match state sent in authz request.
            // this should be stored in session from the authorization request.
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
        } catch (
              ParseException e) {
            throw new LoginException("Authorization response parse error", e);
        }
    }

    /*
     * using PAR
     */
    public PushedAuthorizationRequest makePar(
        ProtocolVerifier protocolVerifier,
        URI redirectURI
    ) {
        AuthorizationRequest authzRequest =
            new AuthenticationRequest.Builder(
                ResponseType.CODE,
                new Scope("openid"),
                serviceProperties.clientID(),
                redirectURI
            )
             .nonce(protocolVerifier.nonce())
             .state(protocolVerifier.state())
             .codeChallenge(protocolVerifier.codeVerifier(), CodeChallengeMethod.S256)
             .build();

        ClientAuthentication clientAuthn =
            new ClientSecretBasic(serviceProperties.clientID(),
                                  serviceProperties.clientSecret());
        return new PushedAuthorizationRequest(
            oidcProviderMetadata.getPushedAuthorizationRequestEndpointURI(),
            clientAuthn,
            authzRequest
        );
    }

    public PushedAuthorizationSuccessResponse sendPar(
        PushedAuthorizationRequest par
    ) {
        try {
            PushedAuthorizationResponse parResponse =
                PushedAuthorizationResponse.parse(par.toHTTPRequest().send());
            if (!parResponse.indicatesSuccess()) {
                ErrorResponse errorResponse = parResponse.toErrorResponse();
                throw new LoginException("PAR error: " + errorResponse.getErrorObject().toString());
            }
            return parResponse.toSuccessResponse();
        }
        catch (IOException e) {
            throw new LoginException("Failed to send PAR", e);
        }
        catch (ParseException e) {
            throw new LoginException("Failed to parse PAR response", e);
        }
    }

    public AuthorizationRequest makeAuthzRequestWithParRequestUri(URI parRequestUri) {
        return
            new AuthorizationRequest.Builder(
                parRequestUri,
                serviceProperties.clientID()
            ).endpointURI(oidcProviderMetadata.getAuthorizationEndpointURI())
             .build();
    }
}
