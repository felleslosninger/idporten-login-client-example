package no.idporten.example.login.web;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import no.idporten.example.login.config.LoginProperties;
import no.idporten.example.login.service.LoginException;
import no.idporten.example.login.service.LoginService;
import no.idporten.example.login.service.ProtocolVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

@Controller
public class LoginController {

    private final static Logger logger =
        LoggerFactory.getLogger(LoginController.class);

    private final LoginService loginService;
    private final LoginProperties.RpProperties.WebProperties webProperties;

    public LoginController(LoginService loginService,
                           LoginProperties.RpProperties.WebProperties webProperties) {
        this.loginService = loginService;
        this.webProperties = webProperties;
    }

    @GetMapping(path = "/")
    public String index() {
        return "index";
    }

    @GetMapping(path = "/login")
    public String loginRequest(HttpSession session) {

        ProtocolVerifier protocolVerifier = new ProtocolVerifier();

        String requestUriStr =
            loginService.makeAuthnRequest(protocolVerifier, webProperties.redirectUri())
                        .toURI()
                        .toString();

        session.setAttribute("protocol_verifier", protocolVerifier);

        return "redirect:" + requestUriStr;
    }

    @GetMapping(path = "/callback")
    public String loginCallback(
        HttpServletRequest request, HttpSession session, Model model
    ) {

        URI redirectUri = webProperties.redirectUri();
        URI authzResponseUri =
            UriComponentsBuilder.fromUri(redirectUri)
                                .query(request.getQueryString())
                                .build()
                                .toUri();

        ProtocolVerifier protocolVerifier =
            ProtocolVerifier.fromHttpSession(session);

        AuthorizationCode authzCode =
            loginService.getAuthzCodeFromAuthzResponse(
                authzResponseUri, protocolVerifier.state());

        TokenRequest tokenRequest =
            loginService.makeTokenRequest(
                authzCode, redirectUri, protocolVerifier.codeVerifier());

        AccessTokenResponse tokenResponse = sendTokenRequest(tokenRequest);

        processTokenResponse(tokenResponse, protocolVerifier, model);

        return "login_success";
    }

    private void processTokenResponse(
        AccessTokenResponse tokenResponse,
        ProtocolVerifier protocolVerifier,
        Model model
    ) {
        Tokens tokens = tokenResponse.getTokens();
        model.addAttribute("access_token", tokens.getAccessToken().getValue());
        model.addAttribute("refresh_token", tokens.getRefreshToken().getValue());

        ClaimsSet claims = loginService.validateTokenResponse(
            tokenResponse, protocolVerifier.nonce());

        if (claims == null) {
            throw new LoginException("Failed to get OIDC claims!");
        }

        String pidStr = claims.getStringClaim("pid");
        String acrStr = claims.getStringClaim("acr");

        if (pidStr == null || acrStr == null) {
            throw new LoginException("Failed to get PID and ACR from claims!");
        }

        model.addAttribute("pid", pidStr);
        model.addAttribute("acr", acrStr);
    }


    private AccessTokenResponse sendTokenRequest(TokenRequest tokenRequest) {
        try {
            TokenResponse tokenResponse =
                OIDCTokenResponse.parse(tokenRequest.toHTTPRequest().send());
            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResp = tokenResponse.toErrorResponse();
                throw new LoginException(
                    "Token request error: " + errorResp.getErrorObject().toString());
            }
            return tokenResponse.toSuccessResponse();
        }
        catch (
            IOException |
            ParseException e) {
            throw new LoginException("Error sending token request", e);
        }
    }

    @ExceptionHandler
    public String handleMyLoginException(LoginException e, Model model) {
        model.addAttribute("errmsg_attr", "Login error: " + e.getMessage());
        logger.error("Login failed with exception: ", e);
        return "login_fail";
    }
}
