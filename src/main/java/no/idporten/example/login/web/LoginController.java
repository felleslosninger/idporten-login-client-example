package no.idporten.example.login.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import no.idporten.example.login.service.LoginException;
import no.idporten.example.login.service.LoginService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;

import java.net.URI;

@Controller
public class LoginController {

    private final static Logger logger =
        LoggerFactory.getLogger(LoginController.class);

    private final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @GetMapping(path = "/login")
    public String loginRequest(HttpSession session) {
        // adds "protocol_verifier" to session.
        URI requestUri = loginService.getAuthnRequestUri(session);
        logger.info("LoginController.loginRequest: got requestUri");
        return "redirect:" + requestUri.toString();
    }

    @GetMapping(path = "/callback")
    public String loginCallback(
        HttpServletRequest request,
        Model model) {
        // loginService handles the login callback and updates session and model
        // accordingly. can throw LoginExceptions, which then redirects to
        // a failure page.
        loginService.handleLoginCallback(request, model);
        return "login_success";
    }

    @ExceptionHandler
    public String handleMyLoginException(LoginException e, Model model) {
        model.addAttribute("errmsg_attr", "Login error: " + e.getMessage());
        logger.error("Login failed with exception: ", e);
        return "login_fail";
    }
}
