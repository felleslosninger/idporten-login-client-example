package no.idporten.example.login;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.net.URI;

@Controller
public class LoginController {

    // used to check state in authorization responses.
    private State lastState = new State(); // TODO: dummy.

    @GetMapping(path = "/login")
    public String login() {
        return "";
    }

    @GetMapping(path = "/callback")
    public String loginCallback(HttpServletRequest req, Model model) {
        URI callbackURI = URI.create(req.getRequestURL() + "?" + req.getQueryString());
        return handleCallbackURI(callbackURI, model);
    }

    private String handleCallbackURI(URI callbackURI, Model model) {
        AuthorizationResponse resp;
        try {
            resp = AuthorizationResponse.parse(callbackURI);
        }
        catch (ParseException e) {
            model.addAttribute("errmsg_attr", "Authorization response parse error");
            return "login_fail";
        }

        if (!resp.indicatesSuccess()) {
            model.addAttribute("errmsg_attr", resp.toErrorResponse());
            return "login_fail";
        }

        if (!resp.getState().equals(lastState)) {
            model.addAttribute("errmsg_attr", "Bad state");
            return "login_fail";
        }

        model.addAttribute("errmsg_attr", "Success");

        AuthorizationCode authzCode = resp.toSuccessResponse()
                                          .getAuthorizationCode();
        model.addAttribute("authz_code_attr", authzCode.getValue());

        return "login_success";
    }
}
