package no.idporten.example.login;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.id.State;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Controller
public class LoginController {

    final URI callbackURI = URI.create("http://localhost:7040/callback");

    @GetMapping(path = "/callback")
    public String loginCallback(HttpServletRequest req, HttpSession session, Model model) {

        URI authzResponseURI = UriComponentsBuilder.fromUri(callbackURI)
                                                   .query(req.getQueryString())
                                                   .build()
                                                   .toUri();
        return handleCallbackURI(authzResponseURI, session, model);
    }

    private String handleCallbackURI(URI authzResponseURI, HttpSession session, Model model) {
        AuthorizationResponse resp;
        try {
            resp = AuthorizationResponse.parse(authzResponseURI);
        }
        catch (ParseException e) {
            model.addAttribute("errmsg_attr", "Authorization response parse error");
            return "login_fail";
        }

        if (!resp.indicatesSuccess()) {
            model.addAttribute("errmsg_attr", resp.toErrorResponse());
            return "login_fail";
        }

        // authz code flow requires that state received in an authz response
        // should match state sent in authz request.
        // this should be stored in session from the authorization request.
        State lastState = (State) session.getAttribute("lastState");
        if (lastState == null) {
            model.addAttribute("errmsg_attr", "No stored state found");
            return "login_fail";
        }
        if (!resp.getState().equals(lastState)) {
            model.addAttribute("errmsg_attr", "Bad state");
            return "login_fail";
        }

        model.addAttribute("errmsg_attr", "Success");

        String authzCode = resp.toSuccessResponse()
                               .getAuthorizationCode()
                               .getValue();
        model.addAttribute("authz_code_attr", authzCode);

        return "login_success";
    }
}
