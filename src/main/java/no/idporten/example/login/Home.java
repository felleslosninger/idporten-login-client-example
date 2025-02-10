package no.idporten.example.login;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class Home {

    @GetMapping(value = "/")
    public String index(Model model) {
        model.addAttribute("name", "Anders");
        return "index";

    }
}