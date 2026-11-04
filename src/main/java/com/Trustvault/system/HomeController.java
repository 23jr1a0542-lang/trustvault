
package com.Trustvault.system;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "forward:/index.html";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
