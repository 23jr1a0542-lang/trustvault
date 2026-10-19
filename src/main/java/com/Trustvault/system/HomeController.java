
package com.Trustvault.system;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

    @GetMapping("/")
    @ResponseBody
    public String home() {
        return """
                <html>
                <head>
                    <title>TrustVault</title>
                </head>
                <body>
                    <h1>Welcome to TrustVault</h1>
                    <p>Secure Document Management System</p>
                    <p>You are logged in successfully.</p>
                </body>
                </html>
                """;
    }
}
