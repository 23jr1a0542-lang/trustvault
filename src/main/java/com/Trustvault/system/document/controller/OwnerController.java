
package com.Trustvault.system.document.controller;

import java.security.Principal;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.security.web.csrf.CsrfToken;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class OwnerController {

    private final Useraccountrepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public OwnerController(
            Useraccountrepository userRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/admin/create-owner")
    @ResponseBody
    public String createOwnerPage(
            Principal principal, CsrfToken csrfToken) {

        Useraccount admin = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        if (!"ADMIN".equals(admin.getRole())) {
            throw new AccessDeniedException(
                    "Only Admin can create Owner accounts.");
        }

        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Create Owner - TrustVault</title>
                </head>
                <body>
                    <h2>Create Owner Account</h2>

                    <form method="post" action="/admin/create-owner">
                        <input type="hidden" name="_csrf" value="%s">

                        <label>Owner username:</label>
                        <input type="text" name="username"
                               maxlength="100" required>
                        <br><br>

                        <label>Password:</label>
                        <input type="password" name="password"
                               minlength="8" required>
                        <br><br>

                        <button type="submit">Create Owner</button>
                    </form>

                    <p><a href="/documents">Back to Documents</a></p>
                </body>
                </html>
                """.formatted(escapeHtml(csrfToken.getToken()));
    }

    @PostMapping("/admin/create-owner")
    @ResponseBody
    public String createOwner(
            @RequestParam String username,
            @RequestParam String password,
            Principal principal) {

        Useraccount admin = userRepository
                .findByUsername(principal.getName())
                .orElseThrow(() ->
                        new IllegalStateException("User not found"));

        if (!"ADMIN".equals(admin.getRole())) {
            throw new AccessDeniedException(
                    "Only Admin can create Owner accounts.");
        }

        username = username.trim();

        if (username.isBlank() || password.length() < 8) {
            return """
                    <h3>Username is required and password must contain
                    at least 8 characters.</h3>
                    <a href="/admin/create-owner">Try again</a>
                    """;
        }

        if (userRepository.findByUsername(username).isPresent()) {
            return """
                    <h3>Username already exists. Choose another username.</h3>
                    <a href="/admin/create-owner">Try again</a>
                    """;
        }

        Useraccount owner = new Useraccount();
        owner.setUsername(username);
        owner.setPasswordHash(passwordEncoder.encode(password));
        owner.setRole("OWNER");
        owner.setEnabled(true);

        userRepository.save(owner);

        return """
                <h2>Owner account created successfully!</h2>
                <p>The Owner can now log in using the new credentials.</p>
                <a href="/admin/create-owner">Create another Owner</a>
                <br><br>
                <a href="/documents">Back to Documents</a>
                """;
    }

    private String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
