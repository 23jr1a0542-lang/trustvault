
package com.Trustvault.system;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import com.Trustvault.system.repository.Useraccountrepository;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class RegistrationController {

    private final Useraccountrepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public RegistrationController(
            Useraccountrepository userRepository,
            PasswordEncoder passwordEncoder) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String showRegistrationPage() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(
            @RequestParam(defaultValue = "") String username,
            @RequestParam(defaultValue = "") String email,
            @RequestParam(defaultValue = "") String password,
            @RequestParam(defaultValue = "") String confirmPassword,
            Model model,
            RedirectAttributes redirectAttributes) {

        username = username.trim();

        final String normalizedEmail =
                email.trim().toLowerCase(Locale.ROOT);

        // Preserve entered non-password fields when validation fails.
        model.addAttribute("username", username);
        model.addAttribute("email", normalizedEmail);

        // 1. Validate username
        if (username.isEmpty() || username.length() > 100) {
            model.addAttribute("error",
                    "Username must contain 1 to 100 characters.");
            return "register";
        }

        // 2. Validate email
        if (normalizedEmail.isEmpty()
                || normalizedEmail.length() > 254
                || !normalizedEmail.matches(
                "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {

            model.addAttribute("error",
                    "Please enter a valid email address.");
            return "register";
        }

        // 3. Validate password length
        if (password.length() < 8) {
            model.addAttribute("error",
                    "Password must contain at least 8 characters.");
            return "register";
        }

        // BCrypt supports a maximum of 72 UTF-8 bytes.
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            model.addAttribute("error",
                    "Password is too long. Please use a shorter password.");
            return "register";
        }

        // 4. Confirm password
        if (!password.equals(confirmPassword)) {
            model.addAttribute("error",
                    "Passwords do not match.");
            return "register";
        }

        // 5. Check duplicate username
        if (userRepository.findByUsername(username).isPresent()) {
            model.addAttribute("error",
                    "This username is already taken.");
            return "register";
        }

        // 6. Check duplicate email
        boolean emailExists = userRepository.findAll()
                .stream()
                .anyMatch(existing ->
                        existing.getEmail() != null
                        && normalizedEmail.equalsIgnoreCase(
                                existing.getEmail().trim()));

        if (emailExists) {
            model.addAttribute("error",
                    "This email address is already registered.");
            return "register";
        }

        // 7. Create new Owner account
        Useraccount user = new Useraccount();

        user.setUsername(username);
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole("OWNER");
        user.setEnabled(true);

        // 8. Save account safely
        try {
            userRepository.save(user);
        } catch (DataIntegrityViolationException exception) {
            model.addAttribute("error",
                    "Username or email is already registered. Please try another.");
            return "register";
        }

        // 9. Registration success
        redirectAttributes.addFlashAttribute(
                "success",
                "Registration successful! Please sign in."
        );

        return "redirect:/login";
    }
}
