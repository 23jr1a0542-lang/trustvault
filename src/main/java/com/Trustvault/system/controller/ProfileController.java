
package com.Trustvault.system.controller;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.repository.Useraccountrepository;

@Controller
public class ProfileController {

    private final Useraccountrepository userRepository;

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    public ProfileController(Useraccountrepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("/profile")
    public String showProfile(
            Authentication authentication,
            Model model) {

        Optional<Useraccount> optionalUser =
                userRepository.findByUsername(authentication.getName());

        if (optionalUser.isEmpty()) {
            return "redirect:/login";
        }

        Useraccount user = optionalUser.get();

        model.addAttribute("username", user.getUsername());
        model.addAttribute("role", user.getRole());
        model.addAttribute("email",
                user.getEmail() == null ? "" : user.getEmail());

        return "profile";
    }

    @PostMapping("/profile/update-email")
    public String updateEmail(
            @RequestParam(defaultValue = "") String email,
            Authentication authentication,
            RedirectAttributes redirectAttributes) {

        String normalizedEmail =
                email.trim().toLowerCase(Locale.ROOT);

        if (normalizedEmail.isEmpty()
                || normalizedEmail.length() > 254
                || !EMAIL_PATTERN.matcher(normalizedEmail).matches()) {

            redirectAttributes.addFlashAttribute(
                    "error",
                    "Please enter a valid email address.");

            return "redirect:/profile";
        }

        Optional<Useraccount> optionalUser =
                userRepository.findByUsername(authentication.getName());

        if (optionalUser.isEmpty()) {
            return "redirect:/login";
        }

        Useraccount user = optionalUser.get();

        Optional<Useraccount> existingUser =
                userRepository.findByEmail(normalizedEmail);

        if (existingUser.isPresent()
                && !existingUser.get().getId().equals(user.getId())) {

            redirectAttributes.addFlashAttribute(
                    "error",
                    "This email address is already registered.");

            return "redirect:/profile";
        }

        user.setEmail(normalizedEmail);
        userRepository.save(user);

        redirectAttributes.addFlashAttribute(
                "success",
                "Email address updated successfully.");

        return "redirect:/profile";
    }
}
