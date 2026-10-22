package com.Trustvault.system;

import com.Trustvault.system.repository.Useraccountrepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Value("${admin.initial-password:${ADMIN_INITIAL_PASSWORD:}}")
    private String adminInitialPassword;

    @Value("${viewer.initial-password:${VIEWER_INITIAL_PASSWORD:}}")
    private String viewerInitialPassword;

    @Bean
    public CommandLineRunner createAdmin(
            Useraccountrepository repository,
            PasswordEncoder passwordEncoder) {

        return args -> {
            String adminUsername = "admin";

            if (repository.findByUsername(adminUsername).isPresent()) {
                System.out.println("Admin account already exists.");
            } else if (adminInitialPassword != null && !adminInitialPassword.isBlank()) {
                Useraccount admin = new Useraccount();
                admin.setUsername(adminUsername);
                admin.setPasswordHash(passwordEncoder.encode(adminInitialPassword));
                admin.setRole("ADMIN");
                admin.setEnabled(true);

                repository.save(admin);
                System.out.println("Initial Admin account created.");
            } else {
                System.out.println("Notice: Initial Admin account was not created. Set ADMIN_INITIAL_PASSWORD to create it.");
            }

            String viewerUsername = "viewer";

            if (repository.findByUsername(viewerUsername).isPresent()) {
                System.out.println("Viewer account already exists.");
            } else if (viewerInitialPassword != null && !viewerInitialPassword.isBlank()) {
                Useraccount viewer = new Useraccount();
                viewer.setUsername(viewerUsername);
                viewer.setPasswordHash(passwordEncoder.encode(viewerInitialPassword));
                viewer.setRole("VIEWER");
                viewer.setEnabled(true);

                repository.save(viewer);
                System.out.println("Initial Viewer account created.");
            } else {
                System.out.println("Notice: Initial Viewer account was not created. Set VIEWER_INITIAL_PASSWORD to create it.");
            }
        };
    }
}
