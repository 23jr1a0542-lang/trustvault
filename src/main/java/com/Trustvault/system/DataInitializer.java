
package com.Trustvault.system;

import com.Trustvault.system.repository.Useraccountrepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataInitializer {

    @Bean
    public CommandLineRunner createAdmin(
            Useraccountrepository repository,
            PasswordEncoder passwordEncoder) {

        return args -> {
            String adminUsername = "admin";

            if (repository.findByUsername(adminUsername).isEmpty()) {
                Useraccount admin = new Useraccount();
                admin.setUsername(adminUsername);
                admin.setPasswordHash(
                        passwordEncoder.encode("anvesh123"));
                admin.setRole("ADMIN");
                admin.setEnabled(true);

                repository.save(admin);

                System.out.println(
                        "Initial Admin account created. Change its password before deployment.");
            }
        };
    }
}
