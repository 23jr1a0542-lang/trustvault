
package com.Trustvault.system;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CurrentUserController {

    @GetMapping("/api/me")
    public Map<String, Object> getCurrentUser(Authentication authentication) {

        Map<String, Object> user = new HashMap<>();

        user.put("username", authentication.getName());

        var roles = authentication.getAuthorities()
                .stream()
                .map(authority -> authority.getAuthority())
                .collect(Collectors.toList());

        user.put("roles", roles);
        user.put("isAdmin", roles.contains("ROLE_ADMIN"));
        user.put("isOwner", roles.contains("ROLE_OWNER"));
        user.put("isViewer", roles.contains("ROLE_VIEWER"));

        return user;
    }
}
