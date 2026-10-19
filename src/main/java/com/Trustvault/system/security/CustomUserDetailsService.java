
package com.Trustvault.system.security;

import com.Trustvault.system.Useraccount;
import com.Trustvault.system.repository.Useraccountrepository;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final Useraccountrepository useraccountrepository;

    public CustomUserDetailsService(
            Useraccountrepository useraccountrepository) {
        this.useraccountrepository = useraccountrepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        Useraccount account = useraccountrepository
                .findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found"));

        return User.withUsername(account.getUsername())
                .password(account.getPasswordHash())
                .roles(account.getRole())
                .disabled(!account.isEnabled())
                .build();
    }
}
