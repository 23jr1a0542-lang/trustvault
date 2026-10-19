
package com.Trustvault.system.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.Trustvault.system.Useraccount;

public interface Useraccountrepository
        extends JpaRepository<Useraccount, Long> {

    Optional<Useraccount> findByUsername(String username);
}
