package com.example.htmlFilePath.Repositor;

import com.example.htmlFilePath.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface Repository extends JpaRepository<User,Integer> {
    Optional<User> findByName(String name);

	Optional<User> findById(Integer id);
}
