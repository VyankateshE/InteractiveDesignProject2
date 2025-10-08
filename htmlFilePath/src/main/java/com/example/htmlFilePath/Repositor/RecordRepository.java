package com.example.htmlFilePath.Repositor;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.htmlFilePath.Entity.RecordEntity;

public interface RecordRepository extends JpaRepository<RecordEntity, Long> {
}
