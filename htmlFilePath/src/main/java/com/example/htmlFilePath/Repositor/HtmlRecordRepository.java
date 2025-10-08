package com.example.htmlFilePath.Repositor;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.example.htmlFilePath.Entity.HtmlRecord;

public interface HtmlRecordRepository extends JpaRepository<HtmlRecord, Long>{

}
