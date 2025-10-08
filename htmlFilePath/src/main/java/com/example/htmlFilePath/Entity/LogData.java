package com.example.htmlFilePath.Entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.Date;

@Data
@Entity
public class LogData {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    int id;
    private Date sendRequestTime;
    private Integer user_id;
    private String result;
    private String error_message;
    private Date outputResponseTime;
    private String typeRequested;
    private String whichAppRequestSentBy;
}
