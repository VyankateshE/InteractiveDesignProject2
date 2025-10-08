package com.example.htmlFilePath.Repositor;

import com.example.htmlFilePath.Entity.LogData;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Date;
import java.util.List;

public interface LogBookRepo extends JpaRepository<LogData,Integer> {
    List<LogData> findBySendRequestTimeBetween(Date startDate, Date endDate);

	List<LogData> findBySendRequestTimeAfter(Date start);

	List<LogData> findBySendRequestTimeBefore(Date end);
}
