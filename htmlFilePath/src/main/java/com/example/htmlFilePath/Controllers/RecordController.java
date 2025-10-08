package com.example.htmlFilePath.Controllers;

import com.example.htmlFilePath.Dto.RequestDTO;
import com.example.htmlFilePath.Entity.LogData;
import com.example.htmlFilePath.Entity.RecordEntity;
import com.example.htmlFilePath.Repositor.LogBookRepo;
import com.example.htmlFilePath.Services.RecordService;

import org.springframework.http.ResponseEntity;
import org.springframework.util.ObjectUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/jsonApi")
@RequiredArgsConstructor
public class RecordController {

	private final RecordService service;
	private final LogBookRepo logBookRepo;
	
	@GetMapping("/getData")
	public String getData() {
		return "Hey the program is running";
	}
	@PostMapping("/uploadPdf")
	public ResponseEntity<byte[]> upload(
	        @RequestPart(value = "payload", required = false) String payload,
	        @RequestPart(value = "jsonFile", required = false) MultipartFile[] files,
	        @RequestPart(value = "htmlFile", required = false) MultipartFile htmlFile) {

	    Date startTime = new Date();
	    RequestDTO requestDTO = new RequestDTO(); // populate if possible
	    try {
	        // Validate input
	        if (payload == null || payload.isEmpty()) {
	            String errorMsg = "Payload is missing or empty";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest()
	                    .body(errorMsg.getBytes());
	        }

	        if (files == null || files.length == 0 || 
	        	    Arrays.stream(files).allMatch(f -> f == null || f.isEmpty())) {
	        	    String errorMsg = "JSON file not selected";
	        	    service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	        	    return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        	}

	        if (htmlFile == null || htmlFile.isEmpty()) {
	            String errorMsg = "HTML file not selected";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest()
	                    .body(errorMsg.getBytes());
	        }

	        // Process PDF generation
	        List<String> generatedPdfPaths = service.processAndGeneratePdf(payload, files, htmlFile);

	        if (generatedPdfPaths.isEmpty()) {
	            String errorMsg = "No PDF files generated from the given input";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        }

	        // Create ZIP only
	        byte[] zipBytes = service.createZipFromFiles(generatedPdfPaths);
	        String randomFileName = UUID.randomUUID().toString() + ".zip";

	        // send ZIP back to client
	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + randomFileName);
	        headers.setContentLength(zipBytes.length);

	        service.logToDatabase(requestDTO, "SUCCESS", "PDFs generated and zipped successfully", startTime);
	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);

	    } catch (Exception e) {
	        String errorMsg = "Exception occurred: " + e.getMessage();
	        try {
	        	service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	        } catch (SQLException sqlEx) {
	            // optional: log this to console, don't fail the request
	            sqlEx.printStackTrace();
	        }
	        return ResponseEntity.internalServerError().body(errorMsg.getBytes());
	    }
	}

	@PostMapping("/uploadHtml")
	public ResponseEntity<byte[]> uploadHtml(
	        @RequestPart(value = "payload", required = false) String payload,
	        @RequestPart(value = "jsonFile", required = false) MultipartFile[] files,
	        @RequestPart(value = "htmlFile", required = false) MultipartFile htmlFile) {

	    Date startTime = new Date();
	    RequestDTO requestDTO = new RequestDTO(); // populate as needed

	    try {
	        // Validate inputs
	        if (payload == null || payload.isEmpty()) {
	            String errorMsg = "Payload is missing or empty";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        }

	        if (files == null || files.length == 0 || 
	        	    Arrays.stream(files).allMatch(f -> f == null || f.isEmpty())) {
	        	    String errorMsg = "JSON file not selected";
	        	    service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	        	    return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        	}


	        if (htmlFile == null || htmlFile.isEmpty()) {
	            String errorMsg = "HTML file not selected";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        }

	        // Process HTML generation
	        List<String> generatedHtmlPaths = service.processAndGenerateHtml(payload, files, htmlFile);

	        if (generatedHtmlPaths.isEmpty()) {
	            String errorMsg = "No HTML files generated from the given input";
	            service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	            return ResponseEntity.badRequest().body(errorMsg.getBytes());
	        }

	        // Create ZIP of HTML files
	        byte[] zipBytes = service.createZipFromFiles(generatedHtmlPaths);
	        String randomFileName = UUID.randomUUID().toString() + ".zip";

	        HttpHeaders headers = new HttpHeaders();
	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + randomFileName);
	        headers.setContentLength(zipBytes.length);

	        service.logToDatabase(requestDTO, "SUCCESS", "HTMLs generated and zipped successfully", startTime);

	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);

	    } catch (Exception e) {
	        String errorMsg = "Exception occurred: " + e.getMessage();
	        
	        try {
		        service.logToDatabase(requestDTO, "FAILURE", errorMsg, startTime);
	        } catch (SQLException sqlEx) {
	            sqlEx.printStackTrace();
	        }
	        return ResponseEntity.internalServerError().body(errorMsg.getBytes());
	    }
	    
	}
	
	
	

//	@PostMapping("/uploadPdf")
//	public ResponseEntity<byte[]> upload(
//	        @RequestPart("payload") String payload,
//	        @RequestPart("jsonFile") MultipartFile[] files,
//	        @RequestPart("htmlFile") MultipartFile htmlFile) {
//	    try {
//	        List<String> generatedPdfPaths = service.processAndGeneratePdf(payload, files, htmlFile);
//
//	        if (generatedPdfPaths.isEmpty()) {
//	            return ResponseEntity.badRequest().build();
//	        }
//
//	        // create ZIP only
//	        byte[] zipBytes = service.createZipFromFiles(generatedPdfPaths);
//	        
//	        String randomFileName = UUID.randomUUID().toString() + ".zip";
//
//
//	        // send ZIP back to client
//	        HttpHeaders headers = new HttpHeaders();
//	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
//	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename="+randomFileName );
//	        headers.setContentLength(zipBytes.length);
//
//	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);
//
//	    } catch (Exception e) {
//	        return ResponseEntity.internalServerError()
//	                .body(("Error: " + e.getMessage()).getBytes());
//	    }
//	}
	
	
//	@PostMapping("/uploadHtml")
//	public ResponseEntity<byte[]> uploadHtml(
//	        @RequestPart("payload") String payload,
//	        @RequestPart("jsonFile") MultipartFile[] files,
//	        @RequestPart("htmlFile") MultipartFile htmlFile) {
//	    try {
//	        List<String> generatedHtmlPaths = service.processAndGenerateHtml(payload, files, htmlFile);
//
//	        if (generatedHtmlPaths.isEmpty()) {
//	            return ResponseEntity.badRequest().build();
//	        }
//
//	        // create ZIP of HTMLs
//	        byte[] zipBytes = service.createZipFromFiles(generatedHtmlPaths);
//
//	        String randomFileName = UUID.randomUUID().toString() + ".zip";
//
//	        HttpHeaders headers = new HttpHeaders();
//	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
//	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + randomFileName);
//	        headers.setContentLength(zipBytes.length);
//
//	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);
//
//	    } catch (Exception e) {
//	        return ResponseEntity.internalServerError()
//	                .body(("Error: " + e.getMessage()).getBytes());
//	    }
//	}

	   @GetMapping("/getErrorLogs")
	    public ResponseEntity<List<LogData>> getErrorLogs(
	            @RequestParam(value = "startDate", required = false) String startDate,
	            @RequestParam(value = "endDate", required = false) String endDate) {

	        HttpHeaders headers = new HttpHeaders();
	        headers.add("Access-Control-Allow-Methods", "GET");
	        headers.add("Access-Control-Allow-Headers", "Content-Type");

	        try {
	            // If both dates are empty, return all logs
	            if (ObjectUtils.isEmpty(startDate) && ObjectUtils.isEmpty(endDate)) {
	                List<LogData> allLogs = logBookRepo.findAll();
	                return ResponseEntity.ok().headers(headers).body(allLogs);
	            }

	            SimpleDateFormat inputFormat = new SimpleDateFormat("yyyy-MM-dd");
	            SimpleDateFormat outputFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	            Date start = null;
	            Date end = null;

	            if (!ObjectUtils.isEmpty(startDate)) {
	                Date parsedStart = inputFormat.parse(startDate);
	                String formattedStart = outputFormat.format(parsedStart);
	                start = outputFormat.parse(formattedStart);
	            }

	            if (!ObjectUtils.isEmpty(endDate)) {
	                Date parsedEnd = inputFormat.parse(endDate);
	                // Set time to 23:59:59 for inclusive search
	                String formattedEnd = new SimpleDateFormat("yyyy-MM-dd").format(parsedEnd) + " 23:59:59";
	                end = outputFormat.parse(formattedEnd);
	            }

	            List<LogData> logs;

	            if (start != null && end != null) {
	                logs = logBookRepo.findBySendRequestTimeBetween(start, end);
	            } else if (start != null) {
	                logs = logBookRepo.findBySendRequestTimeAfter(start);
	            } else {
	                logs = logBookRepo.findBySendRequestTimeBefore(end);
	            }

	            return ResponseEntity.ok().headers(headers).body(logs);

	        } catch (Exception e) {
	            e.printStackTrace();
	            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                    .headers(headers)
	                    .body(List.of());
	        }
	    }

	
//	@PostMapping("/upload")
//	public ResponseEntity<String> upload(
//	        @RequestPart("payload") String payload,
//	        @RequestPart("files") MultipartFile[] files,
//	        @RequestPart("htmlFile") MultipartFile htmlFile) {
//	    try {
//	        List<String> generatedPdfPaths = service.processAndGeneratePdf(payload, files, htmlFile);
//
//	        if (generatedPdfPaths.isEmpty()) {
//	            return ResponseEntity.badRequest().body("No PDF generated");
//	        }
//
//	        service.saveZipToDatabase(generatedPdfPaths);
//
//	        return ResponseEntity.ok("ZIP stored in database successfully!");
//
//	    } catch (Exception e) {
//	        return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
//	    }
//	}

//	@GetMapping("/downloads/{id}")
//	public ResponseEntity<byte[]> downloadZip(@PathVariable Long id) {
//	    try {
//	        byte[] zipBytes = service.getZipFromDatabase(id);
//
//	        if (zipBytes == null || zipBytes.length == 0) {
//	            return ResponseEntity.notFound().build();
//	        }
//
//	        HttpHeaders headers = new HttpHeaders();
//	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
//	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=pdfs.zip");
//	        headers.setContentLength(zipBytes.length);
//
//	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);
//
//	    } catch (Exception e) {
//	        return ResponseEntity.internalServerError()
//	                .body(("Error: " + e.getMessage()).getBytes());
//	    }
//	}
	
	
	
//	@PostMapping("/upload-and-download")
//	public ResponseEntity<byte[]> uploadAndDownloads(
//	        @RequestPart("payload") String payload,
//	        @RequestPart("files") MultipartFile[] files,
//	        @RequestPart("htmlFile") MultipartFile htmlFile) {
//	    try {
//	        List<String> generatedPdfPaths = service.processAndGeneratePdf(payload, files, htmlFile);
//
//	        if (generatedPdfPaths.isEmpty()) {
//	            return ResponseEntity.badRequest().build();
//	        }
//
//	        // create ZIP
//	        byte[] zipBytes = service.createZipFromFiles(generatedPdfPaths);
//
//	        // save ZIP in DB
//	        service.saveZipToDatabase(generatedPdfPaths);
//
//	        // send ZIP back to client
//	        HttpHeaders headers = new HttpHeaders();
//	        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
//	        headers.set(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=pdfs.zip");
//	        headers.setContentLength(zipBytes.length);
//
//	        return new ResponseEntity<>(zipBytes, headers, HttpStatus.OK);
//
//	    } catch (Exception e) {
//	        return ResponseEntity.internalServerError()
//	                .body(("Error: " + e.getMessage()).getBytes());
//	    }
//	}

	


//	@PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
//	public ResponseEntity<String> upload(@RequestPart("payload") String payload,
//			@RequestPart("files") MultipartFile[] files, @RequestPart("htmlFile") MultipartFile htmlFile) {
//
//		try {
//			String result = service.processAndGeneratePdf(payload, files, htmlFile);
//			return ResponseEntity.ok(result);
//		} catch (Exception e) {
//			return ResponseEntity.internalServerError().body("Error: " + e.getMessage());
//		}
//	}
//	
	
	
	
//	
	


//	@GetMapping("/download/{fileName}")
//	public ResponseEntity<Resource> downloadFile(@PathVariable String fileName) {
//		try {
//			Path filePath = Path.of(System.getProperty("user.home"), "/Downloads", fileName);
//			if (!Files.exists(filePath)) {
//				return ResponseEntity.notFound().build();
//			}
//
//			Resource resource = new UrlResource(filePath.toUri());
//
//			return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileName)
//					.contentType(MediaType.APPLICATION_PDF).body(resource);
//
//		} catch (Exception e) {
//			return ResponseEntity.internalServerError().build();
//		}
//	}
//	

//	@GetMapping("/get")
//	public ResponseEntity<?> getData() {
//
//		try {
//			List<RecordEntity> data = service.getData();
//			return new ResponseEntity<>(data, HttpStatus.OK);
//		} catch (Exception e) {
//			// TODO: handle exception
//			return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
//		}
//	}
	
	
	
	

	
	
	
}
