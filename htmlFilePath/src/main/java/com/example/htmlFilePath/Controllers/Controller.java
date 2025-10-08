package com.example.htmlFilePath.Controllers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.sql.SQLException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import com.example.htmlFilePath.Entity.LogData;
import com.example.htmlFilePath.Entity.User;
import com.example.htmlFilePath.Repositor.LogBookRepo;
import com.example.htmlFilePath.Repositor.Repository;
import com.example.htmlFilePath.Services.HtmlService;
import com.example.htmlFilePath.Services.JsonService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.htmlFilePath.FileToMultipartFile;
import com.example.htmlFilePath.FileUploadResponse;
import com.example.htmlFilePath.Mypath;
import com.example.htmlFilePath.Dto.EmployeeDTO;
import com.example.htmlFilePath.Dto.RequestDTO;
import com.example.htmlFilePath.Entity.HtmlRecord;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api")
public class Controller {

    @Autowired
    RestTemplate restTemplate;

    @Autowired
    Repository repository;

    @Autowired
    JsonService serviceLogic;

    @Autowired
    LogBookRepo logBookRepo;
    
    @Autowired
    private HtmlService htmlService;

//    @Autowired
//    JsonService jsonService;

    private static final Logger LOGGER = Logger.getLogger(Controller.class.getName());
    
       
    @GetMapping("/show-html/{id}")
    public String showHtmlById(@PathVariable("id") Integer id) {
        // Example: file path pattern (you can adjust this logic)
        String basePath = "C:\\Users\\Ariantech 01\\eclipse-workspace\\InteractiveDesignLatest-main\\htmlFilePath\\HtmlDownloads\\";
        String filePath = basePath + id + "_downloadable_html.html"; // Example: 1_editable_html.html, 2_editable_html.html, etc.

        try {
            // Read HTML file
            byte[] bytes = Files.readAllBytes(Paths.get(filePath));
            String htmlContent = new String(bytes);
            return htmlContent;

        } catch (IOException e) {
            e.printStackTrace();
            return "<h1>Error: File not found for ID: " + id + "</h1>";
        }
    }

    
//    @PostMapping("/uploadFile")
//    public ResponseEntity<?> uploadFile(
//            @RequestParam(value = "id", required = false) Integer id,
//            @RequestParam(value = "editableHtml", required = false) MultipartFile editableHtml,
//            @RequestParam(value = "downloadableHtml", required = false) MultipartFile downloadableHtml,
//            @RequestParam(value = "name", required = false) String name) {
//
//        Date startTime = new Date();
//
//        try {
//            // Validate name
//            if (ObjectUtils.isEmpty(name)) {
//                String errorMessage = "Name is required";
//                logUploadError(id, "FAILURE", errorMessage, startTime);
//                return ResponseEntity.badRequest().body(errorMessage);
//            }
//
//            User user;
//            boolean isUpdate = (id != null);
//
//            if (isUpdate) {
//                // Update scenario: fetch user by id
//                Optional<User> optionalUser = repository.findById(id);
//                if (!optionalUser.isPresent()) {
//                    String errorMessage = "User not found with id: " + id;
//                    logUploadError(id, "FAILURE", errorMessage, startTime);
//                    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorMessage);
//                }
//                user = optionalUser.get();
//            } else {
//                // Create new user
//                if (doesNameExist(name)) {
//                    String errorMessage = "Name already exists.";
//                    logUploadError(null, "FAILURE", errorMessage, startTime);
//                    return ResponseEntity.badRequest().body(errorMessage);
//                }
//                user = new User();
//                user.setName(name);
//                user = repository.save(user); // save to get ID for file naming
//            }
//
//            // Save editableHtml if provided
//            if (editableHtml != null && !editableHtml.isEmpty()) {
//                String editableFileName = generateFileName(user.getId(), "editable_html.html");
//                saveFile(editableFileName, editableHtml);
//                String folderPath = checkFolder("HtmlDownloads");
//                user.setEditableHtml(folderPath + File.separator + editableFileName);
//            }
//
//            // Save downloadableHtml if provided
//            if (downloadableHtml != null && !downloadableHtml.isEmpty()) {
//                String downloadableFileName = generateFileName(user.getId(), "downloadable_html.html");
//                saveFile(downloadableFileName, downloadableHtml);
//                String folderPath = checkFolder("HtmlDownloads");
//                user.setDownloadableHtml(folderPath + File.separator + downloadableFileName);
//            }
//
//            // Update name if provided
//            user.setName(name);
//            repository.save(user);
//
//            // Prepare response
//            FileUploadResponse response = new FileUploadResponse();
//            response.setFileName1(user.getEditableHtml());
//            response.setFileName2(user.getDownloadableHtml());
//            response.setMessage(isUpdate ? "Updated successfully" : "Uploaded successfully");
//
//            return ResponseEntity.ok(response);
//
//        } catch (IOException e) {
//            String errorMessage = "File processing error: " + e.getMessage();
//            e.printStackTrace();
//            logUploadError(id, "FAILURE", errorMessage, startTime);
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
//
//        } catch (Exception e) {
//            String errorMessage = "Unexpected error: " + e.getMessage();
//            e.printStackTrace();
//            logUploadError(id, "FAILURE", errorMessage, startTime);
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
//        }
//    }

    @PostMapping("/uploadFile/{id}")
    public ResponseEntity<?> uploadFile(
            @PathVariable("id") Integer id,
            @RequestParam(value = "editableHtml", required = false) MultipartFile editableHtml,
            @RequestParam(value = "downloadableHtml", required = false) MultipartFile downloadableHtml) {

        Date startTime = new Date();

        try {
            

            // Fetch user by ID
            Optional<User> optionalUser = repository.findById(id);
            if (!optionalUser.isPresent()) {
                String errorMessage = "User not found with id: " + id;
                logUploadError(id, "FAILURE", errorMessage, startTime);
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorMessage);
            }

            User user = optionalUser.get();

            // Save editableHtml if provided
            if (editableHtml != null && !editableHtml.isEmpty()) {
                String editableFileName = generateFileName(user.getId(), "editable_html.html");
                saveFile(editableFileName, editableHtml);
                String folderPath = checkFolder("HtmlDownloads");
                user.setEditableHtml(folderPath + File.separator + editableFileName);
            }

            // Save downloadableHtml if provided
            if (downloadableHtml != null && !downloadableHtml.isEmpty()) {
                String downloadableFileName = generateFileName(user.getId(), "downloadable_html.html");
                saveFile(downloadableFileName, downloadableHtml);
                String folderPath = checkFolder("HtmlDownloads");
                user.setDownloadableHtml(folderPath + File.separator + downloadableFileName);
            }

            // Update name
//            user.setName(name);
            repository.save(user);

            // Prepare response
            FileUploadResponse response = new FileUploadResponse();
            response.setFileName1(user.getEditableHtml());
            response.setFileName2(user.getDownloadableHtml());
            response.setMessage("Updated successfully");

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            String errorMessage = "File processing error: " + e.getMessage();
            e.printStackTrace();
            logUploadError(id, "FAILURE", errorMessage, startTime);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);

        } catch (Exception e) {
            String errorMessage = "Unexpected error: " + e.getMessage();
            e.printStackTrace();
            logUploadError(id, "FAILURE", errorMessage, startTime);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }
    }

    
    @PostMapping("/uploadFile")
    public ResponseEntity<?> uploadFile(
            @RequestParam(value = "editableHtml", required = false) MultipartFile editableHtml,
            @RequestParam(value = "downloadableHtml", required = false) MultipartFile downloadableHtml,
            @RequestParam(value = "name", required = false) String name) {

        Date startTime = new Date();

        try {
            // Check for missing name
            if (ObjectUtils.isEmpty(name)) {
                String errorMessage = "Name is required";
                logUploadError(null, "FAILURE", errorMessage, startTime);
                return ResponseEntity.badRequest().body(errorMessage);
            }

            // Check if files are missing or empty
            if (editableHtml == null || editableHtml.isEmpty()) {
                String errorMessage = "Editable HTML file is missing or empty";
                logUploadError(null, "FAILURE", errorMessage, startTime);
                return ResponseEntity.badRequest().body(errorMessage);
            }

            if (downloadableHtml == null || downloadableHtml.isEmpty()) {
                String errorMessage = "Downloadable HTML file is missing or empty";
                logUploadError(null, "FAILURE", errorMessage, startTime);
                return ResponseEntity.badRequest().body(errorMessage);
            }

            // Check if the name already exists
            if (doesNameExist(name)) {
                String errorMessage = "Name already exists.";
                logUploadError(null, "FAILURE", errorMessage, startTime);
                return ResponseEntity.badRequest().body(errorMessage);
            }

            // Create new user
            User user = new User();
            user.setName(name);
            user = repository.save(user);

            // Generate file names
            String editableFileName = generateFileName(user.getId(), "editable_html.html");
            String downloadableFileName = generateFileName(user.getId(), "downloadable_html.html");

            // Save files
            saveFile(editableFileName, editableHtml);
            saveFile(downloadableFileName, downloadableHtml);

            // Set paths
            String folderPath = checkFolder("HtmlDownloads");
            user.setEditableHtml(folderPath + File.separator + editableFileName);
            user.setDownloadableHtml(folderPath + File.separator + downloadableFileName);
            repository.save(user);

            FileUploadResponse response = new FileUploadResponse();
            response.setFileName1(user.getEditableHtml());
            response.setFileName2(user.getDownloadableHtml());
            response.setMessage("Uploaded successfully");

            return ResponseEntity.ok(response);

        } catch (IOException e) {
            String errorMessage = "File processing error: " + e.getMessage();
            e.printStackTrace();
            logUploadError(null, "FAILURE", errorMessage, startTime);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);

        } catch (Exception e) {
            String errorMessage = "Unexpected error: " + e.getMessage();
            e.printStackTrace();
            logUploadError(null, "FAILURE", errorMessage, startTime);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
        }
    }

    


    //W
//    @CrossOrigin(origins = "http://localhost:5500")
//    @PostMapping("/uploadFile")
//    public ResponseEntity<?> uploadFile(
//            @RequestParam("editableHtml") MultipartFile multipartFile1,
//            @RequestParam("downloadableHtml") MultipartFile multipartFile2,
//            @RequestParam("name") String name) throws IOException {
//
//        // Check if the name already exists
//        if (doesNameExist(name)) {
//            return ResponseEntity.badRequest().body("Name already exists.");
//        }
//
//        // Create a new user
//        User user = new User();
//        user.setName(name);
//
//        // Save the user to get the ID
//        user = repository.save(user);
//
//        // Generate file names using the user's ID
//        String editableHtmlFileName = generateFileName(user.getId(), "editable_html.html");
//        String downloadableHtmlFileName = generateFileName(user.getId(), "downloadable_html.html");
//
//        // Save the uploaded files
//        saveFile(editableHtmlFileName, multipartFile1);
//        saveFile(downloadableHtmlFileName, multipartFile2);
//
//        // Set file paths for the user
//        String folderPath =  checkFolder("HtmlDownloads");
//        String editableHtmlPath = folderPath + File.separator + editableHtmlFileName;
//        String downloadableHtmlPath = folderPath + File.separator + downloadableHtmlFileName;
//        user.setPathOfEditableHtml(editableHtmlPath);
//        user.setPathOfDownloadableHtml(downloadableHtmlPath);
//
//        // Update the user in the repository
//        repository.save(user);
//
//        // Prepare response
//        FileUploadResponse response = new FileUploadResponse();
//        response.setFileName1(editableHtmlPath);
//        response.setFileName2(downloadableHtmlPath);
//        response.setMessage("Uploaded successfully");
//
//        HttpHeaders headers = new HttpHeaders();
//        return new ResponseEntity<>(response, headers, HttpStatus.OK);
//    }

    private String generateFileName(Integer userId, String fileType) {
        return userId + "_" + fileType;
    }

    private void saveFile(String fileName, MultipartFile multipartFile) throws IOException {
        String folderPath = checkFolder("HtmlDownloads");
        Path filePath = Paths.get(folderPath).resolve(fileName);
        try (InputStream inputStream = multipartFile.getInputStream()) {
            Files.copy(inputStream, filePath, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private String checkFolder(String folder) throws IOException {
    	
    	 String currentDirectory = System.getProperty("user.dir");
         
         Path uploadPath = Paths.get(currentDirectory , folder);
         
        Path folderPath =  Files.createDirectories(uploadPath);
        
        return folderPath.toString();

    	
    }
    
    public boolean doesNameExist(String name) {
        Optional<User> item = repository.findByName(name);
        return item.isPresent();
    }

    /*
     * ______________________________________________________________________________________________________________________
     */
    
    //W
    @GetMapping("/getFile")
    public ResponseEntity<?> getById(@RequestBody RequestDTO requestDTO) throws SQLException {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date startDate = new Date();
		LOGGER.info("Started processing request at: " + dateFormat.format(startDate));

		try {
			validateRequest(requestDTO);
			User user = repository.findById(requestDTO.getId())
					.orElseThrow(() -> new NoSuchElementException("Id is invalid"));
			String filePath = user.getEditableHtml();

			// Modify the HTML content
			String modifiedHtmlContent = modifyHtml(filePath, requestDTO.getJsonData());

			String downloadType = requestDTO.getDownloadType().trim();
			String timestamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
			String folderPath = checkFolder("DownloadHTMLANDPDF");

			if (downloadType.equalsIgnoreCase("HTML")) {
				String newFilePath = folderPath + File.separator + requestDTO.getId() + "_editable_" + timestamp
						+ ".html";
				writeToFile(newFilePath, modifiedHtmlContent);

				File file = new File(newFilePath);
				InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

				HttpHeaders headers = new HttpHeaders();
				headers.setContentType(MediaType.TEXT_HTML);
				headers.setContentDisposition(ContentDisposition.attachment().filename(file.getName()).build());

//				logToDatabase(requestDTO, "Success", null, startDate);

				return new ResponseEntity<>(resource, headers, HttpStatus.OK);

			} else if (downloadType.equalsIgnoreCase("PDF")) {
				String htmlFilePath = folderPath + File.separator + requestDTO.getId() + "_editable_" + timestamp
						+ ".html";
				writeToFile(htmlFilePath, modifiedHtmlContent);

				File htmlFile = new File(htmlFilePath);
				MultipartFile multipartFile = convertFileToMultipartFile(htmlFile);

				ResponseEntity<?> response = getPdf(multipartFile, requestDTO.getId() + "_converted_" + timestamp);
//				logToDatabase(requestDTO, "Success", null, startDate);
				return response;

			} else {
				return handleFailure("Incorrect Download type", requestDTO, startDate);
			}

		} catch (NullPointerException | IllegalArgumentException | NoSuchElementException e) {
			return handleFailure(e.getMessage(), requestDTO, startDate);
		} catch (IOException e) {
			String errorMessage = "Error modifying the HTML file.";
			LOGGER.severe(errorMessage);
			e.printStackTrace();
			return handleFailure(errorMessage, requestDTO, startDate);
		}
	}

    public ResponseEntity<?> getPdf(MultipartFile multipartFile, String name) {
        try {
            // Define the API endpoint URL
            String apiUrl = "https://estateagents.club/api/api/v1/s3Upload/uploadHtml";
            String fileName = multipartFile.getOriginalFilename();

            // Create the request body with name and file parameters
            MultiValueMap<String, Object> requestBody = new LinkedMultiValueMap<>();
            requestBody.add("name", name); // Use the provided name parameter

            // Read the HTML file content and add it as a file parameter
            byte[] fileData = multipartFile.getBytes();
            HttpHeaders fileHeaders = createFileHeaders(Objects.requireNonNull(fileName));
            requestBody.add("file", new HttpEntity<>(fileData, fileHeaders));

            // Build the complete request entity
            RequestEntity<MultiValueMap<String, Object>> requestEntity = RequestEntity
                    .post(apiUrl)
                    .contentType(MediaType.MULTIPART_FORM_DATA)
                    .body(requestBody);

            // Make the HTTP POST request and receive a ResponseEntity<Resource>
            ResponseEntity<Resource> response = restTemplate.exchange(requestEntity, Resource.class);

            // Check if the response status is OK (HTTP status code 200)
            if (response.getStatusCode() == HttpStatus.OK) {
                Resource pdfResource = response.getBody();

                // Define the local file path where you want to save the PDF
                String path = Mypath.getPath() + "DownloadHTMLANDPDF" + File.separator;
                Path directoryPath = Paths.get(path);

                // Create the directories if they don't exist
                Files.createDirectories(directoryPath);
                System.out.println("Directories created or already exist at: " + directoryPath.toString());

            
                String localFilePath = path + fileName.replaceFirst("[.][^.]+$", "") + ".pdf";
                File localFile = new File(localFilePath);

                // Save the PDF content to a local file
                try (InputStream inputStream = pdfResource.getInputStream();
                        OutputStream outputStream = new FileOutputStream(localFile)) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }
                    System.out.println("PDF downloaded and saved to: " + localFilePath);
                }

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_PDF);
                headers.setContentDispositionFormData("attachment", "editable_html.pdf"); // Adjust filename if needed

                Path pdfPath = localFile.toPath();
                
                return ResponseEntity.ok()
                        .headers(headers)
                        .body(new ByteArrayResource(Files.readAllBytes(pdfPath)));
                      

            } else {
                return ResponseEntity.status(response.getStatusCode())
                        .body(new ByteArrayResource("API request failed".getBytes()));
            }
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ByteArrayResource("Internal server error".getBytes()));
        }
    }
    
    private void writeToFile(String filePath, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(content);
            LOGGER.info("File has been written to: " + filePath);
        }
    }

    
    

    private void validateRequest(RequestDTO requestDTO) {
        if (requestDTO.getId() == null || requestDTO.getJsonData() == null || requestDTO.getDownloadType() == null) {
            throw new NullPointerException("Id, JSON data, or download type is null.");
        }
    }

    private static String modifyHtml(String filePath, String jsonData) throws IOException {
        // Modify the HTML content here as needed
        // For example, you can search and replace text or add new elements

        StringBuilder htmlContent = new StringBuilder();
        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        String line;
        while ((line = reader.readLine()) != null) {
            htmlContent.append(line).append("\n");
        }
        reader.close();

        String toFind = "var jsonData1";
        // int startIndex = getSecondLastIndex(htmlContent, toFind);
        // int startIndex = htmlContent.lastIndexOf("var jsonData1");

        int startIndex = htmlContent.lastIndexOf(toFind);

        if (startIndex != -1) {
            int endIndex = htmlContent.indexOf("]; var custom_language", startIndex);
            if (endIndex != -1) {
                String start = htmlContent.substring(0, startIndex + 13);
                String end = htmlContent.substring(endIndex + 2); // +2 to skip the "};"
                String finalString = start + "=[" + jsonData + "]\n" + end;
                return finalString;
            }
        }
        // If "jsonData1" or the ending delimiter "};" is not found, return the original
        // HTML content

        // For demonstration, let's replace all occurrences of "old text" with "new
        // text"
        return htmlContent.toString();
    }


    private ResponseEntity<?> handleFailure(String message, RequestDTO requestDTO, Date startDate) throws SQLException {
        LOGGER.warning("Failure: " + message);
        logToDatabase(requestDTO, "Failure", message, startDate);
        System.out.println("Failure: " + message);
        return ResponseEntity.ok().body(message);
    }

    private HttpHeaders createFileHeaders(String filename) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("file", filename);
        return headers;
    }

    public static MultipartFile convertFileToMultipartFile(File file) throws IOException {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        MultipartFile multipartFile = new FileToMultipartFile(file.getName(), file.getName(),
                "application/octet-stream", fileContent);
        return multipartFile;
    }

   

    /*
     * ______________________________________________________________________________________________________________________
     */
    //W
    @PutMapping("/editTemplate/{id}")
    public ResponseEntity<String> editUser(@PathVariable Integer id, @RequestBody User user) {

        try {
            String result = serviceLogic.editUser(id, user);
            return new ResponseEntity<>(result, HttpStatus.OK);
        } catch (Exception e) {
            String response = "Template not added";
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    /*
     * ______________________________________________________________________________________________________________________
     */
    
    //W
    @DeleteMapping("/deleteTemplate/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable Integer id) {
        try {
            String result = serviceLogic.deleteUser(id);
            HttpHeaders headers = new HttpHeaders();
            // http://localhost:9998
//            headers.add("Access-Control-Allow-Origin", "*");
            headers.add("Access-Control-Allow-Methods", "DELETE");
            headers.add("Access-Control-Allow-Headers", "Content-Type");
            List<User> userList = repository.findAll();
            return new ResponseEntity<>(result, headers, HttpStatus.OK);
        } catch (Exception e) {
            String response = "Template deleted";
            return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
        }
    }

    /*
     * ______________________________________________________________________________________________________________________
     */
    
    
    //W
//    @GetMapping("/getTemplate/{id}")
//    public ResponseEntity<User> getUser(@PathVariable Integer id) {
//        User user = repository.findById(id).orElseThrow(() -> new NoSuchElementException());
//        return ResponseEntity.ok(user);
//    }

    @GetMapping("/getTemplate/{id}")
    public ResponseEntity<Map<String, Object>> getUser(@PathVariable Integer id) {
        // Try to fetch the user
        Optional<User> optionalUser = repository.findById(id);

        if (!optionalUser.isPresent()) {
            // Return 404 with error message if ID not found
            Map<String, Object> errorResponse = new LinkedHashMap<>();
            errorResponse.put("error", "Data not found with id: " + id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        }

        User user = optionalUser.get();

        // Prepare response with ordered keys
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", user.getId());
        response.put("name", user.getName());

        try {
            // Read HTML content from pathOfDownloadableHtml
            String htmlPath = user.getEditableHtml();
            byte[] bytes = Files.readAllBytes(Paths.get(htmlPath));
            String htmlContent = new String(bytes);

            response.put("EditableHtml", htmlContent);

        } catch (IOException e) {
            response.put("EditableHtml", "<h1>Error: Unable to load HTML file</h1>");
        }

        return ResponseEntity.ok(response);
    }


    
    /*
     * ______________________________________________________________________________________________________________________
     */
    //W
    @GetMapping("/getTemplate")
    public ResponseEntity<?> getUsers() {
        HttpHeaders headers = new HttpHeaders();
        // http://localhost:9998
//        headers.add("Access-Control-Allow-Origin", "http://127.0.0.1:5501");
        headers.add("Access-Control-Allow-Methods", "GET");
        headers.add("Access-Control-Allow-Headers", "Content-Type");
        List<User> userList = repository.findAll();
        return new ResponseEntity<>(userList, headers, HttpStatus.OK);
    }

    private void logToDatabase(RequestDTO request, String result, String errorMessage, Date startTime)
            throws SQLException {

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date endTime = new Date();

        LogData info = new LogData();
        info.setError_message(errorMessage);
        info.setResult(result);
        info.setSendRequestTime(startTime);
        info.setOutputResponseTime(endTime);
        info.setUser_id(request.getId());
        info.setTypeRequested(request.getDownloadType());
        info.setWhichAppRequestSentBy("Restful API");
        logBookRepo.save(info);
    }
    
    private void logUploadError(Integer userId, String result, String errorMessage, Date startTime) {
        try {
            LogData info = new LogData();
            info.setUser_id(userId);
            info.setResult(result);
            info.setError_message(errorMessage);
            info.setSendRequestTime(startTime);
            info.setOutputResponseTime(new Date());
//            info.setTypeRequested();
            info.setWhichAppRequestSentBy("Restful API");
            logBookRepo.save(info);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Failed to log upload error: " + e.getMessage());
        }
    }

    /*
     * ______________________________________________________________________________________________________________________
     */
    //W
    @GetMapping("/getDataFromDates")
    public ResponseEntity<List<LogData>> getDataFromEntry(@RequestParam("startDate") String startDate,
            @RequestParam("endDate") String endDate) throws ParseException {
        // Step 1: Parse the input date string to a Date object
        HttpHeaders headers = new HttpHeaders();
        // http://localhost:9998
//        headers.add("Access-Control-Allow-Origin", "*");
        headers.add("Access-Control-Allow-Methods", "POST");
        headers.add("Access-Control-Allow-Headers", "Content-Type");

        if (ObjectUtils.isEmpty(startDate) || ObjectUtils.isEmpty(endDate)) { // StringUtils.isEmpty(startDate)
            List<LogData> logData = logBookRepo.findAll();
            return ResponseEntity.ok().headers(headers).body(logData);
        }
        SimpleDateFormat inputDateFormat = new SimpleDateFormat("yyyy-MM-dd");
        Date startDate2 = inputDateFormat.parse(startDate);

        // Step 2: Format the Date object to the desired format
        SimpleDateFormat outputDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String outputDateStr = outputDateFormat.format(startDate2);

        // Step 3: Parse the formatted date string back to a Date object
        Date finalStartDate = outputDateFormat.parse(outputDateStr);

        Date endDate2 = inputDateFormat.parse(endDate);

        // Step 2: Format the Date object to the desired format
        String outputDateStr1 = outputDateFormat.format(endDate2);

        // Step 3: Parse the formatted date string back to a Date object
        Date finalEndDate = outputDateFormat.parse(outputDateStr1);

        List<LogData> data = logBookRepo.findBySendRequestTimeBetween(finalStartDate, finalEndDate);
        return ResponseEntity.ok().headers(headers).body(data);

    }
   

    @PostMapping(value = "/JsonDataSave", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<List<HtmlRecord>> uploadData(
            @RequestPart("data") String jsonArray,
            @RequestPart("file") MultipartFile file) {

        try {
            ObjectMapper mapper = new ObjectMapper();
            List<EmployeeDTO> dtoList = mapper.readValue(jsonArray, new TypeReference<List<EmployeeDTO>>() {});
            List<HtmlRecord> dataList = htmlService.uploadData(dtoList, file);
            return ResponseEntity.ok(dataList);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }
    
      
    @GetMapping("/getJsonData")
    public ResponseEntity<List<HtmlRecord>> getJson(){
    	List<HtmlRecord> data=htmlService.getJson();
    	return new ResponseEntity<>(data,HttpStatus.OK);
    }
    
    
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


}



//private String checkFolder(String folder) throws IOException {
//
//
//String currentDirectory = System.getProperty("user.dir");
//Path uploadPath = Paths.get(currentDirectory , folder);
//Files.createDirectories(uploadPath);
//Path folderPath = uploadPath.resolve(folder);
//
//try {
//   if (!Files.exists(folderPath)) {
//       Files.createDirectories(folderPath);
//       System.out.println("Folder created: " + folderPath);
//   } else {
//       System.out.println("Folder already exists: " + folderPath);
//   }
//} catch (IOException e) {
//   System.err.println("Error creating the folder: " + e.getMessage());
//}
//
//}

