package com.example.htmlFilePath.Services;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import lombok.AllArgsConstructor;
import lombok.Data;

import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import com.example.htmlFilePath.Mypath;
import com.example.htmlFilePath.Dto.RequestDTO;
import com.example.htmlFilePath.Entity.LogData;
import com.example.htmlFilePath.Entity.RecordEntity;
import com.example.htmlFilePath.Repositor.LogBookRepo;
import com.example.htmlFilePath.Repositor.RecordRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
//import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@Service
//@RequiredArgsConstructor
public class RecordService {

	private final RecordRepository repository;
	private final LogBookRepo logRepository;
	
	  public RecordService(RecordRepository repository,LogBookRepo logRepository) {
	        this.repository = repository;
	        this.logRepository=logRepository;
	    }
	  
//	  public List<String> processAndGeneratePdf(String payloadJson, MultipartFile[] files, MultipartFile htmlFile)
//		        throws IOException {
//
//		    Date startTime = new Date(); // record start of operation
//		    ObjectMapper mapper = new ObjectMapper();
//		    JsonNode payloadNode = mapper.readTree(payloadJson);
//
//		    // Map payload HTML IDs to JSON fields
//		    Map<String, JsonNode> htmlIdToJsonField = new LinkedHashMap<>();
//		    for (JsonNode obj : payloadNode) {
//		        obj.fields().forEachRemaining(entry -> htmlIdToJsonField.put(entry.getKey(), entry.getValue()));
//		    }
//
//		    // File name fields
//		    List<String> fileNameFields = new ArrayList<>();
//		    JsonNode fileNameNode = htmlIdToJsonField.get("file_name");
//		    if (fileNameNode != null) {
//		        if (fileNameNode.isTextual()) fileNameFields.addAll(Arrays.asList(fileNameNode.asText().split(",")));
//		        else if (fileNameNode.isArray()) fileNameNode.forEach(n -> fileNameFields.add(n.asText()));
//		    }
//
//		    // Password fields
//		    List<String> passwordFields = new ArrayList<>();
//		    JsonNode passwordNode = htmlIdToJsonField.get("password");
//		    if (passwordNode != null) {
//		        if (passwordNode.isTextual()) passwordFields.addAll(Arrays.asList(passwordNode.asText().split(",")));
//		        else if (passwordNode.isArray()) passwordNode.forEach(n -> passwordFields.add(n.asText()));
//		    }
//
//		    // Read HTML template
//		    String htmlContent = new String(htmlFile.getBytes(), StandardCharsets.UTF_8).replaceFirst("^\uFEFF", "");
//
//		    String outputDir = Mypath.getPath() + "DownloadHTMLANDPDF" + File.separator;
//		    Files.createDirectories(Path.of(outputDir));
//
//		    List<CompletableFuture<String>> futures = new ArrayList<>();
//		    RestTemplate restTemplate = new RestTemplate();
//
//		    for (MultipartFile file : files) {
//		        JsonNode dataJson = mapper.readTree(file.getInputStream());
//
//		        for (Iterator<String> users = dataJson.fieldNames(); users.hasNext(); ) {
//		            String userKey = users.next();
//		            JsonNode userNode = dataJson.get(userKey);
//
//		            // Execute PDF generation asynchronously
//		            futures.add(CompletableFuture.supplyAsync(() -> {
//		                try {
//		                    // Normalize fields
//		                    Map<String, JsonNode> normalizedFieldMap = new HashMap<>();
//		                    userNode.fieldNames().forEachRemaining(field -> normalizedFieldMap.put(field.toLowerCase(), userNode.get(field)));
//
//		                    // Replace payload IDs in HTML
//		                    Document doc = Jsoup.parse(htmlContent);
//		                    doc.outputSettings().syntax(Document.OutputSettings.Syntax.xml);
//		                    htmlIdToJsonField.forEach((id, nodeRef) -> {
//		                        String fieldRef = nodeRef.isTextual() ? nodeRef.asText() : null;
//		                        if (fieldRef == null) return;
//		                        String value = resolveFieldValueWithIndexes(normalizedFieldMap, fieldRef.trim());
//		                        Element elem = doc.getElementById(id);
//		                        if (elem != null && value != null) elem.text(value);
//		                    });
//
//		                    // Generate file name
//		                    String fileType;
//		                    if (!fileNameFields.isEmpty()) {
//		                        StringBuilder fnBuilder = new StringBuilder();
//		                        for (String fnExpr : fileNameFields) {
//		                            String fnValue = resolveFieldValueWithIndexes(normalizedFieldMap, fnExpr.trim());
//		                            if (fnValue != null && !fnValue.isEmpty()) fnBuilder.append(fnValue);
//		                            else fnBuilder.append("file_").append(UUID.randomUUID()).append("_");
//		                        }
//		                        fileType = fnBuilder.toString().replaceAll("_$", "");
//		                    } else fileType = "file_" + UUID.randomUUID();
//
//		                    String pdfFileName = outputDir + fileType + ".pdf";
//
//		                    // Remote PDF generation via REST API
//		                    HttpHeaders headers = new HttpHeaders();
//		                    headers.setContentType(MediaType.MULTIPART_FORM_DATA);
//		                    MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
//		                    body.add("file", new ByteArrayResource(doc.outerHtml().getBytes(StandardCharsets.UTF_8)) {
//		                        @Override
//		                        public String getFilename() {
//		                            return "template.html";
//		                        }
//		                    });
//		                    body.add("name", fileType);
//
//		                    HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
//		                    String apiUrl = "https://estateagents.club/api/api/v1/s3Upload/uploadHtml";
//
//		                    ResponseEntity<byte[]> response = restTemplate.exchange(apiUrl, HttpMethod.POST, requestEntity, byte[].class);
//		                    if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
//		                        Files.write(Path.of(pdfFileName), response.getBody());
//		                    } else {
//		                        throw new IOException("Failed to generate PDF via remote API for " + fileType);
//		                    }
//
//		                    // Apply password if needed
//		                    if (!passwordFields.isEmpty()) {
//		                        StringBuilder pwBuilder = new StringBuilder();
//		                        for (String pwExpr : passwordFields) {
//		                            String pwValue = resolveFieldValueWithIndexes(normalizedFieldMap, pwExpr.trim());
//		                            pwBuilder.append(pwValue != null ? pwValue : pwExpr.trim());
//		                        }
//		                        String userPassword = pwBuilder.toString();
//		                        try (PDDocument document = PDDocument.load(new File(pdfFileName))) {
//		                            String ownerPassword = UUID.randomUUID().toString();
//		                            AccessPermission permissions = new AccessPermission();
//		                            StandardProtectionPolicy policy = new StandardProtectionPolicy(ownerPassword, userPassword, permissions);
//		                            policy.setEncryptionKeyLength(128);
//		                            policy.setPermissions(permissions);
//		                            document.protect(policy);
//		                            document.save(pdfFileName);
//		                        }
//		                    }
//
//		                    // Save record in DB
//		                    RecordEntity record = RecordEntity.builder().fileName(fileType + ".pdf").build();
//		                    repository.save(record);
//
//		                    return pdfFileName;
//
//		                } catch (Exception e) {
//		                    e.printStackTrace();
//		                    return null;
//		                }
//		            }));
//		        }
//		    }
//
//		    // Wait for all async tasks to complete and collect results
//		    List<String> pdfPaths = futures.stream()
//		            .map(CompletableFuture::join)
//		            .filter(Objects::nonNull)
//		            .collect(Collectors.toList());
//
//		    return pdfPaths;
//		}

	  
	public List<String> processAndGeneratePdf(String payloadJson, MultipartFile[] files, MultipartFile htmlFile)
		        throws IOException {
		  Date startTime = new Date(); // record start of operation

		  
		  ObjectMapper mapper = new ObjectMapper();
		    JsonNode payloadNode = mapper.readTree(payloadJson);

		    // Map payload HTML IDs to JSON fields
		    Map<String, JsonNode> htmlIdToJsonField = new LinkedHashMap<>();
		    for (JsonNode obj : payloadNode) {
		        obj.fields().forEachRemaining(entry -> htmlIdToJsonField.put(entry.getKey(), entry.getValue()));
		    }

		    // File name fields
		    List<String> fileNameFields = new ArrayList<>();
		    JsonNode fileNameNode = htmlIdToJsonField.get("file_name");
		    if (fileNameNode != null) {
		        if (fileNameNode.isTextual()) fileNameFields.addAll(Arrays.asList(fileNameNode.asText().split(",")));
		        else if (fileNameNode.isArray()) fileNameNode.forEach(n -> fileNameFields.add(n.asText()));
		    }

		    // Password fields
		    List<String> passwordFields = new ArrayList<>();
		    JsonNode passwordNode = htmlIdToJsonField.get("password");
		    if (passwordNode != null) {
		        if (passwordNode.isTextual()) passwordFields.addAll(Arrays.asList(passwordNode.asText().split(",")));
		        else if (passwordNode.isArray()) passwordNode.forEach(n -> passwordFields.add(n.asText()));
		    }

		    // Read HTML template
		    String htmlContent = new String(htmlFile.getBytes(), StandardCharsets.UTF_8).replaceFirst("^\uFEFF", "");

		    String outputDir = Mypath.getPath() + "DownloadHTMLANDPDF" + File.separator;
		    Files.createDirectories(Path.of(outputDir));
		    List<String> pdfPaths = new ArrayList<>();
		    RestTemplate restTemplate = new RestTemplate();

		    for (MultipartFile file : files) {
		        JsonNode dataJson = mapper.readTree(file.getInputStream());

		        for (Iterator<String> users = dataJson.fieldNames(); users.hasNext(); ) {
		            String userKey = users.next();
		            JsonNode userNode = dataJson.get(userKey);

		            Map<String, JsonNode> normalizedFieldMap = new HashMap<>();
		            userNode.fieldNames().forEachRemaining(field -> normalizedFieldMap.put(field.toLowerCase(), userNode.get(field)));

		            // Replace payload IDs in HTML
		            Document doc = Jsoup.parse(htmlContent);
		            doc.outputSettings().syntax(Document.OutputSettings.Syntax.xml);
		            htmlIdToJsonField.forEach((id, nodeRef) -> {
		                String fieldRef = nodeRef.isTextual() ? nodeRef.asText() : null;
		                if (fieldRef == null) return;
		                String value = resolveFieldValueWithIndexes(normalizedFieldMap, fieldRef.trim());
		                Element elem = doc.getElementById(id);
		                if (elem != null && value != null) elem.text(value);
		            });

		            // Generate file name
		            String fileType;
		            if (!fileNameFields.isEmpty()) {
		                StringBuilder fnBuilder = new StringBuilder();
		                for (String fnExpr : fileNameFields) {
		                    String fnValue = resolveFieldValueWithIndexes(normalizedFieldMap, fnExpr.trim());
		                    if (fnValue != null && !fnValue.isEmpty()) fnBuilder.append(fnValue);
		                    else fnBuilder.append("file_").append(UUID.randomUUID()).append("_");
		                }
		                fileType = fnBuilder.toString().replaceAll("_$", "");
		            } else fileType = "file_" + UUID.randomUUID();

		            String pdfFileName = outputDir + fileType + ".pdf";

		            try {
		                HttpHeaders headers = new HttpHeaders();
		                headers.setContentType(MediaType.MULTIPART_FORM_DATA);

		                MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
		                body.add("file", new ByteArrayResource(doc.outerHtml().getBytes(StandardCharsets.UTF_8)) {
		                    @Override
		                    public String getFilename() { return "template.html"; }
		                });

		                body.add("name", fileType);
		                
		                

		                HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(body, headers);
		                String apiUrl = "https://estateagents.club/api/api/v1/s3Upload/uploadHtml";

		                ResponseEntity<byte[]> response = restTemplate.exchange(apiUrl, HttpMethod.POST, requestEntity, byte[].class);

		                if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
		                    Files.write(Path.of(pdfFileName), response.getBody());
		                } else {
		                    throw new IOException("Failed to generate PDF via remote API for " + fileType);
		                }

		            } catch (HttpStatusCodeException e) {
		                throw new IOException("Remote API PDF generation failed for " + fileType + ": " + e.getResponseBodyAsString(), e);
		            } catch (Exception e) {
		                throw new IOException("Remote API PDF generation failed for " + fileType + ": " + e.getMessage(), e);
		            }

		            // Apply password if needed
		            if (!passwordFields.isEmpty()) {
		                StringBuilder pwBuilder = new StringBuilder();
		                for (String pwExpr : passwordFields) {
		                    String pwValue = resolveFieldValueWithIndexes(normalizedFieldMap, pwExpr.trim());
		                    pwBuilder.append(pwValue != null ? pwValue : pwExpr.trim());
		                }
		                String userPassword = pwBuilder.toString();
		                try (PDDocument document = PDDocument.load(new File(pdfFileName))) {
		                    String ownerPassword = UUID.randomUUID().toString();
		                    AccessPermission permissions = new AccessPermission();
		                    StandardProtectionPolicy policy = new StandardProtectionPolicy(ownerPassword, userPassword, permissions);
		                    policy.setEncryptionKeyLength(128);
		                    policy.setPermissions(permissions);
		                    document.protect(policy);
		                    document.save(pdfFileName);
		                }
		            }

		            // Save record
		            RecordEntity record = RecordEntity.builder().fileName(fileType + ".pdf").build();
		            repository.save(record);
		            pdfPaths.add(pdfFileName);
		        }
		    }

		    return pdfPaths;

	}
	  
	private String resolveFieldValueWithIndexes(Map<String, JsonNode> normalizedFieldMap, String expression) {
        if (expression == null || expression.isEmpty()) {
            return null;
        }

        String field = expression;
        List<Integer> indexes = new ArrayList<>();

        if (expression.contains("[")) {
            int start = expression.indexOf("[");
            int end = expression.indexOf("]");
            field = expression.substring(0, start).trim().toLowerCase();
            String indexPart = expression.substring(start + 1, end);

            for (String idxStr : indexPart.split(",")) {
                try {
                    indexes.add(Integer.parseInt(idxStr.trim()));
                } catch (NumberFormatException ignore) {
                }
            }
        } else {
            field = field.trim().toLowerCase();
        }

        JsonNode node = normalizedFieldMap.get(field);
        if (node == null || !node.isTextual()) {
            return null;
        }

        String value = node.asText().trim().replaceAll("[-_/]", "");

        if (!indexes.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Integer idx : indexes) {
                if (idx >= 0 && idx < value.length()) {
                    sb.append(value.charAt(idx));
                }
            }
            return sb.toString();
        }

        return value;
    }
    
	  
    private void findAllJsonObjects(JsonNode node, List<ObjectNode> objects, List<String> requiredFields) {
        if (node.isObject()) {
            ObjectNode objNode = (ObjectNode) node;
            boolean hasAllRequiredFields = true;
            for (String field : requiredFields) {
                if (!objNode.has(field)) {
                    hasAllRequiredFields = false;
                    break;
                }
            }
            if (hasAllRequiredFields) {
                objects.add(objNode);
            }
            node.fields().forEachRemaining(entry -> findAllJsonObjects(entry.getValue(), objects, requiredFields));
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                findAllJsonObjects(item, objects, requiredFields);
            }
        }
        
        
    }


    public byte[] createZipFromFiles(List<String> filePaths) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zos = new ZipOutputStream(baos)) {
        for (String filePath : filePaths) {
            File file = new File(filePath);
            if (!file.exists()) continue;

            try (FileInputStream fis = new FileInputStream(file)) {
                ZipEntry zipEntry = new ZipEntry(file.getName());
                zos.putNextEntry(zipEntry);

                byte[] buffer = new byte[1024];
                int length;
                while ((length = fis.read(buffer)) >= 0) {
                    zos.write(buffer, 0, length);
                }
                zos.closeEntry();
            }
        }
    }
    return baos.toByteArray();
    }
    
    public List<String> processAndGenerateHtml(String payloadJson, MultipartFile[] files, MultipartFile htmlFile)
            throws Exception {
    	Date startTime = new Date(); // record start of operation
    	
        ObjectMapper mapper = new ObjectMapper();
        JsonNode payloadNode = mapper.readTree(payloadJson);
        try {
            payloadNode = mapper.readTree(payloadJson);
        } catch(Exception e) {
            logToDatabase(null, "FAILURE", "JSON parsing error: " + e.getMessage(), startTime);
            throw e;
        }

        Map<String, JsonNode> htmlIdToJsonField = new LinkedHashMap<>();
        for (JsonNode obj : payloadNode) {
            obj.fields().forEachRemaining(entry ->
                    htmlIdToJsonField.put(entry.getKey(), entry.getValue()));
        }

        List<String> fileNameFields = new ArrayList<>();
        JsonNode fileNameNode = htmlIdToJsonField.get("file_name");
        if (fileNameNode != null) {
            if (fileNameNode.isTextual()) {
                fileNameFields.add(fileNameNode.asText().trim());
            } else if (fileNameNode.isArray()) {
                fileNameNode.forEach(n -> fileNameFields.add(n.asText().trim()));
            }
        }

        List<String> passwordFields = new ArrayList<>();
        JsonNode passwordNode = htmlIdToJsonField.get("password");
        if (passwordNode != null) {
            if (passwordNode.isTextual()) {
                passwordFields.add(passwordNode.asText().trim());
            } else if (passwordNode.isArray()) {
                passwordNode.forEach(n -> passwordFields.add(n.asText().trim()));
            }
        }

        String htmlTemplate = new String(htmlFile.getBytes(), StandardCharsets.UTF_8).replaceFirst("^\uFEFF", "");

        String outputDir = "DownloadHTMLANDPDF" + File.separator;
        Files.createDirectories(Path.of(outputDir));
        List<String> htmlPaths = new ArrayList<>();

        for (MultipartFile file : files) {
            JsonNode dataJson = mapper.readTree(file.getInputStream());

            for (Iterator<String> keys = dataJson.fieldNames(); keys.hasNext(); ) {
                String key = keys.next();
                JsonNode userNode = dataJson.get(key);

                Map<String, JsonNode> normalizedFieldMap = new HashMap<>();
                userNode.fieldNames().forEachRemaining(f ->
                        normalizedFieldMap.put(f.toLowerCase(), userNode.get(f)));

                Document doc = Jsoup.parse(htmlTemplate);
                doc.outputSettings().syntax(Document.OutputSettings.Syntax.xml);

                htmlIdToJsonField.forEach((id, nodeRef) -> {
                    String fieldRef = nodeRef.isTextual() ? nodeRef.asText() : null;
                    if (fieldRef == null) return;
                    String value = resolveFieldValueWithIndexes(normalizedFieldMap, fieldRef.trim());
                    Element elem = doc.getElementById(id);
                    if (elem != null && value != null) elem.text(value);
                });

                String fileType;
                if (!fileNameFields.isEmpty()) {
                    StringBuilder fnBuilder = new StringBuilder();
                    for (String fnExpr : fileNameFields) {
                        String fnValue = resolveFieldValueWithIndexes(normalizedFieldMap, fnExpr.trim());
                        if (fnValue != null && !fnValue.isEmpty()) {
                            fnBuilder.append(fnValue);
                        } 
                    }
                    fileType = fnBuilder.toString().replaceAll("_$", "");
                } else {
                    fileType = "file_" + UUID.randomUUID();
                }

                String htmlFileName = outputDir + fileType + ".html";

                String userPassword = null;
                if (!passwordFields.isEmpty()) {
                    StringBuilder pwBuilder = new StringBuilder();
                    for (String pwExpr : passwordFields) {
                        String pwValue = resolveFieldValueWithIndexes(normalizedFieldMap, pwExpr.trim());
                        pwBuilder.append(pwValue != null ? pwValue : pwExpr.trim());
                    }
                    userPassword = pwBuilder.toString();
                }

                String finalHtml = doc.outerHtml();

                // If password exists → encrypt HTML content
                if (userPassword != null && !userPassword.isEmpty()) {
                    String bodyContent = extractBodyContent(finalHtml);
                    String encryptedBody = encryptAES(bodyContent, userPassword);

                    finalHtml = finalHtml.replaceAll("(?s)<body.*?>.*?</body>",
                            "<body>" +
                                    "<div id=\"encrypted-content\">" + encryptedBody + "</div>" +
                                    "<script>\n" +
                                    "async function decryptAES(encryptedBase64, password) {\n" +
                                    "    function base64ToArrayBuffer(base64) {\n" +
                                    "        var binary_string = atob(base64);\n" +
                                    "        var len = binary_string.length;\n" +
                                    "        var bytes = new Uint8Array(len);\n" +
                                    "        for (var i = 0; i < len; i++) {\n" +
                                    "            bytes[i] = binary_string.charCodeAt(i);\n" +
                                    "        }\n" +
                                    "        return bytes;\n" +
                                    "    }\n" +
                                    "    const encryptedBytes = base64ToArrayBuffer(encryptedBase64);\n" +
                                    "    const iv = encryptedBytes.slice(0, 12);\n" +
                                    "    const data = encryptedBytes.slice(12);\n" +
                                    "    const keyBytes = new Uint8Array(32);\n" +
                                    "    const passwordBytes = new TextEncoder().encode(password);\n" +
                                    "    keyBytes.set(passwordBytes.slice(0, Math.min(32, passwordBytes.length)));\n" +
                                    "    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, {name:'AES-GCM'}, false, ['decrypt']);\n" +
                                    "    const decrypted = await crypto.subtle.decrypt({name:'AES-GCM', iv: iv}, cryptoKey, data);\n" +
                                    "    return new TextDecoder().decode(decrypted);\n" +
                                    "}\n" +
                                    "(async()=>{\n" +
                                    "  try {\n" +
                                    "    var pass = prompt('Enter password to view content:');\n" +
                                    "    var decrypted = await decryptAES(document.getElementById('encrypted-content').textContent, pass);\n" +
                                    "    document.body.innerHTML = decrypted;\n" +
                                    "  } catch(e){\n" +
                                    "    document.body.innerHTML='<h2>Access Denied</h2>';\n" +
                                    "    console.error(e);\n" +
                                    "  }\n" +
                                    "})();\n" +
                                    "</script>" +
                                    "</body>"
                    );
                }

                Files.write(Path.of(htmlFileName), finalHtml.getBytes(StandardCharsets.UTF_8));
                htmlPaths.add(htmlFileName);
            }
        }

        return htmlPaths;

    }

    private String encryptAES(String plaintext, String password) throws Exception {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 32); // 256-bit
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[12]; // 12-byte IV for GCM
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    private String extractBodyContent(String html) {
        int start = html.indexOf("<body");
        start = html.indexOf(">", start) + 1;
        int end = html.indexOf("</body>", start);
        return html.substring(start, end);
    }
    
    public void logToDatabase(RequestDTO request, String result, String errorMessage, Date startTime)
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
        logRepository.save(info);
    }

    
    
    
    
    
    @Data
    @AllArgsConstructor
    private static class GeneratedPdf {
        private String fileName;
        private byte[] bytes;          
    }

 
 

     
}






