package com.example.htmlFilePath.Services;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.lang.model.element.Element;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.AccessPermission;
import org.apache.pdfbox.pdmodel.encryption.StandardProtectionPolicy;
import org.jsoup.Jsoup;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.example.htmlFilePath.Dto.EmployeeDTO;
import com.example.htmlFilePath.Entity.HtmlRecord;
import com.example.htmlFilePath.Repositor.HtmlRecordRepository;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;

@Service
public class HtmlService {


	
	@Value("${html.upload-dir:${user.home}/HtmlUploads}")
    private String uploadDir;
	
	@Autowired
	private HtmlRecordRepository repository;

//    public HtmlService(HtmlRecordRepository repository) {
//        this.repository = repository;
//    }
    
    

//    public HtmlRecord processHtml(EmployeeDTO employeeDTO, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        String originalContent = new String(file.getBytes());
//
//        // Replace the textarea content
//        String modifiedHtml = originalContent.replaceAll(
//            "<textarea[^>]*id=\"ic5w\"[^>]*>(.*?)</textarea>",
//            "<textarea id=\"ic5w\">" + employeeDTO.getEmpName() + "</textarea>"
//        );
//
//        String savedFileName = "modified_" + System.currentTimeMillis() + ".html";
//        File savedFile = new File(dir, savedFileName);
//
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(savedFile))) {
//            writer.write(modifiedHtml);
//        }
//
//        // Save metadata to DB
//        HtmlRecord record = HtmlRecord.builder()
//                .empName(employeeDTO.getEmpName())
//                .filePath(savedFile.getAbsolutePath())
//                .build();
//
//        return repository.save(record);
//    }
//
//    public HtmlRecord processHtml(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        // Parse HTML using Jsoup
//        String originalContent = new String(file.getBytes());
//        Document doc = Jsoup.parse(originalContent);
//        
//        for (EmployeeDTO dto : dtoList) {
//            Element element = doc.getElementById(dto.getId());
//            if (element != null) {
//                String tag = element.tagName();
//                if ("input".equalsIgnoreCase(tag)) {
//                    element.attr("value", dto.getEmpName());
//                } else if ("textarea".equalsIgnoreCase(tag)) {
//                    element.text(dto.getEmpName());
//                } else {
//                    element.text(dto.getEmpName());
//                }
//            }
//        }
//
//        String modifiedHtml = doc.outerHtml();
//        String savedFileName = "modified_" + System.currentTimeMillis() + ".html";
//        File savedFile = new File(dir, savedFileName);
//
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(savedFile))) {
//            writer.write(modifiedHtml);
//        }
//        String combinedNames = dtoList.stream().map(EmployeeDTO::getEmpName).collect(Collectors.joining(", "));
//
//        // Save metadata to DB
//        HtmlRecord records = HtmlRecord.builder()
//                .empName(combinedNames)
//                .filePath(savedFile.getAbsolutePath())
//                .build();
//
//        return repository.save(records);
//    }



//    public HtmlRecord uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        String originalContent = new String(file.getBytes());
//        Document doc = Jsoup.parse(originalContent);
//        
//        for (EmployeeDTO dto : dtoList) {
//            Element element = doc.getElementById(dto.getId());
//            if (element != null) {
//                String tag = element.tagName();
//                if ("input".equalsIgnoreCase(tag)) {
//                    element.attr("value", dto.getEmpName());
//                } else if ("textarea".equalsIgnoreCase(tag)) {
//                    element.text(dto.getEmpName());
//                } else {
//                    element.text(dto.getEmpName());
//                }
//            }
//        }
//
//        String modifiedHtml = doc.outerHtml();
//        String savedFileName = "modified_" + System.currentTimeMillis() + ".html";
//        File savedFile = new File(dir, savedFileName);
//
//        try (BufferedWriter writer = new BufferedWriter(new FileWriter(savedFile))) {
//            writer.write(modifiedHtml);
//        }
//
//        // Save metadata with all names combined (optional)
//        String combinedNames = dtoList.stream().map(EmployeeDTO::getEmpName).collect(Collectors.joining(", "));
//
//        HtmlRecord record = HtmlRecord.builder()
//                .empName(combinedNames)
//                .filePath(savedFile.getAbsolutePath())
//                .build();
//
//        return repository.save(record);
//    }
//
//    
    
    
    
    
   
    
    
//    public HtmlRecord uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        // 1. Parse and update HTML
//        String originalContent = new String(file.getBytes());
//        Document doc = Jsoup.parse(originalContent);  // Or use Parser.xmlParser() for strict
//        for (EmployeeDTO dto : dtoList) {
//            Element element = doc.getElementById(dto.getId());
//            if (element != null) {
//                String tag = element.tagName();
//                if ("input".equalsIgnoreCase(tag)) {
//                    element.attr("value", dto.getEmpName());
//                } else {
//                    element.text(dto.getEmpName());
//                }
//            }
//        }
//
//        Document.OutputSettings settings = new Document.OutputSettings();
//        settings.syntax(Document.OutputSettings.Syntax.xml);
//        settings.escapeMode(Entities.EscapeMode.xhtml);
//        settings.prettyPrint(true);
//        doc.outputSettings(settings);
//
//        String modifiedHtml = doc.html();
//
//
//
//        String timestamp = String.valueOf(System.currentTimeMillis());
//
//        // 2. Convert HTML to PDF
//        File pdfFile = new File(dir, "converted_" + timestamp + ".pdf");
//        try (OutputStream os = new FileOutputStream(pdfFile)) {
//            com.openhtmltopdf.pdfboxout.PdfRendererBuilder builder = new com.openhtmltopdf.pdfboxout.PdfRendererBuilder();
//            builder.useFastMode();
//            builder.withHtmlContent(modifiedHtml, null); // null base URI is okay for inline HTML
//            builder.toStream(os);
//            builder.run();
//        } catch (Exception e) {
//            e.printStackTrace();
//            throw new IOException("Failed to generate PDF", e);
//        }
//
//        // 3. Save metadata to DB
//        String combinedNames = dtoList.stream()
//                                      .map(EmployeeDTO::getEmpName)
//                                      .collect(Collectors.joining(", "));
//
//        HtmlRecord record = HtmlRecord.builder()
//                .empName(combinedNames)
//                .filePath(pdfFile.getAbsolutePath())  // Now stores PDF path
//                .build();
//
//        return repository.save(record);
//    }

    
    
    
//    public HtmlRecord uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        String originalContent = new String(file.getBytes());
//        org.jsoup.nodes.Document doc = Jsoup.parse(originalContent);
//
//        List<String> linesToPrint = new ArrayList<>();
//        for (EmployeeDTO dto : dtoList) {
//            Element element = doc.getElementById(dto.getId());
//            if (element != null) {
//                linesToPrint.add(dto.getEmpName());
//            }
//        }
//
//        // Build dynamic HTML
//        StringBuilder htmlBuilder = new StringBuilder();
//        htmlBuilder.append("<html><body style='font-family: Arial; font-size:14px;'>");
//        for (String line : linesToPrint) {
//            htmlBuilder.append("<p>").append(line).append("</p>");
//        }
//        htmlBuilder.append("</body></html>");
//
//        String htmlContent = htmlBuilder.toString();
//        String pdfFileName = "output_" + System.currentTimeMillis() + ".pdf";
//        File pdfFile = new File(dir, pdfFileName);
//
//        try (OutputStream os = new FileOutputStream(pdfFile)) {
//            PdfRendererBuilder builder = new PdfRendererBuilder();
//            builder.useFastMode();
//            builder.withHtmlContent(htmlContent, null);
//            builder.toStream(os);
//            builder.run();
//        }
//
//        String combinedNames = String.join(", ", linesToPrint);
//        HtmlRecord record = HtmlRecord.builder()
//                .empName(combinedNames)
//                .filePath(pdfFile.getAbsolutePath())
//                .build();
//
//        return repository.save(record);
//    }
//
//    
    
    
    //this was working without the pdf password protection
//    public List<HtmlRecord> uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//        File dir = new File(uploadDir);
//        if (!dir.exists()) dir.mkdirs();
//
//        String originalContent = new String(file.getBytes());
//        org.jsoup.nodes.Document doc = Jsoup.parse(originalContent);
//
//        List<HtmlRecord> savedRecords = new ArrayList<>();
//
//        for (EmployeeDTO dto : dtoList) {
//            Element element = doc.getElementById(dto.getId());
//            if (element != null) {
//                // Build individual HTML for this employee
//                String htmlContent = "<html><body style='font-family: Arial; font-size:14px;'>" +
//                                     "<p>" + dto.getEmpName() + "</p>" +
//                                     "</body></html>";
//
//                // Create a separate PDF file for this record
//                String sanitizedName = dto.getEmpName().replaceAll("[^a-zA-Z0-9]", "_");
//                String pdfFileName = "output_" + sanitizedName + "_" + System.currentTimeMillis() + ".pdf";
//                File pdfFile = new File(dir, pdfFileName);
//
//                try (OutputStream os = new FileOutputStream(pdfFile)) {
//                    PdfRendererBuilder builder = new PdfRendererBuilder();
//                    builder.useFastMode();
//                    builder.withHtmlContent(htmlContent, null);
//                    builder.toStream(os);
//                    builder.run();
//                }
//
//                // Save one HtmlRecord per PDF
//                HtmlRecord record = HtmlRecord.builder()
//                        .empName(dto.getEmpName())
//                        .filePath(pdfFile.getAbsolutePath())
//                        .build();
//
//                savedRecords.add(repository.save(record));
//            }
//        }
//
//        return savedRecords;
//    }

//
//
//public List<HtmlRecord> uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
//    File dir = new File(uploadDir);
//    if (!dir.exists()) dir.mkdirs();
//
//    String originalContent = new String(file.getBytes());
//    org.jsoup.nodes.Document doc = Jsoup.parse(originalContent);
//
//    List<HtmlRecord> savedRecords = new ArrayList<>();
//
//    for (EmployeeDTO dto : dtoList) {
//        Element element = doc.getElementById(dto.getId());
//        if (element != null) {
//            // Build individual HTML for this employee
//            String htmlContent = "<html><body style='font-family: Arial; font-size:14px;'>" +
//                                 "<p>" + dto.getEmpName() + "</p>" +
//                                 "</body></html>";
//
//            // Create unprotected PDF first
//            String sanitizedName = dto.getEmpName().replaceAll("[^a-zA-Z0-9]", "_");
//            String baseFileName = "output_" + sanitizedName + "_" + System.currentTimeMillis();
//            File unprotectedPdf = new File(dir, baseFileName + ".pdf");
//
//            try (OutputStream os = new FileOutputStream(unprotectedPdf)) {
//                PdfRendererBuilder builder = new PdfRendererBuilder();
//                builder.useFastMode();
//                builder.withHtmlContent(htmlContent, null);
//                builder.toStream(os);
//                builder.run();
//            }
//
//            // Now encrypt the PDF using the ID as the password
//            File encryptedPdf = new File(dir, baseFileName + "_protected.pdf");
//            try (PDDocument document = PDDocument.load(unprotectedPdf)) {
//                AccessPermission ap = new AccessPermission();
////                StandardProtectionPolicy spp = new StandardProtectionPolicy(dto.getId(), dto.getId(), ap);
//                StandardProtectionPolicy spp = new StandardProtectionPolicy(dto.getEmpName(), dto.getEmpName(), ap);
//
//                spp.setEncryptionKeyLength(128);
//                spp.setPermissions(ap);
//
//                document.protect(spp);
//                document.save(encryptedPdf);
//            }
//
//            // Delete unprotected PDF (optional)
//            unprotectedPdf.delete();
//
//            // Save metadata
//            HtmlRecord record = HtmlRecord.builder()
//                    .empName(dto.getEmpName())
//                    .filePath(encryptedPdf.getAbsolutePath())
//                    .build();
//
//            savedRecords.add(repository.save(record));
//        }
//    }
//
//    return savedRecords;
//}
//
    
    public List<HtmlRecord> uploadData(List<EmployeeDTO> dtoList, MultipartFile file) throws IOException {
        File dir = new File(uploadDir);
        if (!dir.exists()) dir.mkdirs();

        String originalContent = new String(file.getBytes());
        org.jsoup.nodes.Document doc = Jsoup.parse(originalContent);

        List<HtmlRecord> savedRecords = new ArrayList<>();
        Set<String> processedEmpNames = new HashSet<>(); // <--- add this set
    	Set<String> processedIds = new HashSet<>();

        for (EmployeeDTO dto : dtoList) {
        	
        	// Skip duplicate Id
        	if (processedIds.contains(dto.getId())) continue;
        	processedIds.add(dto.getId());

            // Skip duplicate empName
//            if (processedEmpNames.contains(dto.getEmpName())) continue;
//            processedEmpNames.add(dto.getEmpName());

            Element element = (Element) doc.getElementById(dto.getId());
            if (element != null) {
                // Build HTML content
                String htmlContent = "<html><body style='font-family: Arial; font-size:14px;'>" +
                                     "<p>" + dto.getEmpName() + "</p>" +
                                     "</body></html>";

                // Generate PDF
                String sanitizedName = dto.getEmpName().replaceAll("[^a-zA-Z0-9]", "_");
                String baseFileName = "output_" + sanitizedName + "_" + System.currentTimeMillis();
                File unprotectedPdf = new File(dir, baseFileName + ".pdf");

                try (OutputStream os = new FileOutputStream(unprotectedPdf)) {
                    PdfRendererBuilder builder = new PdfRendererBuilder();
                    builder.useFastMode();
                    builder.withHtmlContent(htmlContent, null);
                    builder.toStream(os);
                    builder.run();
                }

                // Password protect PDF (using empName or any other logic)
                File encryptedPdf = new File(dir, baseFileName + "_protected.pdf");
                try (PDDocument document = PDDocument.load(unprotectedPdf)) {
                    AccessPermission ap = new AccessPermission();
                    StandardProtectionPolicy spp = new StandardProtectionPolicy(dto.getEmpName(), dto.getEmpName(), ap);
                    spp.setEncryptionKeyLength(128);
                    spp.setPermissions(ap);

                    document.protect(spp);
                    document.save(encryptedPdf);
                }

                // Delete unprotected PDF
                unprotectedPdf.delete();

                // Save DB record
                HtmlRecord record = HtmlRecord.builder()
                        .empName(dto.getEmpName())
                        .filePath(encryptedPdf.getAbsolutePath())
                        .build();

                savedRecords.add(repository.save(record));
            }
        }

        return savedRecords;
    }



	public List<HtmlRecord> getJson() {
		// TODO Auto-generated method stub
		return repository.findAll();
	}


}




//data=  [
//{"id":"i36c","empName":"Venky!"},
//{"id":"i36c","empName":"Venky!"},
//{"id":"i36c","empName":"Venky!"},

//]
//
//