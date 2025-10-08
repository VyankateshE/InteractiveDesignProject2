package com.example.htmlFilePath.Dto;

public class PdfResult{
    private byte[] pdfBytes;
    private String fileName;
    
    public PdfResult(byte[] pdfBytes, String fileName) {
        this.pdfBytes = pdfBytes;
        this.fileName = fileName;
    }
    
    public byte[] getPdfBytes() {
        return pdfBytes;
    }
    
    public String getFileName() {
        return fileName;
    }
}
