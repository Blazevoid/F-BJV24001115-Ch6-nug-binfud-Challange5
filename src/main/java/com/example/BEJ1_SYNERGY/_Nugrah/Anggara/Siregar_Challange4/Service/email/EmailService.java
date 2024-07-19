package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.email;

import java.util.concurrent.CompletableFuture;

public interface EmailService {
    CompletableFuture<Void> sendEmail(String to, String subject, String text);
    String getOtpLoginEmailTemplate(String name,String accountNumber, String otp) ;
}
