package com.chatify.app.core.auth.service;


public interface EmailService {
    void sendMail(String to, String subject, String code);
}
