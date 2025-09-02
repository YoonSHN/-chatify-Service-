package com.chatify.app.core.auth.service.impl;

import com.chatify.app.core.auth.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;

    @Override
    public void sendMail(String to, String subject, String text) {
        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        try {
            // MimeMessageHelper를 사용하면 간단하게 메일을 구성할 수 있습니다.
            // true는 멀티파트 메세지를 사용하겠다는 의미입니다. (파일 첨부 등)
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false, "UTF-8");

            helper.setTo(to);
            helper.setSubject(subject);
            helper.setText(text, false); // true는 HTML 형식으로 보내겠다는 의미입니다.

            javaMailSender.send(mimeMessage);

        } catch (MessagingException e) {
            // MessagingException은 이메일 발송 관련 예외입니다.
            // 실무에서는 로그를 남기거나, 예외 처리를 더 정교하게 해야 합니다.
            throw new RuntimeException("메일 발송에 실패했습니다.", e);
        }
    }
}
