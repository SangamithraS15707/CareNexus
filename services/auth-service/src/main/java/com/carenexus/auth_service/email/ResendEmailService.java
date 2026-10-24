
package com.carenexus.auth_service.email;

import com.resend.Resend;
import com.resend.core.exception.ResendException;
import com.resend.services.emails.model.CreateEmailOptions;
import org.springframework.stereotype.Service;

@Service
public class ResendEmailService {

    private final Resend resend;

    public ResendEmailService() {
        String apiKey = System.getenv("RESEND_API_KEY");

        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException(
                "RESEND_API_KEY environment variable is missing"
            );
        }

        this.resend = new Resend(apiKey);
    }

    public void sendVerificationEmail(String to, String verificationUrl)
            throws ResendException {

        CreateEmailOptions email = CreateEmailOptions.builder()
            .from("onboarding@resend.dev")
            .to(to)
            .subject("Verify your CareNexus email")
            .html("""
                <h2>Welcome to CareNexus!</h2>
                <p>Please click the link below to verify your email:</p>
                <p><a href="%s">Verify my email</a></p>
                <p>If you did not create this account, ignore this email.</p>
                """.formatted(verificationUrl))
            .build();

        resend.emails().send(email);
    }
}
