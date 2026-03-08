package com.learnwithiftekhar.redissessionmanagement.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class MfaSetupResponse {
    private String secret;
    private String qrCodeUri;
    private String qrCodeImage;

}
