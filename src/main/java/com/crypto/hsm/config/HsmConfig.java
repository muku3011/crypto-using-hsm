package com.crypto.hsm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties
@ConfigurationProperties(prefix = "hsm")
public class HsmConfig {

    //@Value("${hsm.slotNumber}")
    private int slotNumber;

    //@Value("${hsm.tokenPin}")
    private int tokenPin;

    //@Value("${hsm.pkcs11ModuleName}")
    private String pkcs11ModuleName;

    public int getSlotNumber() {
        return slotNumber;
    }

    public void setSlotNumber(int slotNumber) {
        this.slotNumber = slotNumber;
    }

    public int getTokenPin() {
        return tokenPin;
    }

    public void setTokenPin(int tokenPin) {
        this.tokenPin = tokenPin;
    }

    public String getPkcs11ModuleName() {
        return pkcs11ModuleName;
    }

    public void setPkcs11ModuleName(String pkcs11ModuleName) {
        this.pkcs11ModuleName = pkcs11ModuleName;
    }
}
