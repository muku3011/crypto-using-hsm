package com.crypto.hsm.service;

import com.crypto.hsm.util.HsmOperationUtil;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Service
public class HsmService {

    public static final int MAX_OBJECT_COUNT = 10;

    @Autowired
    private HsmSession hsmSession;

    private Module module;
    private Token token;

    @Autowired
    public HsmService(HsmSession hsmSession) {
        this.hsmSession = hsmSession;
    }

    public List<String> getAllKeys() throws IOException, TokenException {
        // Step 1: Initialize session
        Session session = initializeSession();
        try {
            // Step 2: Perform operation
            Object[] objectsFromSession = HsmOperationUtil.getAllObjectsFromSession(session, new SecretKey());
            List<String> keys = new ArrayList<>();
            for (Object aes : objectsFromSession) {
                keys.add(String.valueOf(((AESSecretKey) aes).getLabel()).concat(" -> ").concat(String.valueOf(((AESSecretKey) aes).getKeyType())));
            }
            return keys;
        } finally {
            // Step 3: finalize session
            finalizeSession(session);
        }
    }

    public void addKey(String name) throws IOException, TokenException {
        // Step 1: Initialize session
        Session session = initializeSession();
        try {
            // Step 2: Perform operation
            HsmOperationUtil.generateKey(session, PKCS11Constants.CKM_AES_KEY_GEN, name);
        } finally {
            // Step 3: finalize session
            finalizeSession(session);
        }
    }

    public void removeKey(String name) {
        //HsmOperationUtil.deleteAESKey();
    }

    // Helper methods

    public Session initializeSession() throws IOException, TokenException {
        // Step 1: Initialize module
        this.module = hsmSession.initializeModule();

        // Step 2: Initialize token
        this.token = hsmSession.initializeToken(module);

        // Step 3: Create a session and login
        return hsmSession.openSessionAndLogin(token);
    }

    public void finalizeSession(Session session) throws TokenException {
        // Step 5: Close session
        hsmSession.closeSession(session);

        // Step 6: Close token
        this.token.closeAllSessions();

        // Step 7: Finalize module
        hsmSession.finalizeModule(this.module);
    }
}
