package com.crypto.hsm.service;

import com.crypto.hsm.config.HsmConfig;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.io.IOException;

@Service
public class HsmSession {

    private HsmConfig hsmConfig;

    @Autowired
    public HsmSession(HsmConfig hsmConfig) {
        this.hsmConfig = hsmConfig;
    }

    /**
     * Initialize module in the beginning by providing crypto library
     *
     * @throws IOException,    if there are errors finding crypto library
     * @throws TokenException, if there are errors while loading crypto library
     */
    public Module initializeModule() throws IOException, TokenException {
        // Initialize module
        Module module = Module.getInstance(hsmConfig.getPkcs11ModuleName());
        module.initialize(null);
        return module;
    }

    /**
     * When all crypto operations are performed, advised to finalize module.
     * Initialize module before extracting token.
     *
     * @throws TokenException, if there are any errors while finalizing module
     */
    public void finalizeModule(Module module) throws TokenException {
        if (module != null) {
            module.finalize(null);
        }
    }

    /**
     * Initialize or extract to token from slot, slot which is extracted from the module
     *
     * @throws TokenException, if there are errors while getting token from module
     */
    public Token initializeToken(Module module) throws TokenException {
        // Select slot and get token
        Slot slot = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT)[hsmConfig.getSlotNumber()];
        return slot.getToken();
    }

    /**
     * Open session from a token object and login into a session with token pin
     *
     * @return Session, session object to perform crypto operations
     * @throws TokenException, if there is any exception while opening or logging in into session
     */
    public Session openSessionAndLogin(Token token) throws TokenException {
        Session session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
        session.login(Session.UserType.USER, String.valueOf(hsmConfig.getTokenPin()).toCharArray());
        return session;
    }

    /**
     * Close opened session after performing crypto operations
     *
     * @param session, session object to be closed
     * @throws TokenException, if there is any exception while closing session
     */
    public void closeSession(Session session) throws TokenException {
        try {
            session.findObjectsFinal();
        } catch (TokenException e) {
            if (e instanceof PKCS11Exception && ((PKCS11Exception) e).getErrorCode() == 145) {
                session.closeSession();
                return;
            }
        }
        session.closeSession();
    }
}