package com.crypto.hsm.controller;

import com.crypto.hsm.service.HsmService;
import iaik.pkcs.pkcs11.TokenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/hsm")
public class HsmController {

    private HsmService hsmService;

    @Autowired
    public HsmController(HsmService hsmService) {
        this.hsmService = hsmService;
    }

    @GetMapping
    public @ResponseBody
    List<String> getAllKeys() throws IOException, TokenException {
        return hsmService.getAllKeys();
    }

    @PostMapping(path = "/{name}")
    public void addKey(@PathVariable String name) throws IOException, TokenException {
        hsmService.addKey(name);
    }

    public void removeKey(@PathVariable String name) {
        hsmService.removeKey(name);
    }
}
