/*

FLRSAhost Project

Copyright (c) 2026 Anon22

Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all

copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE

AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.
*/


package opencrypto.jcmathlib;

import javax.smartcardio.*;
import java.util.Arrays;
import static opencrypto.jcmathlib.HostUtils.*;
import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import apdu4j.core.BIBO;

// Import GPCardKeys for the new structure
import pro.javacard.gp.GPCardKeys;
// Concrete implementation is here:
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPKeyInfo.GPKey;
import pro.javacard.gp.keys.PlaintextKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPSession.APDUMode;


import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import java.util.EnumSet;

import static apdu4j.core.HexUtils.hex2bin;
import static pro.javacard.gp.GPCardKeys.KeyPurpose;


class CardChannelToBIBOWrapper implements BIBO {
    private final CardChannel channel;

    public CardChannelToBIBOWrapper(CardChannel channel) {
        this.channel = channel;
    }

    @Override
    public byte[] transceive(byte[] command) {
        try {
            // Using fully qualified name for standard CommandAPDU
            return channel.transmit(new javax.smartcardio.CommandAPDU(command)).getBytes();
        } catch (CardException e) {
            
            throw new RuntimeException("Card communication failed", e);
        }
    }

    
    @Override
    public void close() {
       
    }
}
// Ensure the ISD, AID, and keys match specific card configuration.
public class InitHost {
 // Master Key Set 01 (version 0) keys
    private static final int KEY_VERSION = 0; 
    
    // Key ENC (4041...4F)
    private static final byte[] KEY_ENC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // Key MAC (4041...4F)
    private static final byte[] KEY_MAC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // Key DEK (4041...4F)
    private static final byte[] KEY_DEK_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // Applet AID to be selected
    public static final AID APPLET_AID = new AID(hex2bin("4A434D6174684C69625554"));
    // ISD AID (Target for GlobalPlatform authentication)
    public static final AID DEFAULT_ISD_AID = new AID(hex2bin("A000000151000000")); 

   
    // --- APDU Constants for Provisioning ---
    private static final byte CLA = (byte) 0xB0;
    private static final byte INS_INIT = (byte) 0x10;
    private static final short KEY_SIZE_BYTES = 128; // 128 bytes

    // --- Extracted and Provisioned Constants ---
  public static final byte[] N_BYTES = {
    // ----------------------------------------------------
    (byte) 0xC4, (byte) 0xA1, (byte) 0x26, (byte) 0x9C, (byte) 0xB6, (byte) 0x80, (byte) 0x64, (byte) 0xE1, // 00 - 07
    (byte) 0x7D, (byte) 0x8D, (byte) 0x99, (byte) 0x12, (byte) 0x35, (byte) 0x67, (byte) 0x66, (byte) 0x9B, // 08 - 15
    (byte) 0xA5, (byte) 0xD5, (byte) 0xDF, (byte) 0xA4, (byte) 0x75, (byte) 0x09, (byte) 0x38, (byte) 0x5F, // 16 - 23
    (byte) 0xA0, (byte) 0x19, (byte) 0x32, (byte) 0x27, (byte) 0xDB, (byte) 0x64, (byte) 0x5F, (byte) 0x15, // 24 - 31
    (byte) 0xCD, (byte) 0xE7, (byte) 0xBF, (byte) 0x36, (byte) 0xAB, (byte) 0x72, (byte) 0x08, (byte) 0x5B, // 32 - 39
    (byte) 0xF8, (byte) 0xA3, (byte) 0x19, (byte) 0xD6, (byte) 0x19, (byte) 0x28, (byte) 0xAD, (byte) 0xB1, // 40 - 47
    (byte) 0x70, (byte) 0x86, (byte) 0x22, (byte) 0xD8, (byte) 0x09, (byte) 0x9A, (byte) 0x0A, (byte) 0x7E, // 48 - 55
    (byte) 0xE4, (byte) 0xF0, (byte) 0x18, (byte) 0xD5, (byte) 0xF3, (byte) 0xB4, (byte) 0xF1, (byte) 0xC8, // 56 - 63
    (byte) 0x9C, (byte) 0xAC, (byte) 0xC2, (byte) 0xE7, (byte) 0x90, (byte) 0xA4, (byte) 0x5A, (byte) 0xFB, // 64 - 71
    (byte) 0x99, (byte) 0x60, (byte) 0xCF, (byte) 0xD0, (byte) 0xF5, (byte) 0x14, (byte) 0x46, (byte) 0x71, // 72 - 79
    (byte) 0x53, (byte) 0xC3, (byte) 0x9C, (byte) 0xF3, (byte) 0xB3, (byte) 0x6A, (byte) 0x92, (byte) 0x5C, // 80 - 87
    (byte) 0x5B, (byte) 0xD9, (byte) 0xDE, (byte) 0xC8, (byte) 0xF6, (byte) 0x3E, (byte) 0x02, (byte) 0x57, // 88 - 95
    (byte) 0x0F, (byte) 0xFC, (byte) 0x2D, (byte) 0x25, (byte) 0xED, (byte) 0x77, (byte) 0xC2, (byte) 0x06, // 96 - 103
    (byte) 0xF4, (byte) 0x3F, (byte) 0x8E, (byte) 0x86, (byte) 0xAC, (byte) 0x16, (byte) 0xF6, (byte) 0x1F, // 104 - 111
    (byte) 0xE1, (byte) 0x5A, (byte) 0x5D, (byte) 0x99, (byte) 0xFF, (byte) 0x4F, (byte) 0xB9, (byte) 0xC5, // 112 - 119
    (byte) 0xF3, (byte) 0xB4, (byte) 0x4D, (byte) 0xAF, (byte) 0x4C, (byte) 0xC2, (byte) 0xC2, (byte) 0x27  // 120 - 127
};
   public static final byte[] D_BYTES = {
    (byte) 0x21, (byte) 0xd1, (byte) 0x7a, (byte) 0x75, (byte) 0x77, (byte) 0xea, (byte) 0xc3, (byte) 0x61,
    (byte) 0x63, (byte) 0x46, (byte) 0x75, (byte) 0x98, (byte) 0x80, (byte) 0x47, (byte) 0x27, (byte) 0xc7,
    (byte) 0x70, (byte) 0xc3, (byte) 0xec, (byte) 0x89, (byte) 0xec, (byte) 0xcf, (byte) 0x50, (byte) 0x0c,
    (byte) 0xc1, (byte) 0xa1, (byte) 0x5f, (byte) 0x27, (byte) 0x71, (byte) 0xb1, (byte) 0xa7, (byte) 0x82,
    (byte) 0xec, (byte) 0xcb, (byte) 0x67, (byte) 0x46, (byte) 0x5a, (byte) 0xc6, (byte) 0x9a, (byte) 0x25,
    (byte) 0x78, (byte) 0x1b, (byte) 0xaa, (byte) 0xd9, (byte) 0xdc, (byte) 0x4d, (byte) 0x2c, (byte) 0x16,
    (byte) 0xe7, (byte) 0xfb, (byte) 0xae, (byte) 0x05, (byte) 0xcb, (byte) 0xc5, (byte) 0xfd, (byte) 0xf4,
    (byte) 0xd3, (byte) 0x1c, (byte) 0x10, (byte) 0x70, (byte) 0xd7, (byte) 0x2e, (byte) 0x8f, (byte) 0xb7,
    (byte) 0xb6, (byte) 0x5d, (byte) 0xed, (byte) 0x92, (byte) 0x01, (byte) 0x34, (byte) 0x89, (byte) 0x17,
    (byte) 0x8b, (byte) 0x24, (byte) 0x28, (byte) 0xa6, (byte) 0xe4, (byte) 0x64, (byte) 0x1a, (byte) 0xd2,
    (byte) 0x4a, (byte) 0xe1, (byte) 0x00, (byte) 0xdf, (byte) 0xf0, (byte) 0xd3, (byte) 0x71, (byte) 0x5f,
    (byte) 0xb5, (byte) 0x5c, (byte) 0x4e, (byte) 0xde, (byte) 0xd4, (byte) 0xc1, (byte) 0x9d, (byte) 0x1f,
    (byte) 0xce, (byte) 0x00, (byte) 0xfe, (byte) 0x31, (byte) 0x53, (byte) 0xbc, (byte) 0xef, (byte) 0x4f,
    (byte) 0x70, (byte) 0x7f, (byte) 0x18, (byte) 0x4e, (byte) 0xe7, (byte) 0x6a, (byte) 0x58, (byte) 0xe0,
    (byte) 0x54, (byte) 0x9c, (byte) 0x14, (byte) 0xe7, (byte) 0x99, (byte) 0x4f, (byte) 0x87, (byte) 0xa9,
    (byte) 0xea, (byte) 0x89, (byte) 0xf6, (byte) 0x4a, (byte) 0xc9, (byte) 0xbb, (byte) 0xd6, (byte) 0xe1
};
  

     public static void main(String[] args) {
        try {
            CardTerminal terminal = HostUtils.connectToCard();
            if (terminal == null) return;
            
            Card card = terminal.connect("*");
           
           
            APDUBIBO apduChannel = new APDUBIBO(new CardChannelToBIBOWrapper(card.getBasicChannel()));

         
            System.out.println(" Card connexion established for Initialisation.");
            System.out.println("\n--- Initializing 4 Constants in EEPROM (INS_INIT) ---");
            initializeBigNat(apduChannel, (byte) 0x01, N_BYTES, "n"); 
            initializeBigNat(apduChannel, (byte) 0x02, D_BYTES, "d");
            System.out.println(" INITIALIZATION COMPLETE. Constants are now persistent.");
            
            card.disconnect(false);
            System.out.println("\n Disconnecting from card.");
        } catch (Exception e) {
            System.err.println("\n Critical error during initialization: " + e.getMessage());
            e.printStackTrace(); // Displays the full stack trace for unhandled local errors
        }
    }

   private static void initializeBigNat( APDUBIBO apduchannel, byte p1, byte[] data, String name) throws CardException {
        
        if (data == null || data.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Le tableau de bytes pour " + name + " doit avoir exactement " + KEY_SIZE_BYTES + " bytes.");
        }
        
        PlaintextKeys keys = PlaintextKeys.fromKeys(KEY_ENC_BYTES, KEY_MAC_BYTES, KEY_DEK_BYTES);
        keys.setVersion(KEY_VERSION);
        
         System.out.println("GPSession ?");
        GPSession session = new GPSession(apduchannel, (DEFAULT_ISD_AID));
        System.out.println("GPSession ok");  
        
        // MAC and ENC security level (Required for sensitive data)
        EnumSet<APDUMode> securityLevel =  EnumSet.of(APDUMode.MAC, APDUMode.ENC);
        System.out.println("Mannual selection of the ISD " + DEFAULT_ISD_AID + "...");
        
        CommandAPDU isdSelectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, DEFAULT_ISD_AID.getBytes());
        try {
            byte[] rawResponse0 = apduchannel.transceive(isdSelectApdu.getBytes());
            ResponseAPDU isdSelectResponse = new ResponseAPDU(rawResponse0);
            if (isdSelectResponse.getSW() != 0x9000) {
                System.err.println("   - ISD selection failed (SW: " + Integer.toHexString(isdSelectResponse.getSW()) + ")");
                throw new CardException("ISD selection failed before secure channel open.");
            }
            System.out.println("   - ISD selected (SW: 9000)");
        } catch (RuntimeException e) { 
             System.err.println("   -ISD selection transmission error: " + e.getMessage());
             throw new CardException("ISD selection failed.", e);
        }
       
        try {
            System.out.println("Session ?");
            session.openSecureChannel(keys,
                    new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0), 
                    null,
                    securityLevel);
            System.out.println("Session ok");
        } catch (Exception e) { 
            e.printStackTrace();
            return; 
        }     
       
        // CRITICAL STEP: Selecting the Applet after opening the secure channel with the ISD
        System.out.println("Applet selected " + APPLET_AID + "...");
        apdu4j.core.ResponseAPDU selectResponse;
        
        
        
        CommandAPDU selectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID.getBytes());
      
    // Using session.transmit() (which is secure)
            byte[] rawResponse1 = apduchannel.transceive(selectApdu.getBytes());
            selectResponse = new ResponseAPDU(rawResponse1);


        if (selectResponse.getSW() != 0x9000) {
           
            System.err.println("   - Applet selection failed (SW: " + Integer.toHexString(selectResponse.getSW()) + ")");
            // 6E00 can sometimes indicate a missing Applet (although 6A82 is more common)
            System.err.println("Please verify that the Applet has been correctly installed (SW: 6E00 = Class not supported).");
            throw new CardException("Applet selection failed.");
        }
        System.out.println("   - Applet selected (SW: 9000)");




        // APDU : CLA=B0, INS=10, P1={ID}, P2=00, Lc=80, DATA
        CommandAPDU initApdu = new CommandAPDU(CLA, INS_INIT, p1, 0x00, data);
        
        
        // STEP 3: Secure Provisioning APDU Transmission
        apdu4j.core.ResponseAPDU response;
        
            // This APDU will be automatically secured (MAC/ENC) because the session is opened in MAC, ENC mode
            // GPSession.transmit() is declared to throw IOException, so this try/catch block is correct  
            byte[] rawResponse2 = apduchannel.transceive(initApdu.getBytes());
            response = new ResponseAPDU(rawResponse2);
            
      
        if (response.getSW() == 0x9000) {
            System.out.println("   - Constant " + name + " (P1=0x" + Integer.toHexString(p1) + ") initialized (SW: 9000)");
        } else {
            System.err.println("   - Failed to initialize " + name + " (SW: " + Integer.toHexString(response.getSW()) + ")");
            throw new CardException("Initialisation failed for constant " + name + ".");
        }
    }
    // --- Utility Function for Conversion ---
private static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    if (len % 2 != 0) {
        throw new IllegalArgumentException("Hex string must have an even length.");
    }
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}
}
