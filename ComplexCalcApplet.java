/**
 * Project: FLRSA-JavaCard
 * Implementation of Fast and Lightweight RSA Signature (1024-bit)
 * Target Hardware: NXP JCOP J3R180
 * * Credits:
  * - Optimized with Cubic Expansion formula (c^3 - c).
 * * Dependencies:
 * - JCMathLib (https://github.com/OpenCryptoProject/JCMathLib)
 * * License: MIT License
 * Copyright (c) 2026 Anon22
 * * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * * This project acknowledges the use of JCMathLib under MIT License.
 */



package opencrypto.jcmathlib;

import javacard.framework.*;
import opencrypto.jcmathlib.BigNat;
import opencrypto.jcmathlib.ResourceManager;


import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;



public class ComplexCalcApplet extends Applet {
    private RSAPrivateKey rsaKey;
    private Cipher rsaCipher;

   // Commands
    final static byte CLA_INIT = (byte) 0xB0;
    final static byte INS_INIT = (byte) 0x10;
    final static byte CLA_CALC = (byte) 0x80;
    final static byte INS_DO_CALC = (byte) 0x03;

   // --- Key size reduced to 128 bytes ( 1024 bits) ---
    private final static short KEY_SIZE_BYTES = 128; 
    private final static short DELTA_SIZE_BYTES = 128;
   
   // --- PERSISTENT OBJECTS (EEPROM) ---
    private BigNat n;
    private BigNat xcopy;
    private BigNat T; // Accumulator and final result (PERSISTENT)
    private BigNat d;
   
    // --- TRANSIENT OBJECTS (RAM) ---
    private BigNat x; // Input/output
   
    private ResourceManager rm;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ComplexCalcApplet().allocateAndRegister();
    }

    private ComplexCalcApplet() {}

    private void allocateAndRegister() {
        // KEEP 1024 FOR INSTALLATION (physical constraint)
        rm = new ResourceManager(JCSystem.MEMORY_TYPE_PERSISTENT, (short) 1024); 

        // PERSISTENT allocations (EEPROM)
        n      = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
       T      = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        d  = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        xcopy  = new BigNat(DELTA_SIZE_BYTES, (byte) 0, rm);
   
        // TRANSIENT allocation (RAM)
        x = new BigNat(KEY_SIZE_BYTES, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, rm);
   
      
    

        register();
    }
   

    public void process(APDU apdu) {
        if (selectingApplet()) return;

        byte[] buf = apdu.getBuffer();
        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        // Secure CLA handling
        if ((cla == CLA_INIT || cla == (byte)(CLA_INIT | 0x04)) && ins == INS_INIT) {
            initConstants(apdu);
            return;
        }

        if ((cla == CLA_CALC || cla == (byte)(CLA_CALC | 0x04)) && ins == INS_DO_CALC) {
            doCalc(apdu);
            return;
        }

        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    private void initConstants(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short off = ISO7816.OFFSET_CDATA;

        switch (buf[ISO7816.OFFSET_P1]) {
            case 0x01: n.fromByteArray(buf, off, KEY_SIZE_BYTES); break;
            case 0x02: d.fromByteArray(buf, off, KEY_SIZE_BYTES); break;
            default: ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }

private void doCalc(APDU apdu) {

        byte[] buf = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        // Loading input ciphertext/message in x (transient)
        x.fromByteArray(buf, ISO7816.OFFSET_CDATA, KEY_SIZE_BYTES);

        // --- COMPATIBLE JCMATHLIB MANUAL SQUARE-AND-MULTIPLY  ---
        
        // 1. Initialising the result T in 1
        T.zero();
        T.setValue((short) 1);

        // xcopy working data
        xcopy.copy(x); 

        // 2. Exporting 'd' 
        // directly in buffer APDU (buf) 
        short dLen = d.copyToByteArray(buf, ISO7816.OFFSET_CDATA);

        // Classic Square and Multiply loop
        for (short i = 0; i < dLen; i++) {
            byte currentByte = buf[(short)(ISO7816.OFFSET_CDATA + i)];

            for (short bit = 7; bit >= 0; bit--) {
                
                // SQUARE
                T.modMult(T, n);

                // MULTIPLY
                if (((currentByte >> bit) & 1) == 1) {
                    T.modMult(xcopy, n); // T = (T * base) mod n
                }
            }
        }

        // --- END OF STANDARD RSA COMPUTATION ---

        // Copy final result (T) to the beginning of the APDU buffer (offset 0) for transmission
        short L = T.length();
        apdu.setOutgoing();
        apdu.setOutgoingLength(L);
        T.copyToByteArray(buf, (short) 0);
        apdu.sendBytesLong(buf, (short) 0, L);
        
        rm.refreshAfterReset();
    }
}