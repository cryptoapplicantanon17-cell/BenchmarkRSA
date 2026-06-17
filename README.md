# BenchmarkRSA: Standard RSA Software Emulation Evaluation

This directory contains the experimental baseline source code and empirical logs used to evaluate standard software-emulated RSA decryption on resource-constrained smart cards, as described in Section 6.1 of the manuscript.

## File Deployment Instructions

To reproduce our experiments or test the baseline software implementation within your environment, you must manually deploy the provided source files into your local project structure:

1. **Locate Target Files:** Identify the specific source files provided in this directory (e.g., `ComplexCalcApplet.java`).
2. **Replace Project Files:** Copy and paste these files into the corresponding directories of your active repository setup, replacing the existing files that share the exact same names.
3. **⚠️ CRITICAL SAFETY WARNING:** Always create a secure backup of your original project files (`.java`, configuration scripts, etc.) before performing this replacement. This ensures you can safely restore your previous operational environment (such as the successful FLRSA applet configuration) after running the baseline tests (and don't create backup under folder JCMATHLIB otherwise compîlation errors appear).

---

## Empirical Evidence and Execution Logs

Due to the heavy modular abstraction layer and processing overhead of the JavaCard Virtual Machine (JCVM), running a standard bit-by-bit modular Square-and-Multiply loop natively on ultra-lightweight hardware pushes the platform's micro-architecture to its absolute physical limits. 

As detailed in the evaluation section of our paper, this computational bottleneck results in unstable runtime scenarios depending on the card's transient state:
* It systematically triggers a hardware resource exhaustion error (**Status Word `0x7010`**).
* Alternatively, in cases where the execution manages to complete without a hard crash, it incurs a prohibitive and non-viable processing delay.

### Included Verification Screenshot
We have included the formal execution trace screenshot directly within this directory:
* **Filename:** `ScreenShotRSAstandard.jpg` 

This screenshot provides definitive empirical proof of the software emulation overhead, demonstrating that the smart card required **more than 7 minutes** to complete a single standard 1024-bit RSA decryption sequence. 

This extreme delay validates our theoretical claims and empirically proves that standard software-emulated RSA is computationally non-viable for real-world deployment on resource-constrained micro-architectures, whereas our proposed **FLRSA** applet executes successfully and deterministically without runtime exceptions or prohibitive latency.
