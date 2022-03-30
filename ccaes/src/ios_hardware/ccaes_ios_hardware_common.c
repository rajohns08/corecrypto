/* Copyright (c) (2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/cc_config.h>

#if CCAES_MUX

#include <unistd.h>

#include <IOKit/IOKitLib.h>
#include <Kernel/IOKit/crypto/IOAESTypes.h>
#include <sys/ioctl.h>
#include <os/once_private.h>

#include "cc_debug.h"
#include "ccaes_ios_hardware.h"
#include <corecrypto/ccmode_internal.h>

/*
 ccaes_hardware_threshold is being set to a constant of 1 so that hardware FIPS tests
 can directly call into this with a low threshold of bytes.  This shouldn't matter since
 iOS clients use this interface through the ccaes_ios_mux interface; which will use
 the 16K value.
 */

#include <errno.h>

static int ccaes_device = -1;
size_t ccaes_hardware_block_quantum = ((256*4096) / CCAES_BLOCK_SIZE);
size_t ccaes_hardware_block_threshold = 1;
uint32_t ccaes_hardware_support = 0;
uint64_t ccaes_hardware_perf = 0;

#define AES_HW_INIT_MAGIC 0xA5A5C5C5

#define WORKAROUND_32163348

static bool isHWfaster(void)
{
    cc_assert(ccaes_hardware_perf>0);
    // Only use HW if fast enough
    if (ccaes_hardware_perf>=(14*1024*1024)) {
        return true;
    }
    return false;
}

static void init(void *arg)
{
    int *status = arg;
    struct IOAESAcceleratorInfo aesInfo;

    ccaes_device = open("/dev/aes_0", O_RDWR | O_NONBLOCK, 0); // Non guarded
    // Guarded open does not seem to support O_NONBLOCK
    if(ccaes_device < 0) {
        cc_printf("Failed open file descriptor to AES HW %d",errno);
        *status = CCMODE_INTERNAL_ERROR;
    }
    if(ioctl(ccaes_device, IOAES_GET_INFO, &aesInfo) != -1) {
        ccaes_hardware_block_quantum =  aesInfo.maxBytesPerCall / CCAES_BLOCK_SIZE;
        // For right now we're going to set the minimum to 1 block - allowing this
        // to function like any other aes-cbc modeObj. It can be tested while in this
        // configuration with the normal tests, although the round trips through the
        // kernel boundary are painfully slow for small block counts.
        ccaes_hardware_block_threshold = 1; // aesInfo.minBytesPerCall / CCAES_BLOCK_SIZE;
        ccaes_hardware_support = aesInfo.options;
        ccaes_hardware_perf = aesInfo.encryptSpeed; // byte per seconds
#ifdef WORKAROUND_32163348
        if (!isHWfaster()) {
            ccaes_hardware_support &= ~(uint32_t)kIOAESAcceleratorSupportCTR;
        }
#endif
    }
}

// Check HW support
static int ccaes_ios_hardware_support(int operation) {
    static os_once_t initp;
    int status = 0;
    os_once(&initp, &status, init);

    if (status) {
        return status;
    }
    else if (((operation&CCAES_HW_MODE) == CCAES_HW_CBC)
        && !(ccaes_hardware_support & kIOAESAcceleratorSupportCBC)) {
        return CCMODE_NOT_SUPPORTED;
    }
    else if (((operation&CCAES_HW_MODE) == CCAES_HW_CTR)
        && !(ccaes_hardware_support & kIOAESAcceleratorSupportCTR)) {
        return CCMODE_NOT_SUPPORTED;
    }
    return 0;
}

// Return true if the operation is supported by HW and if HW has some advantage
// over SW.
// Can be used as kill switch for corecrypto client without
// blocking function/performance testing within corecrypto
int ccaes_ios_hardware_enabled(int operation) {
    // First try to connect to the driver for operation support
    if (ccaes_ios_hardware_support(operation)==0) {
        // Then check if there is a performance benefit
        return isHWfaster()?1:0;
    }
    return 0;
}


int
ccaes_ios_hardware_common_init(int operation CC_UNUSED, ccaes_hardware_aes_ctx_t ctx, size_t rawkey_len, const void *rawkey)
{
    if (rawkey_len !=CCAES_KEY_SIZE_128
        && rawkey_len != CCAES_KEY_SIZE_192
        && rawkey_len != CCAES_KEY_SIZE_256) {
        return CCMODE_INVALID_INPUT;
    }

    cc_memcpy(&ctx->keyBytes[0], rawkey, rawkey_len);
    ctx->keyLength = rawkey_len;

    int status = ccaes_ios_hardware_support(operation);
    if (status) return status;

    ctx->init_complete=AES_HW_INIT_MAGIC;
    return 0;
}

size_t ccaes_ios_hardware_crypt(int operation, ccaes_hardware_aes_ctx_const_t ctx, uint8_t *iv,
                            const void *in, void *out, size_t nblocks)
{
    uint8_t *pt8, *ct8;
	struct IOAESAcceleratorRequest aesRequest;
	
    if(nblocks < ccaes_hardware_block_threshold) return 0; // 0 block processed
	size_t remaining = nblocks;
	size_t chunk;

    if ((ctx->init_complete!=AES_HW_INIT_MAGIC) || (ccaes_device < 0)) return 0;

    // Prepare data request
    if((operation&CCAES_HW_ENCRYPT)) {
        aesRequest.operation = (operation&CCAES_HW_CTR)?IOAESOperationEncryptCTR:IOAESOperationEncrypt;
        pt8 = __DECONST(uint8_t *,in);
        ct8 = (uint8_t *) out;
    } else {
        aesRequest.operation = (operation&CCAES_HW_CTR)?IOAESOperationDecryptCTR:IOAESOperationDecrypt;
        pt8 = (uint8_t *) out;
        ct8 = __DECONST(uint8_t *,in);
    }

    // Setup key and IV
	cc_memcpy(aesRequest.iv.ivBytes, iv, CCAES_BLOCK_SIZE);
	aesRequest.keyData.key.keyLength = (UInt32) (ctx->keyLength << 3); //Hardware needs it in bits.
	cc_memcpy(aesRequest.keyData.key.keyBytes, ctx->keyBytes, ctx->keyLength);
	aesRequest.keyData.keyHandle = kIOAESAcceleratorKeyHandleExplicit;

    // Last chunks of data, as large as supported by the HW
	while (remaining) {
        chunk = CC_MIN(ccaes_hardware_block_quantum,remaining);

        // In corecrypto, the counter width is 64bit for AES CTR
        uint64_t counter;
        bool isOverflow = false;
        CC_LOAD64_BE(counter,aesRequest.iv.ivBytes+8); // Get the lowest part of the counter
        if ((UINT64_MAX-counter <= chunk-1) && (operation&CCAES_HW_CTR)) {
            chunk = (size_t)(UINT64_MAX-counter)+1;
            isOverflow = true;
        }

        // Data
        aesRequest.plainText = (mach_vm_address_t)pt8;
        aesRequest.cipherText = (mach_vm_address_t)ct8;
        aesRequest.textLength = (IOByteCount32) (chunk * CCAES_BLOCK_SIZE); //The hardware needs textLength in bytes.
        if(ioctl(ccaes_device, IOAES_ENCRYPT_DECRYPT, &aesRequest) == -1) {
            break;
        }

        // Most significant bit was increased which does not match corecrypto
        // counter width, we decrement it.
        if (isOverflow) {
            CC_LOAD64_BE(counter,aesRequest.iv.ivBytes);
            counter--;
            CC_STORE64_BE(counter,aesRequest.iv.ivBytes);
        }

        remaining -= chunk;
        pt8 += (chunk*CCAES_BLOCK_SIZE);
        ct8 += (chunk*CCAES_BLOCK_SIZE);
	}
	//Copy the IV back.
	cc_memcpy(iv, aesRequest.iv.ivBytes, CCAES_BLOCK_SIZE);
    cc_clear(ctx->keyLength,aesRequest.keyData.key.keyBytes); // zero key bytes
	return (nblocks - remaining);
}




#endif /* CCAES_MUX */

