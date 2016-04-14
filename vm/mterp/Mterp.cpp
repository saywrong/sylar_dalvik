/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Mterp entry point and support functions.
 */
#include "Dalvik.h"
#include "mterp/Mterp.h"

#include <stddef.h>
#include <dlfcn.h>

#if not defined(BUILD_HOST)

// void dvmMterpSpyEnable()
// {
//     extern unsigned int isSpyActive;
//     isSpyActive = 1;
// }
void sylar_PrintMethod(Method* method)
{
    /*
     * It is a direct (non-virtual) method if it is static, private,
     * or a constructor.
     */
    bool isDirect =
        ((method->accessFlags & (ACC_STATIC|ACC_PRIVATE)) != 0) ||
        (method->name[0] == '<');

    char* desc = dexProtoCopyMethodDescriptor(&method->prototype);

    ALOGE("<%c:%s.%s %s> ",
            isDirect ? 'D' : 'V',
            method->clazz->descriptor,
            method->name,
            desc);

    free(desc);
}


typedef void (*Pdalvik_invoke_watcher)(const Method*, Method*, void*, void*); 
Pdalvik_invoke_watcher dalvik_invoke_watcher = NULL;

void callInvokeWatcher(Method* methodToCall, u4 *fp, Thread* curThread)
{
    if(!dalvik_invoke_watcher)
    {
        void *lib = dlopen("libspy.so", RTLD_NOW);
        if(lib == NULL)
        {
            ALOGE("libdvm open libspy faild\n");
            return;
        }
            
        dalvik_invoke_watcher = (Pdalvik_invoke_watcher)dlsym(lib,"dalvik_invoke_watcher");
        if(dalvik_invoke_watcher==NULL)
            ALOGE("dlsym dalvik_invoke_watcher faild\n");
    }
    // ALOGE("spsize:%d", sizeof(StackSaveArea));
    StackSaveArea* saveArea = SAVEAREA_FROM_FP(fp);
    const Method* curMethod = saveArea->method;
    // ClassObject* curclazz = curMethod->clazz;
    // ClassObject* callClazz = methodToCall->clazz;

    dalvik_invoke_watcher(curMethod, methodToCall, saveArea, curThread); 

}
// void callInvokeWatcher()
// {
// }
#endif
/*
 * Verify some constants used by the mterp interpreter.
 */
bool dvmCheckAsmConstants()
{
    bool failed = false;

#ifndef DVM_NO_ASM_INTERP

#ifndef DVM_JMP_TABLE_MTERP
    extern void* dvmAsmInstructionStart[];
    extern void* dvmAsmInstructionEnd[];
#endif

#define ASM_DEF_VERIFY
#include "mterp/common/asm-constants.h"

    if (failed) {
        ALOGE("Please correct the values in mterp/common/asm-constants.h");
        dvmAbort();
    }

#ifndef DVM_JMP_TABLE_MTERP
    /*
     * If we're using computed goto instruction transitions, make sure
     * none of the handlers overflows the 64-byte limit.  This won't tell
     * which one did, but if any one is too big the total size will
     * overflow.
     */
#if defined(__mips__)
    const int width = 128;
#else
    const int width = 64;
#endif
    int interpSize = (uintptr_t) dvmAsmInstructionEnd -
                     (uintptr_t) dvmAsmInstructionStart;
    if (interpSize != 0 && interpSize != kNumPackedOpcodes*width) {
        ALOGE("ERROR: unexpected asm interp size %d", interpSize);
        ALOGE("(did an instruction handler exceed %d bytes?)", width);
        dvmAbort();
    }
#endif

#endif // ndef DVM_NO_ASM_INTERP

    return !failed;
}

/*
 * "Mterp entry point.
 */
void dvmMterpStd(Thread* self)
{
    /* configure mterp items */
    self->interpSave.methodClassDex = self->interpSave.method->clazz->pDvmDex;

    IF_LOGVV() {
        char* desc = dexProtoCopyMethodDescriptor(
                         &self->interpSave.method->prototype);
        LOGVV("mterp threadid=%d : %s.%s %s",
            dvmThreadSelf()->threadId,
            self->interpSave.method->clazz->descriptor,
            self->interpSave.method->name,
            desc);
        free(desc);
    }
    //ALOGI("self is %p, pc=%p, fp=%p", self, self->interpSave.pc,
    //      self->interpSave.curFrame);
    //ALOGI("first instruction is 0x%04x", self->interpSave.pc[0]);

    /*
     * Handle any ongoing profiling and prep for debugging
     */
    if (self->interpBreak.ctl.subMode != 0) {
        TRACE_METHOD_ENTER(self, self->interpSave.method);
        self->debugIsMethodEntry = true;   // Always true on startup
    }

    dvmMterpStdRun(self);

#ifdef LOG_INSTR
    ALOGD("|-- Leaving interpreter loop");
#endif
}
