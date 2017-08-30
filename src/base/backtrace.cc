/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include "base/backtrace.h"

#include <boost/algorithm/string.hpp>
//WINDOWSFIX #include <execinfo.h>
#include <stdio.h>

#include "base/logging.h"

#ifdef _WIN32
#include <dbghelp.h>
#endif

ssize_t BackTrace::ToString(void * const* callstack, int frames, char *buf,
                            size_t buf_len) {
#ifdef _WINDOWS
    assert(0);//should not be called
    return 0;
#elif defined(DARWIN)
    return 0;
#else
    buf[0] = '\0';

    char *str = buf;
    char **strs = backtrace_symbols(callstack, frames);
    int line_pos;
    size_t len = 0;

    for (int i = 0; i < frames; ++i) {
        int status;
        std::vector<std::string> SplitVec;

        if (i == frames - 1) continue;
        boost::split(SplitVec, strs[i], boost::is_any_of("()"),
                     boost::token_compress_on);
        boost::split(SplitVec, SplitVec[1], boost::is_any_of("+"),
                     boost::token_compress_on);
        char *demangledName =
            abi::__cxa_demangle(SplitVec[0].c_str(), NULL, NULL, &status);
        line_pos = 1;

        if (status == 0) {
            if (!strstr(demangledName, "boost::") &&
                !strstr(demangledName, "tbb::") &&
                !strstr(demangledName, "BackTrace::") &&
                !strstr(demangledName, "BgpDebug::") &&
                !strstr(demangledName, "testing::")) {
                len = snprintf(str, buf_len - (str - buf),
                               "\t%s+%s\n", demangledName,
                               SplitVec[line_pos].c_str());
                if (len > buf_len - (str - buf)) {

                    // Overflow
                    free(demangledName);
                    str += buf_len - (str - buf);
                    assert((size_t) (str - buf) == buf_len);
                    break;
                }
                str += len;
            }
            free(demangledName);
        }
    }
    free(strs);

    return (str - buf);
#endif
}

int BackTrace::Get(void * const* &callstack) {
#ifdef _WINDOWS
     assert(0);
     return 0;
#else
    callstack = (void * const *) calloc(1024, sizeof(void *));
    return backtrace((void **) callstack, 1024);
#endif
}

void BackTrace::Log(void * const* callstack, int frames,
                    const std::string &msg) {
#ifdef _WINDOWS
    assert(0); //should not be called for windows
    return;
#endif
    char buf[10240];

    ToString(callstack, frames, buf, sizeof(buf));
    std::string s(buf, strlen(buf));
    LOG(DEBUG, msg << ":BackTrace\n" << s);
    free((void *) callstack);
}

void BackTrace::Log(const std::string &msg) {
#ifndef _WINDOWS
    void * const*callstack;
    int frames = Get(callstack);
    Log(callstack, frames, msg);
#else

    //see https://msdn.microsoft.com/en-us/library/windows/desktop/ms680344(v=vs.85).aspx
    //https://msdn.microsoft.com/en-us/library/windows/desktop/ms680578(v=vs.85).aspx
    std::string callstack;

    HANDLE hProcess = GetCurrentProcess();//-1 return value is OK and valid, hence no error checking
    const int maxframes = 128;
    void * frames[maxframes];
    USHORT nFrames = 0;
    DWORD64  dwDisplacement = 0;
    PSYMBOL_INFO pSymbol = nullptr;

    if (SymInitialize(hProcess, NULL, TRUE)) {
        nFrames = CaptureStackBackTrace(0, maxframes, frames, NULL);
        if (nFrames > 0) {
            std::unique_ptr<char[]> pbuffer(new char[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)]);
            pSymbol = reinterpret_cast<SYMBOL_INFO*>(pbuffer.get()); //unique_ptr does not give up ownership
            pSymbol->MaxNameLen = MAX_SYM_NAME;
            pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            std::stringstream ss;
            for (USHORT i = 0; i < nFrames; i++) {
                if (SymFromAddr(hProcess, (DWORD64)frames[i], 0, pSymbol) == TRUE) {
                    ss << i << "::" << pSymbol->Name << "::" << std::hex << pSymbol->Address << std::endl;
                }
            }
            callstack += ss.str();
        }

    }
    else {
        callstack = GetFormattedWindowsErrorMsg();//could not get callstack
    }

    LOG(DEBUG, msg << "BackTrace:" << callstack);
#endif
}
