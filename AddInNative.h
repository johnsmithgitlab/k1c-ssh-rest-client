/*
 * This file is part of k-) stack
 * Copyright (c) 2023 by Yury Deshin j.deshin@hotmail.com
 *
 * This work uses SSH Library (libssh) https://www.libssh.org/
 * This work based on the external component template source code, written by 1C Company
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __ADDINNATIVE_H__
#define __ADDINNATIVE_H__

#include "include/ComponentBase.h"
#include "include/AddInDefBase.h"
#include "include/IMemoryManager.h"


#include "include/libssh/libssh.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include <map>
#include <string>

///////////////////////////////////////////////////////////////////////////////
// class CAddInNative
class CAddInNative : public IComponentBase
{
public:
    enum Props
    {
        eLocalHostProp,
        eLocalPortProp,
        eRemoteHostProp,
        eRemotePortProp,
        eIsUnixSocketProp,
        eForwardingProp,
        eLastProp      // Always last
    };

    enum Methods
    {
        eOpenSessionMethod = 0,
        eCloseSessionMethod,
        eVerifyHostMethod,
        eAuthenticateByPasswordMethod,
        eAuthenticateByKeyMethod,
        eAuthenticateByKeyBase64Method,

        eSetBufferSizeMethod,
        eSetRequestFromBinaryDataMethod,
        eSetRequestFromStringMethod,
        eSendRequestMethod,
        eExecuteCommandMethod,
        eGetResponseAsBinaryDataMethod,
        eGetRespornseAsStringMethod,

        eSetHttpHeadMethod,
        eAddHttpHeaderMethod,
        eSetBodyFromBinaryDataMethod,
        eSendHttpRequestMethod,
        eGetHttpHeaderMethod,
        eGetBodyAsBinaryDataMethod,

        eLastMethod      // Always last
    };


    CAddInNative(void);
    virtual ~CAddInNative();
    // IInitDoneBase
    virtual bool ADDIN_API Init(void*) override;
    virtual bool ADDIN_API setMemManager(void* mem) override;
    virtual long ADDIN_API GetInfo() override;
    virtual void ADDIN_API Done() override;
    // ILanguageExtenderBase
    virtual bool ADDIN_API RegisterExtensionAs(WCHAR_T**) override;
    virtual long ADDIN_API GetNProps() override;
    virtual long ADDIN_API FindProp(const WCHAR_T* wsPropName) override;
    virtual const WCHAR_T* ADDIN_API GetPropName(long lPropNum, long lPropAlias) override;
    virtual bool ADDIN_API GetPropVal(const long lPropNum, tVariant* pvarPropVal) override;
    virtual bool ADDIN_API SetPropVal(const long lPropNum, tVariant* varPropVal) override;
    virtual bool ADDIN_API IsPropReadable(const long lPropNum) override;
    virtual bool ADDIN_API IsPropWritable(const long lPropNum) override;
    virtual long ADDIN_API GetNMethods() override;
    virtual long ADDIN_API FindMethod(const WCHAR_T* wsMethodName) override;
    virtual const WCHAR_T* ADDIN_API GetMethodName(const long lMethodNum, 
                            const long lMethodAlias) override;
    virtual long ADDIN_API GetNParams(const long lMethodNum) override;
    virtual bool ADDIN_API GetParamDefValue(const long lMethodNum, const long lParamNum,
                            tVariant *pvarParamDefValue) override;   
    virtual bool ADDIN_API HasRetVal(const long lMethodNum) override;
    virtual bool ADDIN_API CallAsProc(const long lMethodNum,
                    tVariant* paParams, const long lSizeArray) override;
    virtual bool ADDIN_API CallAsFunc(const long lMethodNum,
                tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray) override;
    // LocaleBase
    virtual void ADDIN_API SetLocale(const WCHAR_T* loc) override;
    // UserLanguageBase
    virtual void ADDIN_API SetUserInterfaceLanguageCode(const WCHAR_T* lang) override;
    
private:
    // Attributes
    long findName(const wchar_t* names[], const wchar_t* name, const uint32_t size) const;
    void addError(uint32_t wcode, const wchar_t* source,
                    const wchar_t* descriptor, long code);
    void addError(uint32_t wcode, const char16_t* source,
                    const char16_t* descriptor, long code);
    IAddInDefBase      *m_iConnect;
    IMemoryManager     *m_iMemory;

    // properties
    char *local_host;
    int local_port;
    char *remote_host;
    int remote_port;
    bool is_unix_socket;
    bool forwarding;

    ssh_session session;
    char *buffer;
    int buffer_size;
    int request_size;
    int response_size;

    bool OpenSession(tVariant* paParams, const long lSizeArray);
    bool CloseSession(void);
    bool VerifyHost(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool AuthenticateByPassword(tVariant* paParams, const long lSizeArray);
    bool AuthenticateByKey(tVariant* paParams, const long lSizeArray);
    bool AuthenticateByKeyBase64(tVariant* paParams, const long lSizeArray);
    bool SetBufferSize(tVariant* paParams, const long lSizeArray);
    // general functions
    bool SetRequestFromBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool SetRequestFromString(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool SendRequest(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool ExecuteCommand(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool GetResponseAsBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool GetRespornseAsString(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    // http functions
    bool SetHttpRequestHead(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool AddHttpHeader(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool SetBodyFromBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool SendHttpRequest(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool GetBodyAsBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
    bool GetHttpHeader(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray);
};
#endif //__ADDINNATIVE_H__
