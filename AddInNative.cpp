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

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>

#include <uchar.h>
#include <codecvt>
#include <locale>

#include <map>
#include <string>


#include "stdafx.h"


#if defined( __linux__ ) || defined(__APPLE__)
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <iconv.h>
#endif

#include <wchar.h>
#include "AddInNative.h"
#include <string>

static const WCHAR_T g_kClassNames[] = u"CAddInNative"; //|OtherClass1|OtherClass2";

uint32_t convToShortWchar(WCHAR_T** Dest, const wchar_t* Source, size_t len = 0);
uint32_t convFromShortWchar(wchar_t** Dest, const WCHAR_T* Source, uint32_t len = 0);
void disconnect_ssh_session(ssh_session session);

uint32_t getLenShortWcharStr(const WCHAR_T* Source);
static AppCapabilities g_capabilities = eAppCapabilitiesInvalid;
static std::u16string s_names(g_kClassNames);

static const wchar_t *g_PropNames[] = {
    L"LocalHost",
    L"LocalPort",
    L"RemoteHost",
    L"RemotePort",
    L"IsUnixSocket",
    L"UsingForwarding",
    L"Status"
};

static const wchar_t *g_MethodNames[] = {
    L"OpenSession",
    L"CloseSession",
    L"VerifyHost",
    L"AuthenticateByPassword",
    L"AuthenticateByKey",
    L"AuthenticateByKeyBase64",

    L"SetBufferSize",
    L"SetRequestFromBinaryData",
    L"SetRequestFromString",
    L"SendRequest",
    L"ExecuteCommand",
    L"GetResponseAsBinaryData",
    L"GetRespornseAsString",


    L"SetHttpHead",
    L"AddHttpHeader",
    L"SetBodyFromBinaryData",
    L"SendHttpRequest",
    L"GetHttpHeader",
    L"GetBodyAsBinaryData"
};

static const wchar_t *g_PropNamesRu[] = {
    L"ЛокальныйХост",
    L"ЛокальныйПорт",
    L"УдаленныйХост",
    L"УдаленныйПорт",
    L"UnixСокет",
    L"ИспользоватьПересылку"
};
static const wchar_t *g_MethodNamesRu[] = {
    L"ОткрытьСессию",
    L"ЗакрытьСессию",
    L"ПроверитьСервер",
    L"АутентифицироватьсяПоПаролю",
    L"АутентифицироватьсяПоКлючу",
    L"АутентифицироватьсяПоКлючуBase64",

    L"УстановитьРазмерБуфера",
    L"УстановитьЗапросИзДвоичныхДанных",
    L"УстановитьЗапросИзСтроки",
    L"ОтправитьЗапрос",
    L"ВыполнитьКоманду",
    L"ПолучитьОтветКакДвоичныеДанные",
    L"ПолучитьОтветКакСтроку",

    L"УстановитьЗаголовокHttpЗапроса",
    L"ДобавитьHttpЗаголовок",
    L"УстановитьТелоИзДвоичныхДанных",
    L"ОтправитьHttpЗапрос",
    L"ПолучитьHttpЗаголовок",
    L"ПолучитьТелоКакДвоичныеДанные",
    L"ПолучитьТелоКакСтроку"
};
//////////////////////////////////////////////////////////////////////
/*
 * Функции компоненты
 */

//---------------------------------------------------------------------------//
char * conv_wchar16_t_to_char(char16_t *source)
{
    wchar_t *wchar_t_str = NULL;
    ::convFromShortWchar(&wchar_t_str, source);
    std::wstring wstring_str(wchar_t_str);
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
    std::string cs = converter.to_bytes(wstring_str);
    return strdup(cs.c_str());
}
//---------------------------------------------------------------------------//
void disconnect_ssh_session(ssh_session session)
{
    ssh_disconnect(session);
    ssh_free(session);
}
//---------------------------------------------------------------------------//
bool CAddInNative::OpenSession(tVariant* paParams, const long lSizeArray)
{
    //ssh_session my_ssh_session;
    int verbosity = SSH_LOG_PROTOCOL;
    int port = paParams[1].intVal;
    char *host = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);

    char *user_name = NULL;

    if (TV_VT(&paParams[2]) == VTYPE_PWSTR && paParams[2].strLen > 0) {
        user_name = ::conv_wchar16_t_to_char(paParams[2].pwstrVal);
    }

    session = ssh_new();
    if (session == NULL) {
        free(host);
        if(user_name)
            free(user_name);
        addError(2001, L"LibSSH", L"Cannot create session object", 2001);
        return false;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    free(host);
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if(user_name) {
        ssh_options_set(session, SSH_OPTIONS_USER, user_name);
        free(user_name);
    }

    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        const char * err_str = ssh_get_error(session);
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2001, L"LibSSH", werr_str.data(), 2001);
        ssh_free(session);
        return false;
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::CloseSession(void)
{
    ssh_disconnect(session);
    if(session)
        ssh_free(session);

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::VerifyHost(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    bool accept_unknown_hosts = paParams[0].bVal;
    bool update_changed_hosts = paParams[1].bVal;
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    size_t hlen;
    ssh_key srv_pubkey = NULL;

    int rc;

    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        addError(2002, L"LibSSH", L"Cannot get public key", 2002);
        return false;
    }

    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        addError(2003, L"LibSSH", L"Cannot getpublic key hash", 2003);
        return false;
    }

    state = ssh_session_is_known_server(session);
    char *ret_str;

    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
            ret_str = (char *)"SSH_KNOWN_HOSTS_OK";
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            if(update_changed_hosts) {
                rc = ssh_session_update_known_hosts(session);
                if (rc < 0) {
                    const char * err_str = strerror(errno);
                    std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
                    addError(2004, L"LibSSH", werr_str.data(), 2004);
                    return false;
                }
                else
                    ret_str = (char *)"SSH_KNOWN_HOSTS_OK";
                break;
            }

            ret_str = (char *)"SSH_KNOWN_HOSTS_CHANGED";
            break;
        case SSH_KNOWN_HOSTS_OTHER:
            ret_str = (char *)"SSH_KNOWN_HOSTS_OTHER";
            break;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            ret_str = (char *)"SSH_KNOWN_HOSTS_NOT_FOUND";
            break;
        case SSH_KNOWN_HOSTS_UNKNOWN:
            if(accept_unknown_hosts) {
                rc = ssh_session_update_known_hosts(session);
                if (rc < 0) {
                    const char * err_str = strerror(errno);
                    std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
                    addError(2004, L"LibSSH", werr_str.data(), 2004);
                    return false;
                }
                else ret_str = (char *)"SSH_KNOWN_HOSTS_OK";
                break;
            }
            ret_str = (char *)"SSH_KNOWN_HOSTS_UNKNOWN";
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            const char * err_str = ssh_get_error(session);
            std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
            addError(2004, L"LibSSH", werr_str.data(), 2004);
            return false;
    };

    TV_VT(pvarRetValue) = VTYPE_PWSTR;

    std::wstring wret_str = std::wstring(ret_str, ret_str + strlen(ret_str));
    if (m_iMemory->AllocMemory((void**)&(pvarRetValue->pwstrVal), (unsigned)(wret_str.size() + 1) * sizeof(WCHAR_T))) {
        ::convToShortWchar(&(pvarRetValue->pwstrVal), wret_str.data());
        pvarRetValue->wstrLen = wret_str.length();
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::AuthenticateByPassword(tVariant* paParams, const long lSizeArray)
{
    char *user_name = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    char *password = ::conv_wchar16_t_to_char(paParams[1].pwstrVal);

    int rc = ssh_userauth_password(session, user_name, password);
    free(user_name);
    free(password);
    if (rc != SSH_AUTH_SUCCESS) {
        const char * err_str = ssh_get_error(session);
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2004, L"LibSSH", werr_str.data(), 2004);
        ::disconnect_ssh_session(session);
        return false;
    }
    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::AuthenticateByKey(tVariant* paParams, const long lSizeArray)
{
    char *key_file_name = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    ssh_key privkey = NULL;
    int res;

    if (TV_VT(&paParams[1]) == VTYPE_PWSTR && paParams[1].strLen > 0) {
        char *passphrase = ::conv_wchar16_t_to_char(paParams[1].pwstrVal);
        res = ssh_pki_import_privkey_file(key_file_name, passphrase, NULL, NULL, &privkey);
        free(passphrase);
    }
    else {
        res = ssh_pki_import_privkey_file(key_file_name, NULL, NULL, NULL, &privkey);
    }

    free(key_file_name);

    if(res == SSH_EOF) {
        const char *err_str = "The file doesn't exist or permission denied";
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2004, L"LibSSH", werr_str.data(), 2004);

        if(privkey != NULL)
            ssh_key_free(privkey);

        return false;
    }

    if(res != SSH_OK) {
        const char *err_str = "Error importing key file";
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2004, L"LibSSH", werr_str.data(), 2004);

        if(privkey != NULL)
            ssh_key_free(privkey);

        return false;
    }

    res = ssh_userauth_publickey(session, NULL, privkey);

    if(res != SSH_AUTH_SUCCESS) {
        const char * err_str = ssh_get_error(session);
        ssh_key_free(privkey);
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2004, L"LibSSH", werr_str.data(), 2004);
        ::disconnect_ssh_session(session);
        return false;
    }

    ssh_key_free(privkey);
    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::AuthenticateByKeyBase64(tVariant* paParams, const long lSizeArray)
{
    ssh_key privkey = NULL;
    char *key_buff = (char *)malloc(paParams[0].strLen + 1);
    memcpy(key_buff, paParams[0].pstrVal, paParams[0].strLen);
    key_buff[paParams[0].strLen] = 0;
    int res;

    if (TV_VT(&paParams[1]) == VTYPE_PWSTR && paParams[1].strLen > 0) {
        char *passphrase = ::conv_wchar16_t_to_char(paParams[1].pwstrVal);
        res = ssh_pki_import_privkey_base64(key_buff, passphrase, NULL, NULL, &privkey);
        free(passphrase);
    }
    else {
        res = ssh_pki_import_privkey_base64(key_buff, NULL, NULL, NULL, &privkey);
    }
    free(key_buff);

    if(res != SSH_OK) {
        const char *err_str = "Error importing key";
        std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
        addError(2004, L"LibSSH", werr_str.data(), 2004);

        if (privkey != NULL)
            ssh_key_free(privkey);

        return false;
    }

   res = ssh_userauth_publickey(session, NULL, privkey);

   if(res != SSH_AUTH_SUCCESS) {
       const char * err_str = ssh_get_error(session);
       ssh_key_free(privkey);
       std::wstring werr_str = std::wstring(err_str, err_str + strlen(err_str));
       addError(2004, L"LibSSH", werr_str.data(), 2004);
       ::disconnect_ssh_session(session);
       return false;
   }

   ssh_key_free(privkey);
   return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetBodyAsBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_EMPTY;
    int body_size = 0;
    // Должен быть или Content-Lengrh или chunked
    char *begin_headers = strstr(buffer, "\r\n");
    char *end_headers = strstr(begin_headers, "\r\n\r\n");
    char *body = end_headers + 4;
    std::string headers_str(begin_headers + 2, end_headers + 2);

    // Проверяем на Content-Length
    char *header = strstr((char *)headers_str.c_str(), "Content-Length: ");

    if(header) {
        sscanf(header, "Content-Length: %d", &body_size);

        if (m_iMemory) {
            TV_VT(pvarRetValue) = VTYPE_BLOB;

            if (m_iMemory->AllocMemory((void**)&(pvarRetValue->pstrVal), body_size)) {
                memcpy(pvarRetValue->pstrVal, body, body_size);
                pvarRetValue->strLen = body_size;
            }
        }

        return true;
    }

    // Проверяем на Transfer-Encoding: chunked"
    header = strstr((char *)headers_str.c_str(), "Transfer-Encoding: chunked");

    if (!header)
        return true;

    // Это chunked, считаем общий размер
    char *current = body;

    unsigned int chunk_size = 0;
    sscanf(current, "%x\r\n",&chunk_size);
    //body_size += chunk_size;

    while(chunk_size) {
        current = strstr(current,"\r\n");
        current += 2;
        body_size += chunk_size;
        current += chunk_size + 2;
        sscanf(current, "%x\r\n",&chunk_size);
    };

    // Выделяем память и копируем чанки
    if (m_iMemory) {
        TV_VT(pvarRetValue) = VTYPE_BLOB;
        if (m_iMemory->AllocMemory((void**)&(pvarRetValue->pstrVal), body_size)) {
            current = body;
            char *current_allocated = pvarRetValue->pstrVal;

            sscanf(current, "%x\r\n",&chunk_size);

            while(chunk_size) {
                current = strstr(current,"\r\n");
                current += 2;
                memcpy(current_allocated, current, chunk_size);
                current_allocated += chunk_size;
                current += chunk_size + 2;
                sscanf(current, "%x\r\n",&chunk_size);
            };

            pvarRetValue->strLen = body_size;
        }
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetBufferSize(tVariant* paParams, const long lSizeArray)
{
    if(buffer)
        delete [] buffer;

    buffer_size = paParams[0].lVal;
    buffer = new char[buffer_size];

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetHttpRequestHead(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    request_size = 0;
    char *http_method = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    char *relative_url = ::conv_wchar16_t_to_char(paParams[1].pwstrVal);
    int nbytes = 0;

    try {
        nbytes = sprintf(buffer + request_size, "%s %s HTTP/1.1\r\n", http_method, relative_url);
        request_size += nbytes;
    }
    catch(...) {
        free(http_method);
        free(relative_url);
        addError(2010, L"LibSSH", L"Cannot set http request head", 2010);
        return false;
    }

    free(http_method);
    free(relative_url);

    TV_VT(pvarRetValue) = VTYPE_I4;
    TV_I4(pvarRetValue) = nbytes;

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::AddHttpHeader(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    char *http_header_type = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    char *http_header_value = ::conv_wchar16_t_to_char(paParams[1].pwstrVal);
    int nbytes = 0;

    try {
        nbytes = sprintf(buffer + request_size, "%s: %s\r\n", http_header_type, http_header_value);
        request_size += nbytes;
    }
    catch(...) {
        free(http_header_type);
        free(http_header_value);
        addError(2010, L"LibSSH", L"Cannot set http request head", 2010);
        return false;
    }

    free(http_header_type);
    free(http_header_value);

    TV_VT(pvarRetValue) = VTYPE_I4;
    TV_I4(pvarRetValue) = nbytes;

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetBodyFromBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_I4;

    if (TV_VT(&paParams[0]) == VTYPE_BLOB && paParams[0].strLen > 0) {
        int nbytes = sprintf(buffer + request_size, "Content-Length: %d\r\n\r\n", paParams[0].strLen);
        request_size += nbytes;
        memcpy(buffer + request_size, paParams[0].pstrVal, paParams[0].strLen);
        request_size += paParams[0].strLen;
        *(buffer + request_size) = 0;
        TV_I4(pvarRetValue) = nbytes + paParams[0].strLen;
    }
    else {
        int nbytes = sprintf(buffer + request_size, "\r\n");
        request_size += nbytes;
        TV_I4(pvarRetValue) = nbytes;

    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetRequestFromBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_I4;
    request_size = 0;

    if (TV_VT(&paParams[0]) == VTYPE_BLOB && paParams[0].strLen > 0 && paParams[0].strLen < buffer_size) {
        memcpy(buffer + request_size, paParams[0].pstrVal, paParams[0].strLen);
        request_size += paParams[0].strLen;
        *(buffer + request_size) = 0;
        TV_I4(pvarRetValue) = paParams[0].strLen;
    }
    else {
        if (TV_VT(&paParams[0]) == VTYPE_EMPTY || (TV_VT(&paParams[0]) == VTYPE_BLOB && paParams[0].strLen == 0)) {
            TV_I4(pvarRetValue) = 0;
            return true;
        }
        else {
            addError(2010, L"LibSSH", L"Cannot set request", 2010);
            return false;
        }
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetRequestFromString(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_I4;
    request_size = 0;

    if (TV_VT(&paParams[0]) == VTYPE_PWSTR && paParams[0].wstrLen > 0) {
        char *data = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
        int nbytes = strlen(data);
        memcpy(buffer + request_size, data, nbytes);
        request_size += nbytes;
        free(data);
        *(buffer + request_size) = 0;
        TV_I4(pvarRetValue) = nbytes;
    }
    else {
        addError(2010, L"LibSSH", L"Cannot set request", 2010);
        return false;
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SendRequest(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    ssh_channel channel;
    response_size = 0;

    channel = ssh_channel_new(session);

    if (channel == NULL) {
        addError(2005, L"LibSSH", L"Cannot create channel", 2005);
        return false;
    }

    int rc = SSH_OK;
    if(forwarding) {
        if (is_unix_socket)
            rc = ssh_channel_open_forward_unix(channel, remote_host, local_host, local_port);
        else
            rc = ssh_channel_open_forward(channel, remote_host, remote_port, local_host, local_port);
    }
    else
        rc = ssh_channel_open_session(channel);

    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        addError(2006, L"LibSSH", L"Cannot open forwarded socket", 2006);
        return false;
    }

    int nbytes = ssh_channel_write(channel, buffer, request_size);

    if (request_size != nbytes) {
      ssh_channel_free(channel);
      addError(2007, L"LibSSH", L"Cannot write to socket", 2007);
      return false;
    }

    rc = ssh_channel_send_eof(channel);
    if (rc == SSH_ERROR) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        addError(2008, L"LibSSH", L"Error send Eof", 2008);
    }

    response_size = ssh_channel_read(channel, buffer, buffer_size, 0);

    if (response_size == buffer_size) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        addError(2008, L"LibSSH", L"Buffer overflow", 2008);
        return false;
    }

    *(buffer + response_size) = 0;

    TV_VT(pvarRetValue) = VTYPE_I4;
    TV_I4(pvarRetValue) = response_size;

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::ExecuteCommand(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    ssh_channel channel;
    response_size = 0;

    channel = ssh_channel_new(session);

    if (channel == NULL) {
        addError(2005, L"LibSSH", L"Cannot create channel", 2005);
        return false;
    }

    int rc = SSH_OK;
    rc = ssh_channel_open_session(channel);

    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        addError(2007, L"LibSSH", L"Cannot open session", 2007);
        return false;
    }

    char *command_text = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    rc = ssh_channel_request_exec(channel, command_text);
    free(command_text);

    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        addError(2007, L"LibSSH", L"Cannot exec", 2007);
        return false;
    }

    if (request_size) {
        int nbytes = ssh_channel_write(channel, buffer, request_size);

        if (request_size != nbytes) {
          ssh_channel_free(channel);
          addError(2007, L"LibSSH", L"Cannot write to socket", 2007);
          return false;
        }
    }

    rc = ssh_channel_send_eof(channel);

    if (rc == SSH_ERROR) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        addError(2008, L"LibSSH", L"Error send Eof", 2008);
    }

    response_size = ssh_channel_read(channel, buffer, buffer_size, 0);

    if (response_size == buffer_size) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        addError(2008, L"LibSSH", L"Buffer overflow", 2008);
        return false;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    *(buffer + response_size) = 0;

    TV_VT(pvarRetValue) = VTYPE_I4;
    TV_I4(pvarRetValue) = response_size;

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SendHttpRequest(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    if (SendRequest(pvarRetValue, paParams, lSizeArray)) {
        int status_code;
        sscanf(buffer,"%*s %d", &status_code);

        TV_VT(pvarRetValue) = VTYPE_I4;
        TV_I4(pvarRetValue) = status_code;

        return true;
    }

    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetHttpHeader(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_EMPTY;
    char *header_name = ::conv_wchar16_t_to_char(paParams[0].pwstrVal);
    int header_name_len = strlen(header_name);
    char *begin_headers = strstr(buffer, "\r\n");
    char *end_headers = strstr(begin_headers, "\r\n\r\n");
    std::string headers_str(begin_headers + 2, end_headers + 2);
    char *header = strstr((char *)headers_str.c_str(), header_name);
    free(header_name);

    if(header) {
        char *header_value = header + header_name_len + 2;
        char *end_header_value = strstr(header_value, "\r\n");

        if (!end_header_value)
            return true;

        if (m_iMemory) {
            TV_VT(pvarRetValue) = VTYPE_PWSTR;
            std::wstring wret_str = std::wstring(header_value, end_header_value-1);

            if (m_iMemory->AllocMemory((void**)&(pvarRetValue->pwstrVal), (unsigned)(wret_str.size() + 1) * sizeof(WCHAR_T))) {
                ::convToShortWchar(&(pvarRetValue->pwstrVal), wret_str.data());
                pvarRetValue->wstrLen = wret_str.length();
            }
        }
    }

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetResponseAsBinaryData(tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{
    TV_VT(pvarRetValue) = VTYPE_EMPTY;

    if (m_iMemory) {
        TV_VT(pvarRetValue) = VTYPE_BLOB;

        if (m_iMemory->AllocMemory((void**)&(pvarRetValue->pstrVal), response_size)) {
            memcpy(pvarRetValue->pstrVal, buffer, response_size);
            pvarRetValue->strLen = response_size;
        }
    }

    return true;
}
//////////////////////////////////////////////////////////////////////
//---------------------------------------------------------------------------//
long GetClassObject(const WCHAR_T* wsName, IComponentBase** pInterface)
{
    if(!*pInterface) {
        *pInterface= new CAddInNative();
        return (long)*pInterface;
    }
    return 0;
}
//---------------------------------------------------------------------------//
AppCapabilities SetPlatformCapabilities(const AppCapabilities capabilities)
{
    g_capabilities = capabilities;
    return eAppCapabilitiesLast;
}
//---------------------------------------------------------------------------//
AttachType GetAttachType()
{
    return eCanAttachAny;
}
//---------------------------------------------------------------------------//
long DestroyObject(IComponentBase** pIntf)
{
    if(!*pIntf)
        return -1;

    delete *pIntf;
    *pIntf = 0;

    return 0;
}
//---------------------------------------------------------------------------//
const WCHAR_T* GetClassNames()
{
    return s_names.c_str();
}
//---------------------------------------------------------------------------//
//CAddInNative
CAddInNative::CAddInNative()
{
    m_iMemory = nullptr;
    m_iConnect = nullptr;
    // Инициализируем свойства
    local_host = strdup("localhost");
    remote_host = strdup("");
    local_port = 0;
    remote_port = 0;
    is_unix_socket = false;
    session = NULL;

    buffer_size = 1024*1024;
    buffer = new char[buffer_size];

    request_size = 0;
    response_size = 0;
}
//---------------------------------------------------------------------------//
CAddInNative::~CAddInNative()
{
    // Освобождаем память свойств
    if(local_host)
        free(local_host);

    if(remote_host)
        free(remote_host);

    if(session)
        ::disconnect_ssh_session(session);

    if(buffer)
        delete [] buffer;
}
//---------------------------------------------------------------------------//
bool CAddInNative::Init(void* pConnection)
{ 
    m_iConnect = (IAddInDefBase*)pConnection;
    return m_iConnect != NULL;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetInfo()
{ 
    return 2000; 
}
//---------------------------------------------------------------------------//
void CAddInNative::Done()
{
}
// ILanguageExtenderBase
//---------------------------------------------------------------------------//
bool CAddInNative::RegisterExtensionAs(WCHAR_T** wsExtensionName)
{ 
    const wchar_t *wsExtension = L"AddInNativeExtension";
    size_t iActualSize = ::wcslen(wsExtension) + 1;
    WCHAR_T* dest = 0;

    if (m_iMemory) {
        if(m_iMemory->AllocMemory((void**)wsExtensionName, (unsigned)iActualSize * sizeof(WCHAR_T)))
            ::convToShortWchar(wsExtensionName, wsExtension, iActualSize);
        return true;
    }

    return false;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNProps()
{ 
    return eLastProp;
}
//---------------------------------------------------------------------------//
long CAddInNative::FindProp(const WCHAR_T* wsPropName)
{ 
    long plPropNum = -1;
    wchar_t* propName = 0;

    ::convFromShortWchar(&propName, wsPropName);
    plPropNum = findName(g_PropNames, propName, eLastProp);

    if (plPropNum == -1)
        plPropNum = findName(g_PropNamesRu, propName, eLastProp);

    delete[] propName;

    return plPropNum;
}
//---------------------------------------------------------------------------//
const WCHAR_T* CAddInNative::GetPropName(long lPropNum, long lPropAlias)
{ 
    if (lPropNum >= eLastProp)
        return NULL;

    wchar_t *wsCurrentName = NULL;
    WCHAR_T *wsPropName = NULL;
    size_t iActualSize = 0;

    switch(lPropAlias) {
        case 0: // First language
            wsCurrentName = (wchar_t*)g_PropNames[lPropNum];
            break;
        case 1: // Second language
            wsCurrentName = (wchar_t*)g_PropNamesRu[lPropNum];
            break;
        default:
            return 0;
    };

    iActualSize = wcslen(wsCurrentName) + 1;

    if (m_iMemory && wsCurrentName) {
        if (m_iMemory->AllocMemory((void**)&wsPropName, (unsigned)iActualSize * sizeof(WCHAR_T)))
            ::convToShortWchar(&wsPropName, wsCurrentName, iActualSize);
    }

    return wsPropName;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetPropVal(const long lPropNum, tVariant* pvarPropVal)
{ 
    TV_VT(pvarPropVal) = VTYPE_EMPTY;

    switch(lPropNum) {
        case eLocalPortProp:
            TV_VT(pvarPropVal) = VTYPE_I4;
            TV_I4(pvarPropVal) = local_port;
            break;
        case eRemotePortProp:
            TV_VT(pvarPropVal) = VTYPE_I4;
            TV_I4(pvarPropVal) = remote_port;
            break;
        case eLocalHostProp:
        case eRemoteHostProp:
            if (m_iMemory) {
                TV_VT(pvarPropVal) = VTYPE_PWSTR;
                WCHAR_T *wsPropName = NULL;
                char *ret_str = NULL;

                switch(lPropNum) {
                    case eLocalHostProp:
                        ret_str = local_host;
                        break;
                    case eRemoteHostProp:
                        ret_str = remote_host;
                        break;
                };

                std::wstring wret_str = std::wstring(ret_str, ret_str + strlen(ret_str));
                if (m_iMemory->AllocMemory((void**)&(pvarPropVal->pwstrVal), (unsigned)(wret_str.size() + 1) * sizeof(WCHAR_T))) {
                    ::convToShortWchar(&(pvarPropVal->pwstrVal), wret_str.data());
                    pvarPropVal->wstrLen = wret_str.length();
                }
            }
            break;
        case eIsUnixSocketProp:
            TV_VT(pvarPropVal) = VTYPE_BOOL;
            TV_BOOL(pvarPropVal) = is_unix_socket;
            break;
        case eForwardingProp:
            TV_VT(pvarPropVal) = VTYPE_BOOL;
            TV_BOOL(pvarPropVal) = forwarding;
            break;
        default:
            return false;
    };

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::SetPropVal(const long lPropNum, tVariant *varPropVal)
{ 
    switch(lPropNum) {
        case eLocalPortProp:
            if (TV_VT(varPropVal) != VTYPE_INT)
                return false;
            local_port = TV_INT(varPropVal);
            break;
        case eRemotePortProp:
            if (TV_VT(varPropVal) != VTYPE_INT)
                return false;
            remote_port = TV_INT(varPropVal);
            break;
        case eLocalHostProp:
            if (TV_VT(varPropVal) != VTYPE_PWSTR)
                return false;
            free(local_host);
            local_host = ::conv_wchar16_t_to_char(varPropVal->pwstrVal);
            break;
        case eRemoteHostProp:
            if (TV_VT(varPropVal) != VTYPE_PWSTR)
                return false;
            free(remote_host);
            remote_host = ::conv_wchar16_t_to_char(varPropVal->pwstrVal);
            break;
        case eIsUnixSocketProp:
            if (TV_VT(varPropVal) != VTYPE_BOOL)
                return false;
            is_unix_socket = TV_BOOL(varPropVal);
            break;
        case eForwardingProp:
            if (TV_VT(varPropVal) != VTYPE_BOOL)
                return false;
            forwarding = TV_BOOL(varPropVal);
            break;
        default:
            return false;
    };

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::IsPropReadable(const long lPropNum)
{ 
    switch(lPropNum) {
        case eLocalPortProp:
        case eLocalHostProp:
        case eRemotePortProp:
        case eRemoteHostProp:
        case eIsUnixSocketProp:
        case eForwardingProp:
            return true;
        default:
            return false;
    };

    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::IsPropWritable(const long lPropNum)
{
    switch(lPropNum) {
        case eLocalPortProp:
        case eLocalHostProp:
        case eRemotePortProp:
        case eRemoteHostProp:
        case eIsUnixSocketProp:
        case eForwardingProp:
            return true;
        default:
            return false;
    };

    return false;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNMethods()
{ 
    return eLastMethod;
}
//---------------------------------------------------------------------------//
long CAddInNative::FindMethod(const WCHAR_T* wsMethodName)
{ 
    long plMethodNum = -1;
    wchar_t* name = 0;

    ::convFromShortWchar(&name, wsMethodName);

    plMethodNum = findName(g_MethodNames, name, eLastMethod);

    if (plMethodNum == -1)
        plMethodNum = findName(g_MethodNamesRu, name, eLastMethod);

    delete[] name;

    return plMethodNum;
}
//---------------------------------------------------------------------------//
const WCHAR_T* CAddInNative::GetMethodName(const long lMethodNum, const long lMethodAlias)
{ 
    if (lMethodNum >= eLastMethod)
        return NULL;

    wchar_t *wsCurrentName = NULL;
    WCHAR_T *wsMethodName = NULL;
    size_t iActualSize = 0;

    switch(lMethodAlias) {
    case 0: // First language
        wsCurrentName = (wchar_t*)g_MethodNames[lMethodNum];
        break;
    case 1: // Second language
        wsCurrentName = (wchar_t*)g_MethodNamesRu[lMethodNum];
        break;
    default:
        return 0;
    };

    iActualSize = wcslen(wsCurrentName) + 1;

    if (m_iMemory && wsCurrentName) {
        if(m_iMemory->AllocMemory((void**)&wsMethodName, (unsigned)iActualSize * sizeof(WCHAR_T)))
            ::convToShortWchar(&wsMethodName, wsCurrentName, iActualSize);
    }

    return wsMethodName;
}
//---------------------------------------------------------------------------//
long CAddInNative::GetNParams(const long lMethodNum)
{ 
    switch(lMethodNum) {
        case eOpenSessionMethod:
            return 3;
        case eCloseSessionMethod:
            return 0;
        case eVerifyHostMethod:
            return 2;
        case eAuthenticateByPasswordMethod:
            return 2;
        case eAuthenticateByKeyMethod:
            return 2;
        case eAuthenticateByKeyBase64Method:
            return 2;
        case eSetBufferSizeMethod:
            return 1;
        case eSetRequestFromBinaryDataMethod:
            return 1;
        case eSetRequestFromStringMethod:
            return 1;
        case eSendRequestMethod:
            return 0;
        case eExecuteCommandMethod:
            return 1;
        case eGetResponseAsBinaryDataMethod:
            return 0;
        case eGetRespornseAsStringMethod:
            return 0;
        case eSetHttpHeadMethod:
            return 2;
        case eAddHttpHeaderMethod:
            return 2;
        case eSetBodyFromBinaryDataMethod:
            return 1;
        case eSendHttpRequestMethod:
            return 0;
        case eGetHttpHeaderMethod:
            return 1;
        case eGetBodyAsBinaryDataMethod:
            return 0;
        default:
            return 0;
    };

    return 0;
}
//---------------------------------------------------------------------------//
bool CAddInNative::GetParamDefValue(const long lMethodNum, const long lParamNum,
                        tVariant *pvarParamDefValue)
{ 
//    TV_VT(pvarParamDefValue)= VTYPE_EMPTY;
    switch(lMethodNum) {
        case eSetBodyFromBinaryDataMethod:
            TV_VT(pvarParamDefValue)= VTYPE_EMPTY;
            return true;
        default:
            return false;
    };

    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::HasRetVal(const long lMethodNum)
{ 
    switch(lMethodNum) {
        case eOpenSessionMethod:
            return false;
        case eCloseSessionMethod:
            return false;
        case eVerifyHostMethod:
            return true;
        case eAuthenticateByPasswordMethod:
            return false;
        case eAuthenticateByKeyMethod:
            return false;
        case eAuthenticateByKeyBase64Method:
            return false;
        case eSetBufferSizeMethod:
            return false;
        case eSetRequestFromBinaryDataMethod:
            return true;
        case eSetRequestFromStringMethod:
            return true;
        case eSendRequestMethod:
            return true;
        case eExecuteCommandMethod:
            return true;
        case eGetResponseAsBinaryDataMethod:
            return true;
        case eGetRespornseAsStringMethod:
            return true;
        case eSetHttpHeadMethod:
            return true;
        case eAddHttpHeaderMethod:
            return true;
        case eSetBodyFromBinaryDataMethod:
            return true;
        case eSendHttpRequestMethod:
            return true;
        case eGetHttpHeaderMethod:
            return true;
        case eGetBodyAsBinaryDataMethod:
            return true;
        default:
            return false;
    };

    return false;
}
//---------------------------------------------------------------------------//
bool CAddInNative::CallAsProc(const long lMethodNum,
                    tVariant* paParams, const long lSizeArray)
{
    switch(lMethodNum) {
        case eOpenSessionMethod:
            return OpenSession(paParams, lSizeArray);
        case eCloseSessionMethod:
            return CloseSession();
        case eAuthenticateByPasswordMethod:
            return AuthenticateByPassword(paParams, lSizeArray);
        case eAuthenticateByKeyMethod:
            return AuthenticateByKey(paParams, lSizeArray);
        case eAuthenticateByKeyBase64Method:
            return AuthenticateByKeyBase64(paParams, lSizeArray);
        case eSetBufferSizeMethod:
            return SetBufferSize(paParams, lSizeArray);
        default:
            return false;
    };

    return true;
}
//---------------------------------------------------------------------------//
bool CAddInNative::CallAsFunc(const long lMethodNum,
                tVariant* pvarRetValue, tVariant* paParams, const long lSizeArray)
{ 
    switch(lMethodNum) {
        case eVerifyHostMethod:
            return VerifyHost(pvarRetValue, paParams, lSizeArray);
        case eSetRequestFromBinaryDataMethod:
            return SetRequestFromBinaryData(pvarRetValue, paParams, lSizeArray);
        case eSetRequestFromStringMethod:
            return SetRequestFromString(pvarRetValue, paParams, lSizeArray);
        case eSendRequestMethod:
            return SendRequest(pvarRetValue, paParams, lSizeArray);
        case eExecuteCommandMethod:
            return ExecuteCommand(pvarRetValue, paParams, lSizeArray);
        case eGetResponseAsBinaryDataMethod:
            return GetResponseAsBinaryData(pvarRetValue, paParams, lSizeArray);
        case eGetRespornseAsStringMethod:
            return false;
        case eSetHttpHeadMethod:
            return SetHttpRequestHead(pvarRetValue, paParams, lSizeArray);
        case eAddHttpHeaderMethod:
            return AddHttpHeader(pvarRetValue, paParams, lSizeArray);
        case eSetBodyFromBinaryDataMethod:
            return SetBodyFromBinaryData(pvarRetValue, paParams, lSizeArray);
        case eSendHttpRequestMethod:
            return SendHttpRequest(pvarRetValue, paParams, lSizeArray);
        case eGetHttpHeaderMethod:
            return GetHttpHeader(pvarRetValue, paParams, lSizeArray);
        case eGetBodyAsBinaryDataMethod:
            return GetBodyAsBinaryData(pvarRetValue, paParams, lSizeArray);
        default:
            return false;
    };

    return false;
}
//---------------------------------------------------------------------------//
void CAddInNative::SetLocale(const WCHAR_T* loc)
{
}
//---------------------------------------------------------------------------//
void ADDIN_API CAddInNative::SetUserInterfaceLanguageCode(const WCHAR_T * lang)
{
}
//---------------------------------------------------------------------------//
bool CAddInNative::setMemManager(void* mem)
{
    m_iMemory = (IMemoryManager*)mem;
    return m_iMemory != 0;
}
//---------------------------------------------------------------------------//
void CAddInNative::addError(uint32_t wcode, const wchar_t* source,
                        const wchar_t* descriptor, long code)
{
    if (m_iConnect) {
        WCHAR_T *err = 0;
        WCHAR_T *descr = 0;

        ::convToShortWchar(&err, source);
        ::convToShortWchar(&descr, descriptor);

        m_iConnect->AddError(wcode, err, descr, code);
        delete[] err;
        delete[] descr;
    }
}
//---------------------------------------------------------------------------//
void CAddInNative::addError(uint32_t wcode, const char16_t * source, const char16_t * descriptor, long code)
{
    if (m_iConnect) {
        m_iConnect->AddError(wcode, source, descriptor, code);
    }
}
//---------------------------------------------------------------------------//
long CAddInNative::findName(const wchar_t* names[], const wchar_t* name,
                        const uint32_t size) const
{
    long ret = -1;
    for (uint32_t i = 0; i < size; i++) {
        if (!wcscmp(names[i], name)) {
            ret = i;
            break;
        }
    }
    return ret;
}
//---------------------------------------------------------------------------//
uint32_t convToShortWchar(WCHAR_T** Dest, const wchar_t* Source, size_t len)
{
    if (!len)
        len = ::wcslen(Source) + 1;

    if (!*Dest)
        *Dest = new WCHAR_T[len];

    WCHAR_T* tmpShort = *Dest;
    wchar_t* tmpWChar = (wchar_t*) Source;
    uint32_t res = 0;

    ::memset(*Dest, 0, len * sizeof(WCHAR_T));

#if defined( __linux__ ) || defined(__APPLE__)
    size_t succeed = (size_t)-1;
    size_t f = len * sizeof(wchar_t), t = len * sizeof(WCHAR_T);
    const char* fromCode = sizeof(wchar_t) == 2 ? "UTF-16" : "UTF-32";
    iconv_t cd = iconv_open("UTF-16LE", fromCode);
    if (cd != (iconv_t)-1) {
        succeed = iconv(cd, (char**)&tmpWChar, &f, (char**)&tmpShort, &t);
        iconv_close(cd);
        if(succeed != (size_t)-1)
            return (uint32_t)succeed;
    }
#endif 
    for (; len; --len, ++res, ++tmpWChar, ++tmpShort) {
        *tmpShort = (WCHAR_T)*tmpWChar;
    }

    return res;
}
//---------------------------------------------------------------------------//
uint32_t convFromShortWchar(wchar_t** Dest, const WCHAR_T* Source, uint32_t len)
{
    if (!len)
        len = getLenShortWcharStr(Source) + 1;

    if (!*Dest)
        *Dest = new wchar_t[len];

    wchar_t* tmpWChar = *Dest;
    WCHAR_T* tmpShort = (WCHAR_T*)Source;
    uint32_t res = 0;

    ::memset(*Dest, 0, len * sizeof(wchar_t));
#if defined( __linux__ ) || defined(__APPLE__)
    size_t succeed = (size_t)-1;
    const char* fromCode = sizeof(wchar_t) == 2 ? "UTF-16" : "UTF-32";
    size_t f = len * sizeof(WCHAR_T), t = len * sizeof(wchar_t);
    iconv_t cd = iconv_open("UTF-32LE", fromCode);
    if (cd != (iconv_t)-1) {
        succeed = iconv(cd, (char**)&tmpShort, &f, (char**)&tmpWChar, &t);
        iconv_close(cd);
        if(succeed != (size_t)-1)
            return (uint32_t)succeed;
    }
#endif 
    for (; len; --len, ++res, ++tmpWChar, ++tmpShort) {
        *tmpWChar = (wchar_t)*tmpShort;
    }

    return res;
}
//---------------------------------------------------------------------------//
uint32_t getLenShortWcharStr(const WCHAR_T* Source)
{
    uint32_t res = 0;
    WCHAR_T *tmpShort = (WCHAR_T*)Source;

    while (*tmpShort++)
        ++res;

    return res;
}
