/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <fstream>
#include <sstream>
#include <stdlib.h> 
#include <base/misc_utils.h>
#include <base/logging.h>
#include <base/paths.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include "base/sandesh/version_types.h"
#include "base/logging.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#ifdef _WIN32
#include "vnsw/agent/contrail/windows/resource.h"
#endif

using namespace std;
namespace fs = boost::filesystem;

#ifndef _WIN32
const std::string MiscUtils::ContrailVersionCmd = "/usr/bin/contrail-version";
#endif

const std::string MiscUtils::CoreFileDir = dir_paths::var + "crashes/";
const int MiscUtils::MaxCoreFiles = 5;
const map<MiscUtils::BuildModule, string> MiscUtils::BuildModuleNames = 
    MiscUtils::MapInit();

SandeshTraceBufferPtr VersionTraceBuf(SandeshTraceBufferCreate(
                                       VERSION_TRACE_BUF, 500));

string MiscUtils::BaseName(string filename) {
    size_t pos = filename.find_last_of('/');
    if (pos != string::npos) {
        return filename.substr((pos+1));
    }
    return filename;
}

void MiscUtils::LogVersionInfo(const string build_info, Category::type categ) {
    VERSION_TRACE(VersionInfoTrace, build_info);
    if (!LoggingDisabled()) {
        VERSION_LOG(VersionInfoLog, categ, build_info);
    }
}

void MiscUtils::GetCoreFileList(string prog, vector<string> &list) {
    if (!fs::exists(CoreFileDir) || !fs::is_directory(CoreFileDir)) {
        return;
    }
    FileMMap files_map;
    
    string filename = "core." + BaseName(prog) + ".";

    fs::path dir_path(CoreFileDir.c_str());
    fs::directory_iterator end_itr;
    for (fs::directory_iterator itr(dir_path); itr != end_itr; itr++) {
        if (fs::is_regular_file(itr->status())) {
            const string file = itr->path().filename().generic_string();
            size_t pos = file.find(filename);
            if (pos != 0) {
                continue;
            }
            files_map.insert(FileMMap::value_type(fs::last_write_time
                                                    (itr->path()), file));
        }
    }
    FileMMap::reverse_iterator rit;
    int count = 0;
    for (rit = files_map.rbegin(); rit != files_map.rend() && 
        count < MaxCoreFiles; ++rit) {
        count++;
        list.push_back(rit->second);
    }
}

#ifndef _WIN32
bool MiscUtils::GetVersionInfoInternal(const string &cmd, string &rpm_version,
                                       string &build_num) {
    FILE *fp=NULL;
    char line[512];
    fp = popen(cmd.c_str(), "r");
    if (fp == NULL) {
        return false;
    }
    char *ptr = fgets(line, sizeof(line), fp);
    if (ptr == NULL) {
    pclose(fp);
        return false;
    }
    pclose(fp);
    ptr = strchr(line, '\n');
    if (ptr != NULL) {
        *ptr = '\0';
    }
    istringstream iss(line);
    if (iss) {
        iss >> rpm_version;
        if (iss) {
            iss >> build_num;
        } else {
            return false;
        }
    } else {
        return false;
    }

    return true;
}
#endif

bool MiscUtils::GetContrailVersionInfo(BuildModule id, string &rpm_version,
    string &build_num) {
    bool ret;
    stringstream cmd;
    //Initialize the version info here. Overide its value on finding version
    rpm_version.assign("unknown");
    build_num.assign("unknown");
#ifndef _WIN32
    ifstream f(ContrailVersionCmd.c_str());
    if (!f.good()) {
        f.close();
        return false;
    }
    f.close();
    cmd << ContrailVersionCmd << " " << BuildModuleNames.at(id)
        << " | tail -1 | awk '{ print $2 \" \" $3 }'";
    ret = GetVersionInfoInternal(cmd.str(), rpm_version, build_num);
#else // getting it from the binary resources
    ret = false;
    const int bufsize = 64;
    char buffer[bufsize];
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule) {
        if (LoadString(hModule, IDS_CONTRAIL_RPM_VERSION, buffer, bufsize) > 0) {
            rpm_version = buffer;
            if (LoadString(hModule, IDS_CONTRAIL_BUILD_NUM, buffer, bufsize) > 0) {
                build_num = buffer;
                ret = true;
            }
        }
    }
#endif
    return ret;
}

bool MiscUtils::GetBuildInfo(BuildModule id, const string &build_info, 
                             string &result) {
    string rpm_version;
    string build_num;

    bool ret = GetContrailVersionInfo(id, rpm_version, build_num);
    rapidjson::Document d;
    if (d.Parse<0>(const_cast<char *>(build_info.c_str())).HasParseError()) {
        result = build_info;
        return false;
    }
    rapidjson::Value& fields = d["build-info"];
    if (!fields.IsArray()) {
        result = build_info;
        return false;
    }

    rapidjson::Value str1("build-id"), str2("build-number");
    rapidjson::Value str11(rpm_version.c_str(), d.GetAllocator()), str22(build_num.c_str(), d.GetAllocator());

    fields[0u].AddMember(str1, str11, d.GetAllocator());
    fields[0u].AddMember(str2, str22, d.GetAllocator());

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);
    result = strbuf.GetString();
    return ret;
}

bool MiscUtils::GetPlatformInfo(std::string &distro, std::string &code_name) {
#ifdef _WINDOWS //as per discussion for now. May change to different values in the future.
    distro = "windows";
    code_name = GetWindowsVersionString();
#else
    FILE *fp=NULL;
    char line[512];
    fp = popen("cat /etc/*release", "r");
    if (fp == NULL) {
        return false;
    }
    std::string result = "";
    while (!feof(fp)) {
        if (fgets(line, 512, fp) != NULL) {
             result += line;
        }
    }

    // parse the strings for centos 6.4, 6.5, trusty, precise..
    if (result.find("trusty") != std::string::npos) {
        distro = "Ubuntu";
        code_name = "Trusty";
    } else if (result.find("precise") != std::string::npos) {
        distro = "Ubuntu";
        code_name = "Precise";
    } else if (result.find("rhel") != std::string::npos) {
        distro = "rhel";
        code_name = "7.0";
    } else if (result.find("CentOS distro 6.4") != std::string::npos) {
        distro = "CentOS";
        code_name = "6.4";
    } else if (result.find("CentOS distro 6.5") != std::string::npos) {
        distro = "CentOS";
        code_name = "6.5";
    } else if (result.find("CentOS Linux release 7") != std::string::npos) {
        distro = "CentOS";
        code_name = "7.1.1503";
    } else {
        return false;
    }
#endif
    return true;
}
