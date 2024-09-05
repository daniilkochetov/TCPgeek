//See http://www.adp-gmbh.ch/cpp/config_file.html for details

#ifndef THIRDPARTYCODE_CONFIGFILE_H_
#define THIRDPARTYCODE_CONFIGFILE_H_

#include <string>
#include <map>
#include <iostream>

class ConfigFile {
  std::map<std::string, std::string> content_;

public:
  ConfigFile(std::string const& configFile);
  std::string value(std::string const& section, std::string const& entry) const;

};

#endif /* THIRDPARTYCODE_CONFIGFILE_H_ */
