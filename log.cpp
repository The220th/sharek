#include "./include/log.h"

#include <iostream>
#include <ctime>

void clog(const char *s)
{
    clog(std::string(s));
}

void clog(std::string s)
{
	time_t curr_time = time(NULL);
    std::tm *tml = localtime(&curr_time);
    std::cout << "[" << tml->tm_mday << "." << tml->tm_mon << tml->tm_year+1900 << " ";
    std::cout << tml->tm_hour << ":" << tml->tm_min << ":" << tml->tm_sec << "." << curr_time << "] ";

    std::cout << s << std::endl;
}