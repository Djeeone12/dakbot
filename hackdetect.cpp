
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <boost/asio.hpp>

// Convenience namespace declarations to streamline the code below
using namespace boost::asio;
using namespace boost::asio::ip;
// using namespace std;

/** Synonym for an unordered map that is used to track banned IPs and 
 * authorized users. For example, the key in this map would be IP addresses
 * and the value is just a place holder (is always set to true).
 */
using LookupMap = std::unordered_map<std::string, bool>;

/**
 * An unordered map to track the seconds for each log entry associated
 * with each user. The user ID is the key into this unordered map.
 * The values is a list of timestamps of log entries associated with
 * an user. For example, if a user "bob" has 3 login at "Aug 29 11:01:01",
 * "Aug 29 11:01:02", and "Aug 29 11:01:03" (one second apart each), then
 * logins["bill"] will be a vector with values {1630249261, 1630249262, 
 * 1630249263}. 
 */
using LoginTimes = std::unordered_map<std::string, std::vector<long>>;

/**
 * Helper method to load data from a given file into an unordered map.
 * 
 * @param fileName The file name from words are are to be read by this 
 * method. The parameter value is typically "authorized_users.txt" or
 * "banned_ips.txt".
 * 
 * @return Return an unordered map with the 
 */
LookupMap loadLookup(const std::string& fileName) {
    // Open the file and check to ensure that the stream is valid
    std::ifstream is(fileName);
    if (!is.good()) {
        throw std::runtime_error("Error opening file " + fileName);
    }
    // The look up map to be populated by this method.
    LookupMap lookup;
    // Load the entries into the unordered map
    for (std::string entry; is >> entry;) {
        lookup[entry] = true;
    }
    // Return the loaded unordered map back to the caller.
    return lookup;
}

/**
 * This method is used to convert a timestamp of the form "Jun 10
 * 03:32:36" to seconds since Epoch (i.e., 1900-01-01 00:00:00). This
 * method assumes by default, the year is 2021.
 *
 * \param[in] timestamp The timestamp to be converted to seconds.  The
 * timestamp must be in the format "Month day Hour:Minutes:Seconds",
 * e.g. "Jun 10 03:32:36".
 *
 * \param[in] year An optional year associated with the date. By
 * default this value is assumed to be 2021.
 *
 * \return This method returns the seconds elapsed since Epoch.
 */
long toSeconds(const std::string& timestamp, const int year = 2021) {
    // Initialize the time structure with specified year.
    struct tm tstamp = { .tm_year = year - 1900 };
    // Now parse out the values from the supplied timestamp
    strptime(timestamp.c_str(), "%B %d %H:%M:%S", &tstamp);
    // Use helper method to return seconds since Epoch
    return mktime(&tstamp);
}

/**
 * @param url A string containing a valid URL. The port number in URL
 * is always optional.  The default port number is assumed to be 80.
 *
 * @return This method returns a std::tuple with 3 strings. The 3
 * strings are in the order: hostname, port, and path.  Here we use
 * std::tuple because a method can return only 1 value.  The
 * std::tuple is a convenient class to encapsulate multiple return
 * values into a single return value.
 */
std::tuple<std::string, std::string, std::string>
breakDownURL(const std::string& url) {
    // The values to be returned.
    std::string hostName, port = "80", path = "/";
    size_t n, m;
    n = url.find("/") + 2;
    if (url.find(":", n) != std::string::npos) {
        m = url.find(":", n);
        port = url.substr(m + 1, url.find("/", m) - (m+1));
        path = url.substr(url.find("/", m));
    } else {
        m = url.find("/", n);
        path = url.substr(m);
    }
    hostName = url.substr(n, m - n);
    // Return 3-values encapsulated into 1-tuple.
    return {hostName, port, path};
}
/**
 * This method checks is users have been flagged. 
 * @param user A string object of 5 numbers that identify individuals connected
 * to login attempts 
 * @param flagged A LookupMap object that contains a string key and bool content
 * that registers certain users as flagged for potential hackers.
 * @return Returns a bool, false is the user object passed in has not been 
 * flagged or true is they have been flagged. 
 */
bool isFlag(const std::string& user, LookupMap& flagged) {
    if (flagged.find(user) == flagged.end()) {
            flagged[user] = false;
            return false;
            
    } else if (flagged.find(user) != flagged.end() 
            && flagged[user] == true) {
            return true;        
    }
    return false;
}
/**
 * Checks every line read in for being an authorized user according to the 
 * authUser LookupMap
 * @param line A string of the current login attempt report being assessed. 
 * @param authUser A LookupMap containing a string key and bool contents of 
 * authorized users.
 * @return Returns a bool, true if the login attempt was from an authorized 
 * origin or false if it had not. 
 */
bool isAuth(const std::string& line, const LookupMap& authUser) {
    for (auto e : authUser) {
        if (line.find(e.first) != std::string::npos) {
            return true;
        }
    }
    return false;
}
/**
 * This method checks every IP associated with a log in attempt to see if it has
 * been banned. 
 * @param line A string of the current login attempt report being assessed.
 * @param banIP A LookupMap containing a string key and bool contents of 
 * IPs that have been banned.
 * @return Returns a bool, true if the IP has been banned and false if it has 
 * not been banned.
 */
bool isBand(const std::string& line, const LookupMap& banIP) {
    for (auto e : banIP) {
        if (line.find(e.first) != std::string::npos) {
            return true;
        }
    }
    return false;
}
/**
 * This method assist the main checkLog method by using a for loop to go through
 * the relevant past login attempts of a user and checks for login frequency 
 * patterns that may signal hacking. 
 * @param temp A vector of longs showing the time in which each login attempt 
 * occurred 
 * @param line A string of the current login attempt report being assessed.
 * @param log A LoginTimes object made up of a string key and vector of longs
 * contents, holds all Users data of relevant previous log in attempts.
 * @param user A string object of 5 numbers that identify individuals connected
 * to login attempts 
 * @return Returns a bool, false if not a frequency problem, true if there is
 * a frequency issue. 
 */
bool checkLogHelper(std::vector<long> temp, const std::string line, 
        LoginTimes& log, const std::string user) {
    int check = 0;
    for (unsigned int i = 0; i < temp.size(); i++) {
        unsigned int j = i;
        if (j + 1 < temp.size()) {
            j++;
            if (std::abs (temp[j] - temp[i]) < 20 
                    && line.find("Failed") != std::string::npos) {
                check++;
            } else {
                // Means a successful attempt to log in has occurred, resets
                check = 0; 
                long tempLong = temp.back();
                temp.clear();
                // Still need to record this attempt but not previous
                temp.push_back(tempLong);
                log[user] = temp;
            }
        } 
        if (check > 2) {
            // Means an alarming case has occurred, removes first time in vector
            // so next attempt does not automatically fail. 
            temp.erase(temp.begin());
            log[user] = temp;
            return true;
        }
    }
    return false;
}
/**
 * This method checks a login attempt occurrence for patterns regarding the 
 * time of attempt that may signal potential hacking. 
 * @param line A string of the current login attempt report being assessed.
 * @param log A LoginTimes object made up of a string key and vector of longs
 * contents, holds all Users data of relevant previous log in attempts.
 * @param user A string object of 5 numbers that identify individuals connected
 * to login attempts 
 * @return Returns a bool, false if not a frequency problem, true if there is
 * a frequency issue.  
 */
bool checkLog(const std::string& line, LoginTimes& log, 
        const std::string user) {
    long time = toSeconds(line.substr(0, 14));
    std::vector<long> temp; 
    // Checks if user has been previously added, then adds if not
    if (log.find(user) == log.end()) {
        temp.push_back(time);
        log[user] = temp;
        return false;
            
    } else if (log.find(user) != log.end()) {  // adds new time to log
        temp = log[user];
        temp.push_back(time);
        log[user] = temp;
        if (temp.size() < 3) {
            return false;
        } else {
            // calls helper method to assess new and previous log information 
            return checkLogHelper(temp, line, log, user); 
        }
    }
    return false;
}
/**
 * This method assists the process method by printing out the results of the 
 * process method. 
 * @param os A ostream object that prints results to the consol 
 * @param reason An integer object that signals to the processHelper method what 
 * message the processMethod needs printed
 * @param line A string of the current login attempt report being assessed.
 * @param hackAtt An integer that counts the number of login attempts that have
 * been considered hacking that have been processed. 
 * @param lineCount An integer that counts the number of lines that have been 
 * processed 
 * @return returns a 1 to increase the hackAtttemp integer by one 
 */
int processHelper(std::ostream& os, int reason, std::string line, int hackAtt,
        int lineCount) {
    if (reason == 1) {
        os << "Hacking due to banned IP. Line: " << line << "\n";
    } else if (reason == 2) {
        os << "Hacking due to frequency. Line: " << line << "\n";
    } else if (reason == 3) {
        os << "Processed " << lineCount << " lines. Found " << hackAtt 
            << " possible hacking attempts.\n";
    }
    return 1;
}
/**
 * This method analyzes each login attempt for patterns or data that signal 
 * potential hacking. It also reads in the lines in question from a webpage.
 * @param is An in stream of data that has been read from a webpage. 
 * @param os An ostream object that prints results to the consol 
 */
void process(std::istream& is, std::ostream& os) {
    const LookupMap authUser = loadLookup("authorized_users.txt");
    const LookupMap banIP = loadLookup("banned_ips.txt");
    LookupMap flagged;
    LoginTimes log;
    int lineCount = 0, hackAtt = 0; 
    std::string user;
    // Loops removes all header lines
    for (std::string hdr; std::getline(is, hdr) &&
             !hdr.empty() && hdr != "\r";) {} 
    // Loops through each line of input and calls proper assessing methods
    for (std::string line; std::getline(is, line) && !line.empty();) {
        lineCount++;
        int temp = line.find("sshd");
        user = line.substr(temp + 5, 5);
        // os << user << "\n";
        if (isAuth(line, authUser)) {
            // all done
        } else if (isBand(line, banIP)) {
            hackAtt += processHelper(os, 1, line, 0, 0);
            // end and print fail and add to bad test
        } else if (isFlag(user, flagged)) {
            hackAtt += processHelper(os, 1, line, 0, 0);            
            // end and print fail and add to bad test
        } else if (checkLog(line, log, user)) {
            hackAtt += processHelper(os, 2, line, 0, 0);
            // flagged[user] = true;
            // end and print fail and add to bad test and add to flagged
        }
    }
    processHelper(os, 3, user, hackAtt, lineCount); 
    // user is simply being used as a place holder here
}

/**
 * The main function that uses different helper methods to download and process
 * log entries from the given URL and detect potential hacking attempts.
 *
 * \param[in] argc The number of command-line arguments.  This program
 * requires exactly one command-line argument.
 *
 * \param[in] argv The actual command-line argument. This should be an URL.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cout << "URL not specified. See video on setting command-line "
                  << "arguments in NetBeans on Canvas.\n";
        return 1;
    }
    const std::string url = argv[1];
    // http://ceclnx01.cec.miamioh.edu/~raodm/ssh_logs/full_logs.txt
    // Need a tcp stream to create a network connection to the remote 
    // server and request the data from the remote server
    std::string hostname, port, path;
    std::tie(hostname, port, path) = breakDownURL(url);
    
    tcp::iostream data(hostname, port);
    data << "GET "   << path     << " HTTP/1.1\r\n"
         << "Host: " << hostname << "\r\n"
         << "Connection: Close\r\n\r\n";
    std::ostream& os = std::cout;
    process(data, os);
    // Using helper methods, implement the necessary features for
    // this project.
}