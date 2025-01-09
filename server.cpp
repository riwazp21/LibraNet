#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <vector>
#include <map>
#include <random>
#include "p1_helper.cpp"
#include <cstdlib>
#include <openssl/sha.h>
#define BACKLOG 10
using namespace std;
string globalClientIP;

constexpr size_t MAXDATASIZE = 1024; 
string PRE_SHARED_KEY = "F24447TG";

struct User 
{
	string username;
	string salt;
	string hashedPassword; 
};

map<string,User> userDatabase; 

std::vector<std::string> splitString(const std::string& str, char delimiter) {
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(str);
	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}
	return tokens;
}

void loadUserDatabase()
{
	ifstream file(".book_shadow");
	if(!file.is_open()) return;

	string line;
	while(getline(file,line))
	{
		istringstream stream(line);
		string username, salt, hash;
		getline(stream,username,':');
		getline(stream, salt, ':');
		userDatabase[username] = {username,salt,hash};

	}
	file.close();
}

void saveUserToDatabase()
{
	ofstream file(".book_shadow");
	for(const auto&[username, user]:userDatabase)
	{
		file<<user.username<<":"<<user.salt<<":"<<user.hashedPassword<<"\n";

	}
	file.close();
}

void appendUserToDatabase(const string& username, const string& salt, const string& hashedPassword) {
    // Open the file in append mode
    ofstream file(".book_shadow", ios::app);
    
    // Check if the file opened successfully
    if (file.is_open()) {
        // Append the username, salt, and hashed password in the specified format
        file << username << ":" << salt << ":" << hashedPassword << "\n";
        
        // Close the file after writing
        file.close();
    } else {
        // Handle the error if the file couldn't be opened
        cerr << "Error: Unable to open file for appending." << endl;
    }
}

string generateRandomString()
{
	string lowerCase = "abcdefghijklmnopqrstuvwxyz";
	string upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	string numbers = "0123456789";
	string alphaNumeric = lowerCase + upperCase + numbers; 
	string specialChar = "!@#$%&*";
	string everyThing = lowerCase + upperCase + numbers + specialChar;
	srand(time(nullptr));

	string password;
	random_device rd;
	mt19937 gen(rd());

	password = password + upperCase[(rand()%upperCase.length())];
	password = password + numbers[(rand()%numbers.length())];
	password = password + specialChar[rand()%specialChar.length()];

	while(password.length()<5)
	{
		password += everyThing[rand()%everyThing.length()];

	}
	shuffle(password.begin(),password.end(),gen);

	if(specialChar.find(password[0]) != string::npos)
	{
		for (size_t i = 1; i<password.length(); i++)
		{
			if(alphaNumeric.find(password[i]) != string::npos)
			{
				swap(password[0],password[i]);
				break;
			}
		}
	}
	return password; 



}

string generateSalt()
{
	string printableChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*()_+-=[]{}|;:',.<>?";
	random_device rd;
	mt19937 gen(rd());
	uniform_int_distribution<> dist(0, printableChars.size() - 1);

	string salt; 

	for(int i = 0; i<6; i++)
	{
		salt += printableChars[dist(gen)];
	}
	return salt; 

}

string interLeavedPassword(string password, string salt)
{
	int totalLength = password.length() + salt.length();
	string interleave;
	int k = 0;
	int j = 0;
	for(int i=0 ; i<totalLength; i++ )
	{
		if(i%2 == 0)
		{
			interleave = interleave + salt[k];
			k = k + 1;
		}

		else
		{
			interleave = interleave + password[j];
			j = j + 1;
		}
	}
	return interleave; 
}


void writeBooksToFile(const std::vector<Book>& books)
{
    ofstream file("books.db");
    file<<"ftitle;author;genre;available;rating\n";
    for(const auto& book:books) 
   {
	file<<book.title<<";"<<book.author<<";"<<book.genre<<";"<<(book.available ? "true" : "false")<<";"<<book.rating<<"\n";
   }
}


void sigchld_handler(int s)
{
	(void)s;

	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
}

void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

std::string toCamelCase(const std::string& input)
{
	std::string output;
	bool capitalize = true;

	for (char c : input) {
		if (std::isalpha(c)) {
			if (capitalize) {
				output += std::toupper(c);
			} else {
				output += std::tolower(c);
			}
			capitalize = !capitalize;
		} else {
			output += c;
		}
	}
	return output;
}

void logConnection(const std::string& clientIP)
{
	std::time_t now = std::time(nullptr);
	std::tm* localTime = std::localtime(&now);
	char timestamp[20];
	std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
	std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
	globalClientIP = clientIP;
}

void logDisconnection(const std::string& clientIP)
{
	std::time_t now = std::time(nullptr);
	std::tm* localTime = std::localtime(&now);
	char timestamp[20];
	std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
	std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}

std::string hashStringSHA512(const std::string& input) {
    // Create a buffer to store the hash result
    unsigned char hash[SHA512_DIGEST_LENGTH];
    
    // Perform the SHA-512 hash
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    
    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

int main(int argc, char* argv[])
{
	int sockfd, new_fd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;
	socklen_t sin_size;
	struct sigaction sa;
	int yes = 1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	std::vector<Book> books = loadBooksFromFile("books.db");

	std::memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (argc != 2) {
		std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
		return 1;
	}

	std::string configFileName = argv[1];

	std::string port;
	std::ifstream configFile(configFileName);
	if (!configFile.is_open()) {
		std::cerr << "Error opening configuration file: " << configFileName << std::endl;
		return 1;
	}

	std::string line;
	while (std::getline(configFile, line)) {
		if (line.substr(0, 5) == "PORT=") {
			port = line.substr(5);
			break;
		}
	}
	configFile.close();

	if (port.empty()) {
		std::cerr << "Port number not found in configuration file!" << std::endl;
		return 1;
	}

	if ((rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo)) != 0) {
		std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
		return 1;
	}

	for (p = servinfo; p != nullptr; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			std::perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			throw std::system_error(errno, std::generic_category(), "setsockopt");
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			std::perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (p == nullptr) {
		std::cerr << "server: failed to bind" << std::endl;
		return 1;
	}

	if (listen(sockfd, BACKLOG) == -1) {
		throw std::system_error(errno, std::generic_category(), "listen");
	}

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
		throw std::system_error(errno, std::generic_category(), "sigaction");
	}

	std::cout << "server: waiting for connections..." << std::endl;

	while (true) {
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
		if (new_fd == -1) {
			std::perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
		// Log the connection
		logConnection(s);
		if (!fork()) 
		{
			close(sockfd);

			char buf[MAXDATASIZE];
			int numbytes;
			bool heloSetup = false;
			bool searchMode = false;
			bool manageMode = false;
			bool recommendMode = false;
			bool userRegistered = false; 
			while(true)
			{
				if ((numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0)) == -1) {
					perror("recv");
					exit(1);
				} else if (numbytes == 0) { // Client disconnected
					logDisconnection(s);
					break;
				}

				buf[numbytes] = '\0';

				std::string receivedMsg(buf);
				std::string camelCaseMsg = toCamelCase(receivedMsg);


				//USER

				
				//HELO
				if (receivedMsg.substr(0,5) == "USER ") {
					char hostname[1024];
					gethostname(hostname, sizeof(hostname));
					std::string combinedMessage = "";
					string username = receivedMsg.substr(5);
				
					string password = generateRandomString();
					string salt = generateSalt();
					string combinedPassword = interLeavedPassword(password, salt);
					string hashedPassword = hashStringSHA512(combinedPassword);
					appendUserToDatabase(username,salt,hashedPassword);




					if (send(new_fd, hashedPassword.c_str(), combinedMessage.length(), 0) == -1) {
						perror("send");
					}
					heloSetup = true;
					continue;
				}

				//HELP
				if (receivedMsg == "HELP" && heloSetup) {
					string Message = "200 Available commands: HELO, SEARCH, MANAGE, RECOMMEND, BYE";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}
					continue;
				}
				//SEARCH
				if (receivedMsg == "SEARCH" && heloSetup) {
					string Message = "210 Ready for Search";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}
					searchMode = true;
					manageMode = false;
					recommendMode = false;
					continue;
				}

				//MANAGE

				if (receivedMsg == "MANAGE" && heloSetup) {
					string Message = "220 Ready to Manage";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}
					searchMode = false;
					manageMode = true;
					recommendMode = false;
					continue;
				}
				//RECOMMEND
				if (receivedMsg == "RECOMMEND" && heloSetup) {
					string Message = "230 Ready to Recommend";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}
					searchMode = false;
					manageMode = false;
					recommendMode = true;
					continue;
				}

				//FIND
				if (receivedMsg.substr(0,5) == "FIND " && searchMode) {
					string searchTitle = receivedMsg.substr(5);
					bool found = false;

					for (const Book& book : books) {

						if (book.title == searchTitle) {
							std::string message = "250 Book Found: " + book.title;
							if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
								perror("send");
							}
							found = true;
							break;
						}

					}

					if (!found) {
						std::string message = "304 No matching books found";
						if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
							perror("send");
						}
						continue;
					}
					else
					{
						continue;
					}
				}


				//DETAILS
				if (receivedMsg.substr(0,8) == "DETAILS " && searchMode)
				{
					std::vector<Book> books_new = loadBooksFromFile("books.db");
					string searchTitle = receivedMsg.substr(8);
					bool found = false;

					for (const Book& book : books_new) {

						if (book.title == searchTitle) {
							string availability=" ";
							if(book.available) {
								availability = "Available";
							}
							else {
								availability = "Not Available";
							}
							std::string message = "250 Book Found: " + book.title +"\nAuthor: "+ book.author + "\nGenre: "+book.genre+"\nAvailable: " + availability+"\nRating: "+ to_string(book.rating);
							if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
								perror("send");
							}
							found = true;
							break;
						}

					}

					if (!found) {
						std::string message = "404 No matching books found";
						if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
							perror("send");
						}
						continue;
					}
					else {
						continue;
					}


				}

				//CHECKOUT
				if (receivedMsg.substr(0,9) == "CHECKOUT " && manageMode)
				{
					std::vector<Book> books_new = loadBooksFromFile("books.db");
					bool Available = false;
					bool found = false;
					string message = " ";
					string searchTitle = receivedMsg.substr(9);
					for(Book&book:books_new)
					{
						if(book.title == searchTitle)
						{
							found = true;
							if(book.available)
							{
								book.available = false;
								message = "250. Succesfully checked out book";
								Available = true;
								writeBooksToFile(books_new);
								break;
							}
						}
					}
					if(found & !Available)
					{
						message = "403. The book is unavailable";
					}

					if(!found)
					{
						message = "404. Book not Found";
					}

					if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
						perror("send");
					}
					continue;
				}

				//RETURN
				if (receivedMsg.substr(0,7) == "RETURN " && manageMode)
				{
					std::vector<Book> books_new = loadBooksFromFile("books.db");
					bool Available = true;
					bool found = false;
					string message = " ";
					string searchTitle = receivedMsg.substr(7);
					for(Book&book:books_new)
					{
						if(book.title == searchTitle)
						{
							found = true;
							if(!book.available)
							{
								book.available = true;
								message = "250. Succesfully returned the book";
								Available = false;
								writeBooksToFile(books_new);
								break;
							}
						}
					}

					if(found & Available)
					{
						message = "404. Book has never been checked out by anyone.";
					}


					if(!found)
					{
						message = "404. Book not Found";
					}

					if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
						perror("send");
					}
					continue;
				}

				//LIST
				if (receivedMsg == "LIST" && manageMode)
				{
					std::vector<Book> books_new = loadBooksFromFile("books.db");
					string Mainmessage = "";
					int availCount = 0;
					string message = "";
					for(const Book&book:books_new)
					{
						if(book.available)
						{
							availCount++;
							Mainmessage = Mainmessage + "\n" + book.title;
						}
					}

					if(availCount == 0)
					{
						message = "304. No books are available";
					}
					else
					{
						message = "250. The list of available books are: " + Mainmessage;
					}
					if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
						perror("send");
					}
					continue;



				}



				//GET
				if (receivedMsg.substr(0,4) == "GET " && recommendMode)

				{
					string genre = receivedMsg.substr(4);
					string Mainmessage = "";
					int availCount = 0;
					string message = "";
					for(const Book&book:books)
					{
						if(book.genre == genre)
						{
							availCount++;
							Mainmessage = Mainmessage + "\n" + book.title;
						}
					}

					if(availCount == 0)
					{
						message = "304. No books are available";
					}
					else
				 	{
						message = "250. The list of available books are: " + Mainmessage;
					}
					if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
						perror("send");
					}
					continue;
				}

				//RATE
				if (receivedMsg.substr(0,5) == "RATE " && recommendMode)
				{
					std::vector<Book> books_new = loadBooksFromFile("books.db");
					//250 if correct and show all books
					bool valid = true;
					string message = "404. Book Not Found";
					size_t lastSpacePos = receivedMsg.find_last_of(' ');


					string lastPart = receivedMsg.substr(lastSpacePos + 1);
					for (char c : lastPart) {
						if (!std::isdigit(c)) {
							valid = false;
							break;
						}
					}
					int rating = 0;

					if(valid)
					{
						rating = stoi(lastPart);
						if(rating <0 || rating >5)
						{
							valid = false;
						}
					}

					if(valid)
					{
						//Add the rating stuff to the daabase
						string bookName = receivedMsg.substr(5,receivedMsg.length()-7);
						for(Book&book:books_new)
						{
							if(book.title == bookName)
							{
							    book.rating = rating;
							    message = "250. Succesfully rated the book";
								writeBooksToFile(books_new);
								break;
							}
						}
					}

					else
					{
						message = "400. Rating is invalid";
					}
					
					if (send(new_fd, message.c_str(), message.length(), 0) == -1) {
						perror("send");
					}

					continue;
				}

				//BYE
				if(receivedMsg == "BYE")

				{
					
					exit(0);
					string Message = "200. Bye";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}
					close(new_fd);

				}

				else
				{
					string Message = "400 BAD REQUEST";
					if (send(new_fd, Message.c_str(), Message.length(), 0) == -1) {
						perror("send");
					}

					continue;
				}



			}


		
		close(new_fd);
		exit(0);
}
close(new_fd);

	}
	return 0;
}
