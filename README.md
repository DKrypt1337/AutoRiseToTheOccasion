#                                     AutoRiseToTheOccasion
========================================================================================================

A Burp Suite extension for automating HTTP requests to help test for BOLA/IDOR issues

## Overview
------------

AutoRiseToTheOccasion is a Burp Suite extension that allows you to automate HTTP requests and modify responses. It provides a simple and intuitive interface for sending requests and modifying responses.

## Features
------------

* Automate HTTP requests with custom cookie and authorization headers for each user independently
* Test up to ten different users/roles at the same time
* Easy-to-use interface for configuring requests for each user
* Can enable monitoring, replace certain cookie values, authorization header, and more for each user
* Send request once, and the other up to ten users will send the same request with their cookies/authorization header to check for BOLA/IDOR vulnerabilities

## How to Use
--------------

1. Install the extension by downloading the JAR file and loading it into Burp Suite.
2. Configure the extension by setting the request and response formats, headers, and parameters.
3. Send requests and modify responses using the extension's interface.

## How to Compile
-----------------

To compile the extension, you will need:

* Java 8 or later
* Maven 3 or later

1. Clone the repository using Git: `git clone https://github.com/your-username/AutoRiseToTheOccasion.git`
2. Navigate to the project directory: `cd AutoRiseToTheOccasion`
3. Build the project using Maven: `mvn clean package`
4. The compiled JAR file will be located in the `target` directory.

## Requirements
------------

* Burp Suite 1.7 or later
* Java 8 or later

## License
-------

AutoRiseToTheOccasion is released under the MIT License.

## Contributing
------------

Contributions are welcome! Please submit pull requests or issues on the GitHub repository.

## Credits
--------

* DKrypt for creating the extension
* Your name could be here, for future contributions!