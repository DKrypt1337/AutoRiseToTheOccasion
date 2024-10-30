# AutoRiseToTheOccasion
A Burp Suite extension for automated BOLA/IDOR and CSRF token validation testing

## Overview
AutoRiseToTheOccasion is a Burp Suite extension that automates the testing of Role-Based Access Control (BOLA/IDOR) and CSRF token validation vulnerabilities. It provides an intuitive interface for configuring and executing tests across multiple user roles simultaneously.

## Features

### Role-Based Access Control Testing (BOLA/IDOR)
* Test up to 10 different user roles simultaneously
* Selective cookie manipulation:
  - Only modifies existing cookie values
  - Enable/disable per role
  - Custom cookie values per role
  - Visual highlighting of modified values
* Authorization header testing:
  - Only modifies existing Authorization headers
  - Enable/disable per role
  - Custom Authorization values per role
  - Visual highlighting of modified headers

### CSRF Token Testing
* Automatic CSRF token detection in:
  - Headers
  - Cookies
  - Request body
* Multiple bypass attempt methods
* Visual results showing token location and bypass status
* Color-coded success/failure indicators

### UI Features
* Side-by-side request/response comparison
* Separate tabs for each user role
* Dedicated CSRF testing tab
* Configuration tab for global settings
* Color-coded results for easy interpretation
* Real-time request processing
* Detailed logging of modifications

## Installation

1. Download the latest JAR file from the releases page
2. Open Burp Suite
3. Go to Extender > Extensions
4. Click "Add" and select the downloaded JAR file
5. The extension will appear in a new tab labeled "AutoRiseToTheOccasion"

## Usage

1. **Configure User Roles**:
   - Enter cookie values and/or Authorization headers for each user role
   - Enable/disable specific roles as needed

2. **Enable Testing Types**:
   - Toggle cookie testing per role
   - Toggle Authorization header testing per role
   - Enable/disable CSRF testing

3. **Start Testing**:
   - Browse the target application normally
   - The extension automatically processes requests based on your configuration
   - Review results in the respective tabs

## How to Compile

Requirements:
* Java 11 or later
* Maven 3 or later

Steps:
1. Clone the repository:
   ```bash
   git clone https://github.com/DKrypt1337/AutoRiseToTheOccasion.git
   ```
2. Navigate to project directory:
   ```bash
   cd AutoRiseToTheOccasion
   ```
3. Build with Maven:
   ```bash
   mvn clean package
   ```
4. Find the compiled JAR in the `target` directory

## Requirements

* Burp Suite Professional or Community Edition
* Java 11 or later

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

* Created by DKrypt1337
* Contributors:
  - Your name could be here!

## Support

For bugs, feature requests, or questions:
1. Open an issue on GitHub
2. Provide detailed information about your setup and the issue
3. Include steps to reproduce if reporting a bug

## Changelog

### v1.0.0
- Initial release
- BOLA/IDOR testing functionality
- CSRF token validation testing
- Multi-user role support
- Real-time request processing