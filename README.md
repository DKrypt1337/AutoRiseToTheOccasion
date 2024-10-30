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
* Intelligent token manipulation:
  - Maintains token length
  - Smart character replacement
  - Preserves token format
* Multiple bypass attempt methods
* Visual results showing token location and bypass status
* Comprehensive reporting:
  - Export detailed CSRF test results
  - Categorized findings by token location
  - Successful and failed bypass attempts
  - Clear overview of tested endpoints

### UI Features
* Centralized configuration tab:
  - User role settings
  - Cookie and Authorization configurations
  - CSRF testing options
  - Report generation
* Side-by-side request/response comparison
* Separate tabs for each user role
* Dedicated CSRF testing tab
* Color-coded results for easy interpretation
* Real-time request processing
* Detailed logging of modifications

### Reporting Features
* Export comprehensive CSRF test reports
* Report sections include:
  - URLs with CSRF tokens in cookies
  - URLs with CSRF tokens in headers
  - URLs with tokens in both locations
  - Successfully bypassed endpoints
  - Failed bypass attempts
  - Categorized results by token type
* Easy-to-read text format
* Save reports to custom locations

## Installation

1. Download the latest JAR file from the releases page
2. Open Burp Suite
3. Go to Extender > Extensions
4. Click "Add" and select the downloaded JAR file
5. The extension will appear in a new tab labeled "AutoRiseToTheOccasion"

## Usage

1. **Configure User Roles** (Configuration Tab):
   - Enter cookie values and/or Authorization headers for each user role
   - Enable/disable specific roles as needed
   - Configure CSRF testing options

2. **Enable Testing Types**:
   - Toggle cookie testing per role
   - Toggle Authorization header testing per role
   - Enable/disable CSRF testing

3. **Start Testing**:
   - Browse the target application normally
   - The extension automatically processes requests based on your configuration
   - Review results in the respective tabs

4. **Generate Reports**:
   - Click "Export CSRF Report" in the configuration tab
   - Choose save location
   - Review comprehensive test results

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

### v1.1.0
- Added CSRF testing report generation
- Improved token manipulation logic
- Enhanced configuration UI
- Added centralized user role management
- Fixed case sensitivity issues

### v1.0.0
- Initial release
- BOLA/IDOR testing functionality
- CSRF token validation testing
- Multi-user role support
- Real-time request processing