#include <fstream>
#include <sstream>

// Function to read the entire book of Mark from a file
std::string readBookOfMark(const std::string &filePath) {
    std::ifstream file(filePath);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    std::string bookOfMark = readBookOfMark("Gospel-of-Mark-Christian-Standard-Bible-CSB-Sampler.pdf");
    std::cout << "SHA-256 hash: " << sha256(bookOfMark) << std::endl;
    return 0;
}
