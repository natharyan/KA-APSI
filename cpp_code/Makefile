
# TO-DO: Make an equivalent version for Linux
# Compiler and flags
CXX = clang++
CXXFLAGS = -std=c++17 -Wall -I. -I/opt/homebrew/opt/ntl/include
LDFLAGS = -L/opt/homebrew/lib -lntl -lgmp

# Source files
SRCS = apsi.cpp monocypher.c helpers.cpp network.cpp sender.cpp receiver.cpp

# Target executable
TARGET_DIR = bin
TARGET = $(TARGET_DIR)/apsi

# Default target: builds the executable
all: $(TARGET)

# Rule to build the executable
# This rule compiles and links the source files in one step.
# It also ensures the bin directory exists.
$(TARGET): $(SRCS)
	@mkdir -p $(TARGET_DIR)
	$(CXX) $(CXXFLAGS) $^ -o $(TARGET) $(LDFLAGS)
	@echo "Build complete. Executable is at $(TARGET)"

# Clean target: removes the bin directory
clean:
	@echo "Cleaning up..."
	rm -rf $(TARGET_DIR)
	@echo "Cleanup complete."

# Phony targets: these are not files
.PHONY: all clean
