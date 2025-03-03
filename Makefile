# Directories and files
GEN_DIR        := gen
AIDL_DIR       := aidl
PACKAGE_NAME   := com/yuandaima
AIDL_FILE      := $(AIDL_DIR)/$(PACKAGE_NAME)/IHello.aidl
BUILD_TARGET   := aosp_cf_arm64_phone-trunk_staging-eng

.PHONY: all generate aosp-setup clean

# Default target: generate code then run AOSP setup (if applicable)
all: generate build

# Generate AIDL C++ code with headers output to $(GEN_DIR) and using it as include dir.
generate:
	@echo "Creating directory '$(GEN_DIR)' if it doesn't exist..."
	@mkdir -p $(GEN_DIR)
	@echo "Generating AIDL C++ code..."
	@aidl-cpp $(AIDL_FILE) $(GEN_DIR)/include/ $(GEN_DIR)/IHello.cpp -I $(AIDL_DIR)
	@echo "Generation complete."

build: generate
	@if [ -f ../build/envsetup.sh ]; then \
		echo "AOSP environment detected. Running envsetup.sh and lunch in an interactive shell..."; \
		bash -i -c "source ../build/envsetup.sh && lunch $(BUILD_TARGET) && mm"; \
	else \
		echo "Not in an AOSP environment. Skipping AOSP setup."; \
	fi

# Clean up generated files.
clean:
	@echo "Cleaning generated files..."
	@rm -rf $(GEN_DIR)
	@rm -rf $(BUILD_SRC_DIR)
	@echo "Clean complete."
