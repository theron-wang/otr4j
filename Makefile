.PHONY: help fuzz-MessageProcessor fuzz-Fragment

help:
	@echo "Make support is limited to functionality that cannot be provided otherwise."
	@echo
	@echo "Goals:"
	@echo "  fuzz-MessageProcessor: run afl fuzzer for MessageProcessor parser"
	@echo "  fuzz-Fragment: run afl fuzzer for Fragment parser"

SOURCE_FILES := $(shell find src/main/java -type f -name '*.java')
target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar: $(SOURCE_FILES)
	mvn clean install -DskipTests

TEST_FILES = $(shell find src/test/java -type f -name '*.java')
target/test-classes: target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar $(TEST_FILES)
	mvn test-compile
	touch target/test-classes

fuzz-MessageProcessor: target/test-classes
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/seeds/MessageParser net.java.otrfuzz.MessageParserDriver fuzzMessage

fuzz-Fragment: target/test-classes
	@echo "Checking if AFL_DIR is set and jqf-afl-fuzz binary is available."
	@which jqf-afl-fuzz
	jqf-afl-fuzz -v -c target/otr4j-0.60-SNAPSHOT-jar-with-dependencies.jar:target/test-classes -i src/test/seeds/Fragment net.java.otrfuzz.FragmentParserDriver fuzzFragment
